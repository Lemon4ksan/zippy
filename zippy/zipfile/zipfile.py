from datetime import datetime, UTC
from multiprocessing import Pool, cpu_count
from os import PathLike, path, stat
from pathlib import Path
from platform import system
from typing import BinaryIO, TextIO, Optional
from zlib import crc32

from .._base_classes import Archive, File, NewArchive
from ..encryptions import *
from ..compressions import *
from ..exceptions import *
from ._zipfile import FileRaw, CDHeader, CDEnd
from ._zip_algorythms import compress, encrypt

INT32_MAX: int = 4_294_967_295
ILLEGAL_CHARS: list[str] = [
    '#', '%', '&', '{', '}', 
    '<', '>', '*', '?','$',
    '!', "'", '"', ':', '@',
    '+', '`', '|', '='
]

# TODO: Multiprocessing doesn't work for more than 6k files even when sizes and offsets fit under 32 bits (maybe).
#       Also when there're many files, attributes are wrong.

# TODO: Rework user interaction with lib like it's done in zipfile lib.

# TODO: Implement most of the compression algorythms.

# TODO: Add debug feature.

# TODO: Add support for macOS file system.

# TODO: Add way to get info about certain file in a more clean way than "peek_all" and all that.

# TODO: Using dots to start a zip file was a BAD idea. Need to remove them.

class NewZipFile(NewArchive):
    """Class used to create new zip file."""

    def __init__(
            self,
            pwd: Optional[str],
            encoding: str,
            encryption: str
    ):
        # Dictionaries are used to easily replace file's content with new one. All files should "grow" from '.'
        # They are being sorted each time to keep consistent representation.
        super().__init__(pwd, encoding, encryption)
        self._files: dict[str, FileRaw] = {}
        self._cd_headers: dict[str, CDHeader] = {}
        self._sizeof_CD: int = 0
        self._offset: int = 0
        self._current_root: Optional[str] = None

    # see _base_classes.py for documentation.
    def create_file(
            self,
            fn: str,
            fd: str | bytes | TextIO | BinaryIO,
            fp: str = '.',
            /,
            compression: str = STORED,
            level: str = NORMAL,
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:

        for l in fn:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")
        if fp[0] != '.':
            raise ValueError(f"Invalid path for argument fp: '{fp}'. All paths should start from '.' (root).")
        for l in fp:
            if l == '/':
                raise ValueError(f"Invalid path for argument fp: '{fp}'. Use \\ instead of / for paths inside archive.")
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fp contains illegal character '{l}'.")
        
        data: bytes
        last_mod_time: datetime = datetime.now()

        if isinstance(fd, TextIO):
            data = fd.read().encode(encoding)
        elif isinstance(fd, BinaryIO):
            data = fd.read()
        elif isinstance(fd, str):
            data = fd.encode(encoding)
        elif isinstance(fd, bytes):
            data = fd
        else:
            raise TypeError(f"Expected argument fd to be str, bytes, io.TextIO or io.BinaryIO, got {type(fd).__name__} instead.")

        if fp != '.':
            fn = self.create_folder(fp, encoding=encoding).replace('\\', '/') + fn

        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)
        
        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        f_extra_field: bytes = b''
        h_extra_field: bytes = b''

        v: int = 10

        if compression == DEFLATE or fp != '.' or self._encryption == ZIP_CRYPTO:
            v = 20
        if compression == DEFLATE64:
            v = 21
        if compression == PKWARE_IMPLODING:
            v = 25
        if uncompressed_size >= INT32_MAX:
            v = 45
        if compression == BZIP:
            v = 46
        
        bit_flag: list[str] = list('0000000000000000')
        
        if encoding == 'utf-8' and fn[-1] != '/':
            try:
                data.decode('utf-8')
                bit_flag[11] = '1'  # Language encoding flag (EFS)
            except UnicodeDecodeError:
                pass

        compression_method: int = ZIP_COMPRESSION_FROM_STR[compression]
        data = compress(compression_method, level, data)

        if self._encryption != UNENCRYPTED:
            bit_flag[0] = '1'
            data = encrypt(data, self._pwd, crc)
        if compression in (DEFLATE, DEFLATE64):
            if level == FAST:
                bit_flag[2] = '1'
            elif level == MAXIMUM:
                bit_flag[1] = '1'
        
        compressed_size: int = len(data)
        
        if compressed_size >= INT32_MAX:
            f_extra_field += b'\x01\x00\x1C\x00'
            f_extra_field += uncompressed_size.to_bytes(8, 'little')
            f_extra_field += compressed_size.to_bytes(8, 'little')
            f_extra_field += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            f_extra_field += b'\x00\x00\x00\x00'

            uncompressed_size = INT32_MAX
            compressed_size = INT32_MAX
        
        pl = system()
        if pl == 'Windows':
            platform = 0
        elif pl == 'Linux':
            platform = 3
        elif pl == 'Darwin':
            platform = 19
        else:
            raise NotImplementedError(f"Unsupported platform: {pl}")

        if fn[-1] == '/':
            external_attrs = 0x10  # Directory
        else:
            external_attrs = 0x20  # Archive

        file = FileRaw(
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(f_extra_field),
            filename=fn,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start, internal_file_attrs, external_file_attrs
        # and local_header_relative_offset remain placeholders

        cd_header = CDHeader(
            version_made_by=63,
            platform=platform,
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(h_extra_field),
            comment_length=len(comment.encode(self._encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,
            filename=fn,
            extra_field=h_extra_field,
            comment=comment
        )

        if file.filename in self._files:
            # Substract previous length
            self._sizeof_CD -= len(self._cd_headers[file.filename].encode(self._encoding))

        self._sizeof_CD += len(cd_header.encode(self._encoding))

        self._files[file.filename] = file
        self._cd_headers[file.filename] = cd_header

        self._files = {k: v for k, v in sorted(self._files.items(), key=lambda item: item[0])}
        self._cd_headers = {k: v for k, v in sorted(self._cd_headers.items(), key=lambda item: item[0])}

    def add_file(
            self,
            fn: str,
            fd: int | str | bytes | PathLike[str] | PathLike[bytes],
            fp: str = '.',
            /,
            compression: str = STORED,
            level: str = NORMAL,
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:

        for l in fn:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")
        if fp[0] != '.':
            raise ValueError(f"Invalid path for argument fp: '{fp}'. All paths should start from '.' (root).")
        for l in fp:
            if l == '/':
                raise ValueError(f"Invalid path for argument fp: '{fp}'. Use \\ instead of / for paths inside archive.")
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fp contains illegal character '{l}'.")

        if isinstance(fd, (str, bytes, PathLike)):
            if not path.exists(fd):
                raise FileNotFound(f"File {fd!r} doesn't exist.")
            if path.isdir(fd):
                data: bytes = b''
            else:
                with open(fd, 'rb') as f:
                    data = f.read()
        else:
            raise TypeError(
                f"Expected argument fd to be str, bytes or os.PathLike, not {type(fd).__name__}"
            )

        if fp != '.':
            fn = self.create_folder(fp, encoding=encoding).replace('\\', '/') + fn

        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        f_extra_field: bytes = b''
        h_extra_field: bytes = b''

        last_mod_time: datetime = datetime.fromtimestamp(path.getmtime(fd), UTC)

        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        # This is not full:
        # 1.1 - File is a volume label                              | Figure Out
        # 2.7 - File is a patch data set                            | Figure Out
        # 4.5 - File uses ZIP64 format extensions                   | TODO
        # 5.0 - File is encrypted using DES                         | Unsupported
        # 5.0 - File is encrypted using 3DES                        | Unsupported
        # 5.0 - File is encrypted using original RC2 encryption     | TODO
        # 5.0 - File is encrypted using RC4 encryption              | TODO
        # 5.1 - File is encrypted using AES encryption              | TODO
        # 5.1 - File is encrypted using corrected RC2 encryption    | TODO
        # 5.2 - File is encrypted using corrected RC2-64 encryption | TODO
        # 6.1 - File is encrypted using non-OAEP key wrapping       | TODO
        # 6.2 - Central directory encryption                        | Figure Out
        # 6.3 - File is compressed using LZMA                       | TODO
        # 6.3 - File is compressed using PPMd+                      | TODO
        # 6.3 - File is encrypted using Blowfish                    | TODO
        # 6.3 - File is encrypted using Twofish                     | TODO

        v: int = 10

        if compression == DEFLATE or fp != '.' or self._encryption == ZIP_CRYPTO:
            v = 20
        if compression == DEFLATE64:
            v = 21
        if compression == PKWARE_IMPLODING:
            v = 25
        if uncompressed_size >= INT32_MAX:
            v = 45
        if compression == BZIP:
            v = 46

        bit_flag: list[str] = list('0000000000000000')

        if all([encoding == 'utf-8', data != b'', not data.isascii()]):
            try:
                data.decode('utf-8')
                bit_flag[11] = '1'  # Language encoding flag (EFS)
            except UnicodeDecodeError:
                pass

        compression_method: int = ZIP_COMPRESSION_FROM_STR[compression]
        data = compress(compression_method, level, data)

        if self._encryption != UNENCRYPTED:
            bit_flag[0] = '1'
            data = encrypt(data, self._pwd, crc)
        if compression in (DEFLATE, DEFLATE64):
            if level == FAST:
                bit_flag[2] = '1'
            elif level == MAXIMUM:
                bit_flag[1] = '1'

        compressed_size: int = len(data)

        if compressed_size >= INT32_MAX:
            f_extra_field += b'\x01\x00\x1C\x00'
            f_extra_field += uncompressed_size.to_bytes(8, 'little')
            f_extra_field += compressed_size.to_bytes(8, 'little')
            f_extra_field += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            f_extra_field += b'\x00\x00\x00\x00'

            uncompressed_size = INT32_MAX
            compressed_size = INT32_MAX

        # Only these values are relevant.
        #  0 - MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
        #  3 - UNIX
        # 10 - Windows NTFS
        # 19 - OS X (Darwin)

        # 0x0001        Zip64 extended information extra field
        # 0x000a        NTFS
        # 0x000d        UNIX

        if path.isdir(fd):
            external_attrs = 0x10  # Directory
        else:
            external_attrs = 0x20  # Archive
        
        pl = system()
        if pl == 'Windows':
            platform = 0

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                ntfs_epoch = datetime(1601, 1, 1, tzinfo=UTC)
                delta = dt - ntfs_epoch
                ntfs_time = delta.total_seconds() * 10000000
                return int(ntfs_time).to_bytes(8, 'little')

            h_extra_field += b'\x0a\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00'
            h_extra_field += convert(path.getmtime(fd))
            h_extra_field += convert(path.getatime(fd))
            h_extra_field += convert(path.getctime(fd))
        elif pl == 'Linux':
            platform = 3

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                unix_epoch = datetime(1970, 1, 1, tzinfo=UTC)
                delta = dt - unix_epoch
                unix_time = delta.total_seconds()
                return int(unix_time).to_bytes(4, 'little')
            
            _stat = stat(fd)
            h_extra_field += b'\x0d\x00\x10\x00'
            h_extra_field += convert(_stat.st_atime)
            h_extra_field += convert(_stat.st_mtime)
            h_extra_field += _stat.st_uid.to_bytes(2, 'little')  # UID
            h_extra_field += _stat.st_gid.to_bytes(2, 'little')  # GID
            h_extra_field += (_stat.st_mode & 0xFFF).to_bytes(4, 'little')  # Permissions
            external_attrs |= (_stat.st_mode & 0xFFFF) << 16
        elif pl == 'Darwin':
            platform = 19
        else:
            raise NotImplementedError(f"Unsupported platform: '{pl}'")

        file = FileRaw(
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(f_extra_field),
            filename=fn,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start, internal_file_attrs, external_file_attrs
        # and local_header_relative_offset remain placeholders

        cd_header = CDHeader(
            version_made_by=63,
            platform=platform,
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(h_extra_field),
            comment_length=len(comment.encode(self._encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,
            filename=fn,
            extra_field=h_extra_field,
            comment=comment
        )

        if file.filename in self._files:
            self._sizeof_CD -= len(self._cd_headers[file.filename].encode(self._encoding))

        self._sizeof_CD += len(cd_header.encode(self._encoding))

        self._files[file.filename] = file
        self._cd_headers[file.filename] = cd_header

        self._files = {k: v for k, v in sorted(self._files.items(), key=lambda item: item[0])}
        self._cd_headers = {k: v for k, v in sorted(self._cd_headers.items(), key=lambda item: item[0])}

    def edit_file(
            self,
            fn: str,
            fd: str | bytes | TextIO | BinaryIO,
            fp: str = '.',
            /
    ) -> None:

        for l in fn:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")
        if fp[0] != '.':
            raise ValueError(f"Invalid filepath for argument fp: '{fp}'. All paths should start from '.' (root).")
        for l in fp:
            if l == '/':
                raise ValueError(f"Invalid path for argument fp: '{fp}'. Use \\ instead of / for paths inside archive.")
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fp contains illegal character '{l}'.")

        _p = fp.removeprefix('.\\').replace('\\', '/') + '/' + fn
        if _p in self._files:
            self.create_file(fn, fd, fp)
        else:
            raise FileNotFound(f"File '{fn}' doesn't exist.")

    def remove_file(self, fn: str, fp: str, /) -> None:

        for l in fn:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")
        if fp[0] != '.':
            raise ValueError(f"Invalid filepath for argument fp: '{fp}'. All paths should start from '.' (root).")
        for l in fp:
            if l == '/':
                raise ValueError(f"Invalid path for argument fp: '{fp}'. Use \\ instead of / for paths inside archive.")
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fp contains illegal character '{l}'.")

        fp += '\\' + fn
        _p = fp.removeprefix('.\\').replace('\\', '/')
        try:
            self._files.pop(_p)
        except KeyError:
            raise FileNotFound(f"File '{fn}' doesn't exist.")

    def create_folder(self, fn: str, fp: str = '.', /, encoding: str = 'utf-8') -> str:

        if fn[0] != '.' and fp[0] != '.':
            raise ValueError(f"Invalid filepath for argument fp: {fp}. All paths should start from '.' (root).")
        elif fn[0] == '.' and fp[0] == '.':
            fp += '\\' + fn[2:]
        else:
            fp += '\\' + fn
        
        if any([fp + '\\' in st for st in self.get_structure()]):
            return fp[2:] + '\\'

        i = 0
        _path: list[str] = fp.split('\\')[1:]
        for i in range(len(_path)):
            # Filename should be pathlike, final structure should be like a staircase.
            # Folder1/
            # Folder1/Folder2/
            # Folder1/Folder2/text.txt
            # Folder1/Folder2/...
            self.create_file("/".join(_path[:i + 1]) + '/', b'', encoding=encoding)

        return "\\".join(_path[:i + 1]) + '\\'

    def add_folder(
            self,
            fd: str | bytes | PathLike[str] | PathLike[bytes],
            fp: str = '.',
            /,
            compression: str = STORED,
            level: str = NORMAL,
            comment: str = '',
            use_mp: bool = True
    ) -> None:

        if not path.exists(fd):
            raise FileNotFound(f"Folder '{fd!r}' doesn't exist.")
        if not path.isdir(fd):
            raise ValueError(f"Argument fd should be path to the folder, not to the file. Use add_file instead.")
        if fp[0] != '.':
            raise ValueError(f"Invalid filepath for argument fp: '{fp}'. All paths should start from '.' (root).") 

        files: list[tuple[str, Path, str, str, str, str, str]] = []
    
        def get_all_files(_fd: Path) -> None:
            nonlocal files

            for file in _fd.iterdir():
                # Initial fd is the path of the folder being added. Used to get data of files inside it.
                # fp is additional folder inside zip content will be added to.
                
                __path: str = str(Path(fp).joinpath(file.relative_to(_root)).parent)
                if __path != '.':
                    __path = '.\\' + __path

                try:
                    with open('output.txt', 'a') as f:
                        print(files[-1], file=f)
                except Exception:
                    pass
                if file.is_dir():
                    files.append(
                        (file.name + '/', file, __path, STORED, NORMAL, 'utf-8', comment)
                    )
                    get_all_files(file)
                else:
                    files.append(
                        (file.name, file, __path, compression, level, self._encoding, comment)
                    )

        if isinstance(fd, (bytes, PathLike)):
            _root: Path = Path(str(fd))
        elif isinstance(fd, str):
            _root = Path(fd)
        else:
            raise TypeError(f"Expected str or PathLike object, got '{type(fd).__name__}' instead.")

        get_all_files(_root)

        if len(files) >= 36 and use_mp:
            with Pool(cpu_count()) as pool:
                for result in pool.starmap(self._mp_add_file, files):
                    self._files.update(result[0])
                    self._cd_headers.update(result[1])
                    self._sizeof_CD += result[2]
            self._files = {k: v for k, v in sorted(self._files.items(), key=lambda item: item[0])}
            self._cd_headers = {k: v for k, v in sorted(self._cd_headers.items(), key=lambda item: item[0])}
        else:
            for file in files:
                self.add_file(*file)

    def remove_folder(self, fn: str, fp: str = '.', /) -> list[str]:

        if fp[0] != '.' or (fn[0] != '.' and fp[0] != '.'):
            raise ValueError(f"Invalid filepath for argument fp: {fp}. All paths should start from '.' (root).")
        elif fn == '.':
            pass
        elif fn[0] == '.' and fp[0] == '.':
            fp = fn[2:].replace('\\', '/') + '/'
        else:
            fp += '\\' + fn

        deletes: list[str] = []
        try:
            for _p in self._files.keys():
                if fp in _p[:len(fp)] or fp == '.':
                    deletes.append(_p)
        except KeyError:
            raise FileNotFound(f"Folder '{fp}' doesn't exist.")
        finally:  # Return successfuly deleted files
            for file in deletes:
                self._files.pop(file)

            return deletes

    def add_from_archive(
            self,
            ap: str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            fp: str = '.',
            new_fp: str = '.',
            /,
            pwd: Optional[str] = None,
            compression: str = STORED,
            level: str = NORMAL,
            encoding: str = 'utf-8',
            comment: str = ''
    ):

        with ZipFile.open(ap, pwd, encoding) as z:
            for file_path, file_content in z.peek_all():
                # Check if file is in the specified directory and is not a subfolder of it
                # or add everything if fp is root
                if (fp == file_path[:len(fp)] and fp[2:] != file_path[len(file_path) - len(fp) + 1:-1]) or fp == '.':
                    if file_path.endswith('\\'):
                        self.create_folder(file_path, new_fp, encoding)
                    else:
                        file_name = file_path.split('\\')[-1]
                        self.create_file(file_name, file_content, new_fp, compression, level, encoding, comment)

    def get_structure(self, fp: str = '.', /) -> list[str]:

        if fp[0] != '.':
            raise ValueError(f"Invalid filepath for argument fp: '{fp}'. All paths should start from '.' (root).")

        if fp != '.':
            fp = fp[2:].replace('\\', '/') + '/'
            if fp not in self._files:
                raise FileNotFound(f"Folder '{fp}' doesn't exist.")

        _struct: list[str] = []
        for _p in self._files.keys():
            if fp in _p[:len(fp)] or fp == '.':
                _struct.append('.\\' + _p.replace('/', '\\'))

        return _struct

    def save(self, fn: str, fp: str | bytes | PathLike[str] | PathLike[bytes] = '.', /, comment: str = '') -> None:
        __path = path.join(str(fp), fn)
        current_offset = 0
        
        with open(__path, 'wb') as z:
            for filename, file in self._files.items():
                self._cd_headers[filename].local_header_relative_offset = current_offset
                
                # Update extra field with correct offset (pos 20-28)
                if file.compressed_size >= INT32_MAX:
                    extra_field = file.extra_field
                    if extra_field[:2] == b'\x01\x00':  # ZIP64
                        extra_field = (
                            extra_field[:20] +
                            current_offset.to_bytes(8, 'little') +
                            extra_field[28:]
                        )
                        file.extra_field = extra_field
                        self._cd_headers[filename].extra_field = extra_field
                
                file_bytes = file.encode(self._encoding)
                z.write(file_bytes)
                current_offset += len(file_bytes)
            
            # Запоминаем смещение начала CD
            self._offset = current_offset
            
            for header in self._cd_headers.values():
                z.write(header.encode(self._encoding))
            
            endof_cd = CDEnd(
                disk_num=0,
                disk_num_CD=0,
                total_entries=len(self._files),
                total_CD_entries=len(self._cd_headers),
                sizeof_CD=self._sizeof_CD,
                offset=self._offset,
                comment_length=len(comment.encode(self._encoding)),
                comment=comment
            )
            z.write(endof_cd.encode(self._encoding))

    def _mp_create_folder(self, fn: str, encoding: str) -> str:
        
        fp = fn[2:] + '\\'
        return fp

    def _mp_add_file(
            self,
            fn: str,
            fd: str,
            fp: str,
            compression: str,
            level: str,
            encoding: str,
            comment: str,
    ) -> tuple[dict[str, FileRaw], dict[str, CDHeader], int]:
        """Multiprocessing version of add_file method."""

        if path.isdir(fd):
            data: bytes = b''
        else:
            with open(fd, 'rb') as f:
                data = f.read()

        if fp != '.':
            fn = (fp[2:] + '\\' + fn).replace('\\', '/')

        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        f_extra_field: bytes = b''
        h_extra_field: bytes = b''

        last_mod_time: datetime = datetime.fromtimestamp(path.getmtime(fd), UTC)

        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        v: int = 10

        if compression == DEFLATE or fp != '.' or self._encryption == ZIP_CRYPTO:
            v = 20
        if compression == DEFLATE64:
            v = 21
        if compression == PKWARE_IMPLODING:
            v = 25
        if uncompressed_size >= INT32_MAX:
            v = 45
        if compression == BZIP:
            v = 46
        
        bit_flag: list[str] = list('0000000000000000')

        if all([encoding == 'utf-8', data != b'', not data.isascii()]):
            try:
                data.decode('utf-8')
                bit_flag[11] = '1'  # Language encoding flag (EFS)
            except UnicodeDecodeError:
                pass

        compression_method: int = ZIP_COMPRESSION_FROM_STR[compression]
        data = compress(compression_method, level, data)

        if self._encryption != UNENCRYPTED:
            bit_flag[0] = '1'
            data = encrypt(data, self._pwd, crc)
        if compression in (DEFLATE, DEFLATE64):
            if level == FAST:
                bit_flag[2] = '1'
            elif level == MAXIMUM:
                bit_flag[1] = '1'

        compressed_size: int = len(data)

        if compressed_size >= INT32_MAX:
            f_extra_field += b'\x01\x00\x1C\x00'
            f_extra_field += uncompressed_size.to_bytes(8, 'little')
            f_extra_field += compressed_size.to_bytes(8, 'little')
            f_extra_field += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            f_extra_field += b'\x00\x00\x00\x00'

            uncompressed_size = INT32_MAX
            compressed_size = INT32_MAX

        if path.isdir(fd):
            external_attrs = 0x10  # Directory
        else:
            external_attrs = 0x20  # Archive
        
        pl = system()

        if pl == 'Windows':
            platform = 0

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                ntfs_epoch = datetime(1601, 1, 1, tzinfo=UTC)
                delta = dt - ntfs_epoch
                ntfs_time = delta.total_seconds() * 10000000
                return int(ntfs_time).to_bytes(8, 'little')

            h_extra_field += b'\x0a\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00'
            h_extra_field += convert(path.getmtime(fd))
            h_extra_field += convert(path.getatime(fd))
            h_extra_field += convert(path.getctime(fd))
        elif pl == 'Linux':
            platform = 3

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                unix_epoch = datetime(1970, 1, 1, tzinfo=UTC)
                delta = dt - unix_epoch
                unix_time = delta.total_seconds()
                return int(unix_time).to_bytes(4, 'little')
            
            _stat = stat(fd)
            h_extra_field += b'\x0d\x00\x10\x00'
            h_extra_field += convert(_stat.st_atime)
            h_extra_field += convert(_stat.st_mtime)
            h_extra_field += _stat.st_uid.to_bytes(2, 'little')  # UID
            h_extra_field += _stat.st_gid.to_bytes(2, 'little')  # GID
            h_extra_field += (_stat.st_mode & 0xFFF).to_bytes(4, 'little')  # Permissions
            external_attrs |= (_stat.st_mode & 0xFFFF) << 16
        elif pl == 'Darwin':
            platform = 19
        else:
            raise NotImplementedError(f"Unsupported platform: '{pl}'")
        

        file = FileRaw(
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(f_extra_field),
            filename=fn,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start, internal_file_attrs, external_file_attrs
        # and local_header_relative_offset remain placeholders

        cd_header = CDHeader(
            version_made_by=63,
            platform=platform,
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self._encoding)),
            extra_field_length=len(h_extra_field),
            comment_length=len(comment.encode(self._encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,
            filename=fn,
            extra_field=h_extra_field,
            comment=comment
        )

        self._sizeof_CD += len(cd_header.encode(self._encoding))

        self._files[file.filename] = file
        self._cd_headers[file.filename] = cd_header
        return self._files, self._cd_headers, self._sizeof_CD


class ZipFile(Archive):
    """Class representing the zip file and its contents.

    Attributes:
        files: list of files stored in the zip file.
        comment: file comment.
        total_entries: number of entries in the zip file.
        compression_method: compression method.
            If files in the same archive use different compression algorythms, this value is set to 'Mixed'
    """

    def __init__(
            self,
            files: list[File],
            cd_headers: list[CDHeader],
            endof_cd: CDEnd,
            encoding: str
    ):
        super().__init__(files, endof_cd.comment, endof_cd.total_entries, encoding)
        self._cd_headers: list[CDHeader] = cd_headers
        self._endof_CD: CDEnd = endof_cd

    @staticmethod
    def open(
            f: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            pwd: Optional[str] = None,
            encoding: str = 'utf-8'
    ) -> 'ZipFile':

        files: list[File] = []
        CD_headers: list[CDHeader] = []
        indirect: bool = False  # Binary stream is already initialised

        if isinstance(f, (int, str, bytes, PathLike)):
            f = open(f, 'rb')
            indirect = True
        elif not isinstance(f, BinaryIO):
            raise TypeError(f"Expected argument f to be int, str, bytes or os.PathLike object, got '{type(f).__name__}' instead.")

        try:
            signature: bytes = f.read(4)
            if signature == b'PK\x03\x04':  # First check
                raw_file = FileRaw.__init_raw__(f, encoding)
                files.append(raw_file.decode(pwd))
            elif signature == b'PK\x05\x06': # Empty zip file
                endof_cd = CDEnd.__init_raw__(f, encoding)
                return ZipFile(files, CD_headers, endof_cd, encoding)
            else:
                raise BadFile('File should be in .ZIP format.')

            while True:
                signature = f.read(4)
                if signature == b'PK\x03\x04':  # Getting file headers
                    raw_file = FileRaw.__init_raw__(f, encoding)
                    files.append(raw_file.decode(pwd))
                elif signature == b'PK\x01\x02':  # Getting central directory headers
                    header = CDHeader.__init_raw__(f, encoding)
                    CD_headers.append(header)
                elif signature == b'PK\x05\x06':  # End of centeral directory (stop reading)
                    endof_cd = CDEnd.__init_raw__(f, encoding)
                    break
        finally:
            if indirect:
                f.close()

        # Making sure zip file is not damaged
        for file, header in zip(files, CD_headers):
            crc = crc32(file.contents)
            if file.crc != crc or header.crc != crc:
                raise BadFile('File is corrupted or damaged.')
            file.comment = header.comment  # Can't reach comment in first processing

        return ZipFile(files, CD_headers, endof_cd, encoding)

    @staticmethod
    def new(pwd: Optional[str] = None, encryption: str = UNENCRYPTED, encoding: str = 'utf-8') -> NewZipFile:
        return NewZipFile(pwd, encoding, encryption)

    def edit(self, pwd: Optional[str] = None, encryption: str = UNENCRYPTED) -> NewZipFile:
        z = self.new(pwd, encryption, self.encoding)
        for file in self._files:
            z.create_file(file.filename, file.contents, '.', file.compression_method, file.compression_level)

        return z

    def set_password(self, pwd: str, encryption: str = ZIP_CRYPTO, encoding: str = 'utf-8') -> NewZipFile:
        z = self.new(pwd, encryption, encoding)
        for file in self._files:
            z.add_file(file.filename, file.contents, '.', file.compression_method, file.compression_level)
        return z
