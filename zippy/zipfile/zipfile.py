from datetime import datetime, UTC
from multiprocessing import Pool, cpu_count
from os import PathLike, stat, sep
from os import path as os_path
from pathlib import Path
from platform import system
from typing import BinaryIO, TextIO, Optional
from zlib import crc32

from .._base_classes import Archive, File, NewArchive
from ..constants import *
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

# TODO: Implement most of the compression algorythms.

# TODO: Add debug feature.

# TODO: Add support for macOS file system.

# TODO: Add support for extended timestamps

class NewZipFile(NewArchive):
    """Class used to create new zip file."""

    def __init__(
            self,
            pwd: Optional[str],
            encoding: str,
            encryption: ZipEncryptions
    ):
        # Dictionaries are used to easily replace file's content with new one.
        super().__init__(pwd, encoding, encryption)
        self._files: dict[str, FileRaw] = {}
        self._cd_headers: dict[str, CDHeader] = {}
        self._sizeof_CD: int = 0
        self._current_root: Optional[str] = None
        self._encryption: ZipEncryptions

    # see _base_classes.py for documentation.
    def get_files(self, encoding: str = 'utf-8') -> dict[str, File]:
        return {k.replace('/', sep): v.decode(encoding) for k, v in self._files.items()}

    def get_structure(self, path: str = '', /) -> list[str]:
        if path == '':
            return list(
                sorted(
                    file_path.replace('/', sep) for file_path in self._files
                )
            )
        else:
            if path.replace(sep, '/') + '/' not in self._files:
                raise FileNotFound(f"Folder '{path}' doesn't exist.")

            return list(
                sorted(
                    file_path.replace('/', sep) for file_path in self._files if path in file_path[:len(path)]
                )
            )

    def create_file(
            self,
            path: str,
            contents: str | bytes | TextIO | BinaryIO,
            /,
            compression: ZipCompressions = 'Stored',
            level: ZipLevels = 'Normal',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:

        for l in path:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument path contains illegal character '{l}'.")

        if path[-1] == sep:
            if any([compression != 'Stored', level != 'Normal', encoding != 'utf-8']):
                raise ValueError("An incorrect attempt to create a folder was cancelled. " \
                                 "Folder must be STORED with NORMAL level and in utf-8 encoding for add_file method. " \
                                 "Prefer to using create_folder instead, since subfolders will not be automatically created this way.")
            filename: str = path.replace('\\', '/')  # already a full path
            file_path: str = ''
        else:
            filename = os_path.basename(path)
            file_path = os_path.dirname(path)

        data: bytes
        if isinstance(contents, TextIO):
            data = contents.read().encode(encoding)
        elif isinstance(contents, BinaryIO):
            data = contents.read()
        elif isinstance(contents, str):
            data = contents.encode(encoding)
        elif isinstance(contents, bytes):
            data = contents
        else:
            raise TypeError(f"Expected argument content to be str, bytes, io.TextIO or io.BinaryIO, not {type(contents).__name__}.")

        if file_path != '':
            self.create_folder(file_path, encoding)
            filename = os_path.join(file_path, filename).replace('\\', '/')

        last_mod_time: datetime = datetime.now()
        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        v: int = 10

        if compression == 'Deflate' or filename[-1] == '/' or self._encryption == 'ZipCrypto':
            v = 20
        if compression == 'Deflate64':
            v = 21
        if compression == 'PKWARE Imploding':
            v = 25
        if uncompressed_size >= INT32_MAX:
            v = 45
        if compression == 'BZIP2':
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

        if self._encryption != 'Unencrypted':
            bit_flag[0] = '1'
            data = encrypt(data, self._pwd, crc)
        if compression in (DEFLATE, DEFLATE64):
            if level == FAST:
                bit_flag[2] = '1'
            elif level == MAXIMUM:
                bit_flag[1] = '1'

        compressed_size: int = len(data)
        f_extra_field: bytes = b''

        if compressed_size >= INT32_MAX:
            f_extra_field += b'\x01\x00\x1C\x00'
            f_extra_field += uncompressed_size.to_bytes(8, 'little')
            f_extra_field += compressed_size.to_bytes(8, 'little')
            f_extra_field += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            f_extra_field += b'\x00\x00\x00\x00'

            uncompressed_size = INT32_MAX
            compressed_size = INT32_MAX
        
        if filename[-1] == '/':
            external_attrs = 0x10  # Directory
        else:
            external_attrs = 0x20  # Archive

        pl = system()
        if pl == 'Windows':
            platform = 0
        elif pl == 'Linux':
            platform = 3
        elif pl == 'Darwin':
            platform = 19
        else:
            raise NotImplementedError(f"Unsupported platform '{pl}'")

        file = FileRaw(
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(filename.encode(self._encoding)),
            extra_field_length=len(f_extra_field),
            filename=filename,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start remain placeholder

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
            filename_length=len(filename.encode(self._encoding)),
            extra_field_length=0,
            comment_length=len(comment.encode(self._encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,  # Changed later in save method
            filename=filename,
            extra_field=b'',
            comment=comment
        )

        if file.filename in self._files:
            self._sizeof_CD -= len(self._cd_headers[file.filename].encode(self._encoding))

        self._sizeof_CD += len(cd_header.encode(self._encoding))

        self._files[file.filename] = file
        self._cd_headers[file.filename] = cd_header

    def add_file(
            self,
            source: int | str | bytes | PathLike[str] | PathLike[bytes],
            path: str = '',
            /,
            compression: ZipCompressions = 'Stored',
            level: ZipLevels = 'Normal',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:

        for l in path:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument path contains illegal character '{l}'.")
        if path == '':
            if isinstance(source, int):
                raise ValueError("Need to specify path if source is a file descriptor.")
            path = str(os_path.basename(source))
        if os_path.isdir(source):
            if any([compression != 'Stored', level != 'Normal', encoding != 'utf-8']):
                raise ValueError("An attempt to add a folder was cancelled. " \
                                 "Folder must be STORED with NORMAL level without specified encoding. " \
                                 "Prefer to using add_folder instead, since child files will not be added by using add_file.")
            if path[-1] == '/':
                filename: str = path.replace('\\', '/')
                file_path: str = ''
            else:
                if isinstance(source, int):
                    raise ValueError("Can't use file descriptor to add folders using add_file.")
                filename = str(os_path.basename(source))
                file_path = path
        else:
            filename = os_path.basename(path)
            file_path = os_path.dirname(path)

        data: bytes
        if isinstance(source, (int, str, bytes, PathLike)):
            if not os_path.exists(source):
                raise FileNotFound(f"File {source!r} doesn't exist.")
            if os_path.isdir(source):
                data = b''
            else:
                with open(source, 'rb') as f:
                    data = f.read()
        else:
            raise TypeError(
                f"Expected argument source to be int, str, bytes or os.PathLike, not {type(source).__name__}"
            )

        if file_path != '':
            self.create_folder(file_path, encoding)
            filename = os_path.join(file_path, filename).replace('\\', '/')

        last_mod_time: datetime = datetime.now()
        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        f_extra_field: bytes = b''
        h_extra_field: bytes = b''

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

        if compression == 'Deflate' or filename[-1] == '/' or self._encryption == 'ZipCrypto':
            v = 20
        if compression == 'Deflate':
            v = 21
        if compression == 'PKWARE Imploding':
            v = 25
        if uncompressed_size >= INT32_MAX:
            v = 45
        if compression == 'BZIP2':
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

        if self._encryption != 'Unencrypted':
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
        # 19 - OS X (Darwin)

        # 0x0001        Zip64 extended information extra field
        # 0x000a        NTFS
        # 0x000d        UNIX

        if os_path.isdir(source):
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
            h_extra_field += convert(os_path.getmtime(source))
            h_extra_field += convert(os_path.getatime(source))
            h_extra_field += convert(os_path.getctime(source))
        elif pl == 'Linux':
            platform = 3

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                unix_epoch = datetime(1970, 1, 1, tzinfo=UTC)
                delta = dt - unix_epoch
                unix_time = delta.total_seconds()
                return int(unix_time).to_bytes(4, 'little')
            
            _stat = stat(source)
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
            filename_length=len(filename.encode(self._encoding)),
            extra_field_length=len(f_extra_field),
            filename=filename,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start remain placeholder

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
            filename_length=len(filename.encode(self._encoding)),
            extra_field_length=len(h_extra_field),
            comment_length=len(comment.encode(self._encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,  # Changed later in save method
            filename=filename,
            extra_field=h_extra_field,
            comment=comment
        )

        if file.filename in self._files:
            self._sizeof_CD -= len(self._cd_headers[file.filename].encode(self._encoding))

        self._sizeof_CD += len(cd_header.encode(self._encoding))

        self._files[file.filename] = file
        self._cd_headers[file.filename] = cd_header

    def edit_file(
            self,
            path: str,
            contents: str | bytes | TextIO | BinaryIO,
            /
    ) -> None:

        for l in path:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")

        path = path.replace('\\', '/')
        if path in self._files:
            self.create_file(path, contents)
        elif path + '/' in self._files:
            raise ZippyException(f"Can't edit folders.")
        else:
            raise FileNotFound(f"File '{path}' doesn't exist.")

    def create_folder(self, path: str, /, encoding: str = 'utf-8') -> None:
        
        path = path.replace('/', sep)
        struct: list[str] = self.get_structure()
        
        if path + sep in struct:
            return

        i = 0
        paths: list[str] = path.split(sep)

        for i in range(len(paths)):
            # Filename should be pathlike, final structure should be like a staircase.
            # Folder1/
            # Folder1/Folder2/
            # Folder1/Folder2/text.txt
            # Folder1/Folder2/...
            if paths[i] + sep in struct:
                continue
            self.create_file(sep.join(paths[:i + 1]) + sep, b'', encoding=encoding)

    def add_folder(
            self,
            source: str | bytes | PathLike[str] | PathLike[bytes],
            path: str = '',
            /,
            compression: ZipCompressions = 'Stored',
            level: ZipLevels = 'Normal',
            encoding: str = 'utf-8',
            comment: str = '',
            *,
            use_mp: bool = False
    ) -> None:

        if not os_path.exists(source):
            raise FileNotFound(f"Folder '{source!r}' doesn't exist.")
        if not os_path.isdir(source):
            raise ValueError(f"Argument source is leading to the file. Use add_file instead.")
        for l in path:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument path contains illegal character '{l}'.")
            
        if path != '':
            self.create_folder(path, encoding)

        files: list[tuple[Path, str, ZipCompressions, ZipLevels, str, str, str, Optional[str]]] = []
    
        def get_all_files(current_root: Path) -> None:
            nonlocal files

            for file in current_root.iterdir():
                # Initial fd is the path of the folder being added. Used to get data of files inside it.
                # fp is additional folder inside zip content will be added to.
                
                final_path: str = str(Path(path).joinpath(file.relative_to(root)))

                if file.is_dir():
                    files.append(
                        (file, final_path + '/', 'Stored', 'Normal', 'utf-8', comment, self._encryption, self._pwd)
                    )
                    get_all_files(file)
                else:
                    files.append(
                        (file, final_path, compression, level, encoding, comment, self._encryption, self._pwd)
                    )

        if isinstance(source, (bytes, PathLike)):
            root: Path = Path(str(source))
        elif isinstance(source, str):
            root = Path(source)
        else:
            raise TypeError(f"Expected argument source to be str, bytes or os.PathLike, not {type(source).__name__}")

        get_all_files(root)

        if len(files) >= 36 and use_mp:
            with Pool(cpu_count()) as pool:
                for result in pool.starmap(self._mp_add_file, files):
                    for path in result[0].keys():
                        if path in self._files:
                            self._sizeof_CD -= len(self._cd_headers[path].encode(self._encoding))
                    self._files.update(result[0])
                    self._cd_headers.update(result[1])
                    self._sizeof_CD += result[2]
        else:
            for file in files:
                self.add_file(*file[:-2])

    def remove(self, path: str = '', /) -> None:
        for l in path:
            if l in ILLEGAL_CHARS:
                raise ValueError(f"Argument fn contains illegal character '{l}'.")

        __path: str = path.replace('\\', '/')
        if __path in self._files:
            self._files.pop(__path)
        elif __path == '':
            self._files.clear()
        elif __path + '/' in self._files:
            for file in self._files.copy().keys():
                if __path in file[:len(__path)]:
                    self._files.pop(file)
        else:
            raise FileNotFound(f"File '{path}' doesn't exist.")

    def add_from_archive(
            self,
            archive: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            path: str = '',
            new_path: str = '',
            /,
            pwd: Optional[str] = None,
            compression: ZipCompressions = 'Stored',
            level: ZipLevels = 'Normal',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        path = path.replace('\\', sep)
        with ZipFile.open(archive, pwd, encoding) as z:
            for file_path, file_contents in z.get_files().items():
                # Check if file is in the specified directory and is not a subfolder of it
                # or add everything if fp is root
                if path + sep == file_path:
                    self.create_folder(os_path.join(new_path, file_path), encoding)
                    return
                if (path == file_path[:len(path)] and path != file_path) or path == '':
                    if file_path.endswith(sep):
                        self.create_file(os_path.join(new_path, file_path[len(path):]), b'', encoding=encoding)
                    else:
                        self.create_file(os_path.join(new_path, file_path[len(path):]), file_contents, compression, level, encoding, comment)

    def save(self, path: int | str | bytes | PathLike[str] | PathLike[bytes], /, comment: str = '') -> None:
        current_offset = 0
        
        with open(path, 'wb') as z:
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
            
            for header in self._cd_headers.values():
                z.write(header.encode(self._encoding))
            
            endof_cd = CDEnd(
                disk_num=0,
                disk_num_CD=0,
                total_entries=len(self._files),
                total_CD_entries=len(self._cd_headers),
                sizeof_CD=self._sizeof_CD,
                offset=current_offset,
                comment_length=len(comment.encode(self._encoding)),
                comment=comment
            )
            z.write(endof_cd.encode(self._encoding))

    @staticmethod
    def _mp_add_file(
            source: str | bytes | PathLike[str] | PathLike[bytes],
            path: str,
            compression: ZipCompressions,
            level: ZipLevels,
            encoding: str,
            comment: str,
            encryption: ZipEncryptions,
            pwd: Optional[str]
    ) -> tuple[dict[str, FileRaw], dict[str, CDHeader], int]:
        """Multiprocessing version of add_file method."""

        if os_path.isdir(source):
            data: bytes = b''
        else:
            with open(source, 'rb') as f:
                data = f.read()

        filename: str = path.replace('\\', '/')

        crc: int = crc32(data)
        uncompressed_size: int = len(data)

        f_extra_field: bytes = b''
        h_extra_field: bytes = b''

        last_mod_time: datetime = datetime.fromtimestamp(os_path.getmtime(source), UTC)

        # This conversion is based on java8 source code
        time: int = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                      last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        v: int = 10

        if compression == DEFLATE or encryption == ZIP_CRYPTO:
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

        if encryption != 'Unencrypted':
            bit_flag[0] = '1'
            data = encrypt(data, pwd, crc)
        if compression in ('Deflate', 'Deflate64'):
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

        if os_path.isdir(source):
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
            h_extra_field += convert(os_path.getmtime(source))
            h_extra_field += convert(os_path.getatime(source))
            h_extra_field += convert(os_path.getctime(source))
        elif pl == 'Linux':
            platform = 3

            def convert(timestap: float) -> bytes:
                dt = datetime.fromtimestamp(timestap, UTC)
                unix_epoch = datetime(1970, 1, 1, tzinfo=UTC)
                delta = dt - unix_epoch
                unix_time = delta.total_seconds()
                return int(unix_time).to_bytes(4, 'little')
            
            _stat = stat(source)
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
            filename_length=len(filename.encode(encoding)),
            extra_field_length=len(f_extra_field),
            filename=filename,
            extra_field=f_extra_field,
            contents=data
        )

        # Currently disk_number_start remain placeholder

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
            filename_length=len(filename.encode(encoding)),
            extra_field_length=len(h_extra_field),
            comment_length=len(comment.encode(encoding)),
            disk_number_start=0,
            internal_file_attrs=b'\x00\x00',
            external_file_attrs=external_attrs.to_bytes(4, 'little'),
            local_header_relative_offset=0,
            filename=filename,
            extra_field=h_extra_field,
            comment=comment
        )

        return {file.filename: file}, {file.filename: cd_header}, len(cd_header.encode(encoding))

class ZipFile(Archive):
    """Class representing the zip file and its contents. Use one of the static methods to initialise it."""

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
        indirect: bool = False

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
    def new(pwd: Optional[str] = None, encryption: ZipEncryptions = 'Unencrypted', encoding: str = 'utf-8') -> NewZipFile:
        return NewZipFile(pwd, encoding, encryption)

    def edit(self, pwd: Optional[str] = None, encryption: ZipEncryptions = 'Unencrypted') -> NewZipFile:
        z = self.new(pwd, encryption, self.encoding)
        for file in self._files:
            z.create_file(file.filename, file.contents, file.compression_method, file.compression_level)  # type: ignore # mypy: ignore-errors [This arguments can only be supported strings]
        return z

    def set_password(self, pwd: str, encryption: ZipEncryptions = 'ZipCrypto', encoding: str = 'utf-8') -> NewZipFile:
        z = self.new(pwd, encryption, encoding)
        for file in self._files:
            z.create_file(file.filename, file.contents, file.compression_method, file.compression_level)  # type: ignore # mypy: ignore-errors [This arguments can only be supported strings]
        return z
