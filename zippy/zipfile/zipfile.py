from typing import BinaryIO, TextIO, Optional, Self
from io import IOBase
from os import PathLike, path, urandom
from platform import system
from datetime import datetime, UTC
from zlib import crc32

from icecream import ic
ic.disable()  # Remove after testing

from .._base_classes import Archive, File
from .utils.ZipEncrypt import ZipEncrypter
from ._zipfile import FileRaw, CDHeader, CDEnd
from ._zip_algorythms import compress
from .exceptions import *
from .encryptions import *
from .compressions import *


class NewZipFile:
    """Class used to create new zip file."""

    def __init__(
            self,
            pwd: Optional[str],
            encoding: str,
            encryption: str
    ):
        # Dictionaries are used to easily replace file's content with new one. All files should "grow" from '.'
        # They are being sorted each time to keep consistent representation.
        self.pwd: Optional[str] = pwd
        self.encoding: str = encoding
        self.encryption: str = encryption
        self.files: dict[str | PathLike, dict[str, FileRaw]] = {'.': {}}
        self.cd_headers: dict[str | PathLike, dict[str, CDHeader]] = {'.': {}}
        self.sizeof_CD: int = 0

    def add_folder(self, fp: str | PathLike[str] = '.') -> str:
        """Add folder inside zip.

        ``fp`` is file's path inside zip. '.' represents root. Every path should start from root.

        Returns string representing final path. Used to add new files to the folder.
        """
        if fp[0] != '.':
            raise ValueError(f'Invalid filepath: {fp}')

        fp = fp.split('\\')[1:]
        for i in range(len(fp)):
            # Filename should be pathlike, final structure should be like a staircase.
            # Folder1/
            # Folder1/Folder2/
            # Folder1/Folder2/text.txt
            self.add_file("/".join(fp[:i + 1]) + '/', '')
        return "/".join(fp[:i + 1]) + '/'

    def add_file(
            self,
            fn: str,
            fd: str | bytes | PathLike[str] | PathLike[bytes] | TextIO | BinaryIO,
            fp: str | PathLike[str] = '.',
            compression: str = STORED,
            level: str = NORMAL,
            *,
            last_mod_time: Optional[datetime] = None,
            encoding: str = 'utf-8',
            comment: str = ''
    ):
        """Add file to zip archive.

        ``fn`` is filename inside zip. It will be encoded in the same encoding specified in file creation.

        ``fd`` is file's data. It can be string, bytes object, os.PathLike, text or binary stream.
        If it's os.PathLike, contents of the file path's leading to will be used.

        ``fp`` is file's path inside zip. '.' represents root. Every path should start from root.

        ``encoding`` is encoding in wich file's data will be encoded. It may vary from the initial encoding.

        If ``last_mod_date`` is not provided and fd is not os.PathLike, current time will be used instead.

        Additional ``comment`` can be applied to the file.
        """

        if fp not in self.files:
            if fp[0] != '.':
                raise ValueError(f'Invalid filepath: {fp}')
            fn = self.add_folder(fp) + fn
            fp = '.'

        initial_fd = None  # Used to get a, m and c time of the file if fd is pathlike.

        if isinstance(fd, (str, bytes)) and path.isfile(fd):
            initial_fd = fd
            last_mod_time = datetime.fromtimestamp(path.getmtime(fd))
            with open(fd, 'rb') as f:
                fd = f.read()
        elif last_mod_time is None:
            last_mod_time = datetime.now()

        # This conversion is based on java8 source code
        time = ((last_mod_time.year - 1980) << 25 | last_mod_time.month << 21 | last_mod_time.day << 16 |
                last_mod_time.hour << 11 | last_mod_time.minute << 5 | last_mod_time.second >> 1)

        if isinstance(fd, IOBase):
            fd = fd.read()
        if isinstance(fd, str):
            fd: bytes = fd.encode(encoding)
        elif not isinstance(fd, bytes):
            raise TypeError(
                f'Expected file data to be str, bytes, os.PathLike, io.TextIO or io.BinaryIO, not {type(fd).__name__}'
            )
        crc: int = crc32(fd)
        uncompressed_size: int = len(fd)

        bit_flag = list('0000000000000000')
        if self.encryption != UNENCRYPTED:
            bit_flag[0] = '1'
        if compression in (DEFLATE, DEFLATE64):
            if level == FAST:
                bit_flag[2] = '1'
            elif level == MAXIMUM:
                bit_flag[1] = '1'
        if self.encoding == 'utf-8' and fn[-1] != '/':
            bit_flag[11] = '1'  # Language encoding flag (EFS)

        compression_method: int = COMPRESSION_FROM_STR[compression]

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

        if compression_method == DEFLATE or (path.isdir(fp) and fp != '.') or self.encryption == ZIP_CRYPTO:
            v = 20
        elif compression_method == DEFLATE64:
            v = 21
        elif compression_method == PKWARE_IMPLODING:
            v = 25
        elif compression_method == BZIP:
            v = 46
        else:
            v = 10

        fd = compress(compression_method, level, fd)
        if bit_flag[0] == '1':
            ze = ZipEncrypter(self.pwd)
            check_byte = crc.to_bytes(4, 'little')[-1]  # Not sure if it's right (me == stupid)
            encryption_header = b"".join(map(ze, urandom(11) + check_byte.to_bytes(1, 'little')))
            fd = encryption_header + b"".join(map(ze, fd))

        # Only these values are relevant today.
        # 0 - MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
        # 3 - UNIX
        # 10 - Windows NTFS
        # 19 - OS X (Darwin)

        # 0x0001        Zip64 extended information extra field
        # 0x000a        NTFS
        # 0x000d        UNIX

        pl = system()
        if pl == 'Windows':
            platform = 10
            if initial_fd:
                def convert(timestap: float) -> bytes:
                    """Conver Unix timestamp to NTFS timestamp."""
                    dt = datetime.fromtimestamp(timestap, UTC)
                    ntfs_epoch = datetime(1601, 1, 1, tzinfo=UTC)
                    delta = dt - ntfs_epoch
                    ntfs_time = delta.total_seconds() * 10000000
                    return int(ntfs_time).to_bytes(8, 'little')

                extra_filed = b'\x0a\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00'
                extra_filed += convert(path.getmtime(initial_fd))
                extra_filed += convert(path.getatime(initial_fd))
                extra_filed += convert(path.getctime(initial_fd))
            else:
                extra_filed = b''
        elif pl == 'Linux':
            platform = 3
        elif pl == 'Darwin':
            platform = 19
        else:
            platform = 0

        file = FileRaw(
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=len(fd),
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self.encoding)),
            extra_field_length=len(extra_filed),
            filename=fn,
            extra_field=extra_filed,
            contents=fd
        )

        # Currently extra_field_length, disk_number_start, internal_file_attrs,
        # local_header_relative_offset and extra_field remain placeholders

        cd_header = CDHeader(
            version_made_by=63,
            platform=platform,
            version_needed_to_exctract=v,
            bit_flag="".join(bit_flag),
            compression_method=compression_method,
            last_mod_time=time.to_bytes(4, 'little')[:2],
            last_mod_date=time.to_bytes(4, 'little')[2:],
            crc=crc,
            compressed_size=len(fd),
            uncompressed_size=uncompressed_size,
            filename_length=len(fn.encode(self.encoding)),
            extra_field_length=len(extra_filed),
            comment_length=len(comment.encode(self.encoding)),
            disk_number_start=0,
            internal_file_attrs=int('0').to_bytes(2, 'little'),  # Doesn't do much
            external_file_attrs=int('0').to_bytes(4, 'little'),  # Should be 0 for stdin
            local_header_relative_offset=0,  # placeholder
            filename=fn,
            extra_field=extra_filed,
            comment=comment
        )
        self.files[fp][file.filename] = file
        self.cd_headers[fp][file.filename] = cd_header
        self.sizeof_CD += len(cd_header.encode(self.encoding))

        self.files[fp] = {k: v for k, v in sorted(self.files[fp].items(), key=lambda item: item[0])}
        self.cd_headers[fp] = {k: v for k, v in sorted(self.cd_headers[fp].items(), key=lambda item: item[0])}

    def save(self, fn: str, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', comment: str = ''):
        """Save new zip file with name ``fn`` at given ``path``.

        Additional ``comment`` can be applied to the file.
        """

        # Storing zip on different disks will not be implemented due to lack of python utils for that task.
        # disk_num, disk_num_CD and offset should be 0
        __path = path.join(__path, fn)
        endof_cd = CDEnd(
            disk_num=0,
            disk_num_CD=0,
            total_entries=len(self.files.values()),
            total_CD_entries=len(self.cd_headers.values()),
            sizeof_CD=self.sizeof_CD,
            offset=0,
            comment_length=len(comment.encode(self.encoding)),
            comment=comment
        )

        with open(__path, 'wb') as z:  # WIP
            for file in self.files['.'].values():
                z.write(b'PK\x03\x04' + file.encode(self.encoding))
            for header in self.cd_headers['.'].values():
                z.write(b'PK\x01\x02' + header.encode(self.encoding))
            z.write(b'PK\x05\x06' + endof_cd.encode(self.encoding))


class ZipFile(Archive):
    """Class representing the zip file and its contents.

    Attributes:
        files: list of files stored in the zip file.
        comment: file comment.
        total_entries: number of entries in the zip file.
        compression_method: compression method.
            If files in the same archive use different compression algorythm, this value is set to 'Mixed'
    """

    def __init__(
            self,
            files: list[File],
            CD_headers: list[CDHeader],
            endof_CD: CDEnd
    ):
        super().__init__(files, endof_CD.comment, endof_CD.total_entries)
        self._CD_headers: list[CDHeader] = CD_headers
        self._endof_CD: CDEnd = endof_CD

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @staticmethod
    def open(
            f: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            pwd: Optional[str] = None,
            encoding: str = 'utf-8'
    ) -> 'ZipFile':
        """Open zip file and return its representation.

        ``f`` must be a filename, pathlike string or a binary data stream.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding to extract files.

        Raises BadFile exception if target file is damaged and inbuild open function exceptions.
        """

        files: list[File] = []
        CD_headers: list[CDHeader] = []
        indirect: bool = False  # Binary stream is already initialised

        if isinstance(f, (int, str, bytes, PathLike)):
            f: BinaryIO = open(f, 'rb')
            indirect = True
        elif not isinstance(f, BinaryIO):
            raise TypeError(f'Expected int, str, bytes or os.PathLike object, not {type(f).__name__}.')

        try:
            signature = f.read(4)
            if signature == b'PK\x03\x04':  # First check
                raw_file = ic(FileRaw.__init_raw__(f, encoding))
                files.append(raw_file.decode(pwd))
            elif signature == b'PK\x05\x06':
                raise BadFile('Empty zip file.')
            else:
                raise BadFile('File should be in .ZIP format.')

            while True:
                signature = f.read(4)
                if signature == b'PK\x03\x04':  # Getting file headers
                    raw_file = ic(FileRaw.__init_raw__(f, encoding))
                    files.append(raw_file.decode(pwd))
                elif signature == b'PK\x01\x02':  # Getting central directory headers of fieles
                    header = ic(CDHeader.__init_raw__(f, encoding))
                    CD_headers.append(header)
                elif signature == b'PK\x05\x06':  # End of centeral directory (stop reading)
                    endof_cd = ic(CDEnd.__init_raw__(f, encoding))
                    break
                else:
                    # print(signature)
                    break
        finally:
            if indirect:
                f.close()

        # Making sure zip file is not damaged
        for file, header in zip(files, CD_headers):
            if file.crc != crc32(file.contents) or header.crc != crc32(file.contents):
                raise BadFile('File is corrupted or damaged.')
            file.comment = header.comment

        return ZipFile(files, CD_headers, endof_cd)

    @staticmethod
    def new(pwd: Optional[str] = None, encryption: str = UNENCRYPTED, encoding: str = 'utf-8') -> NewZipFile:
        """Initialize creation of new zip file.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding on files.
        It is also reccomended not to mix different encodings.
        """
        return NewZipFile(pwd, encoding, encryption)
