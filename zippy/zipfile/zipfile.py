from typing import BinaryIO, TextIO, Optional, Self
from os import PathLike, path

from zlib import crc32

from .._base_classes import Archive, File
from ._zipfile import FileRaw, CDHeader, CDEnd
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
        self.pwd: Optional[str] = pwd
        self.encoding: str = encoding
        self.encryption: str = encryption
        self.files: dict[str | PathLike, list[FileRaw]] = {'.': []}
        self.cd_headers: dict[str | PathLike, list[CDHeader]] = {'.': []}

    def add_file(
            self,
            fn: str,
            fd: str | bytes | TextIO | BinaryIO,
            fp: str | PathLike[str] = '.',
            compression: str = STORED,
            encoding: str = 'utf-8',
            comment: str = ''
    ):
        """Add file to zip archive.

        ``fn`` is filename. It should be encoded in the same encoding specified in file creation.

        ``fd`` is file's data. It can be string, bytes object, text and binary stream.

        ``fp`` is file's path inside zip. '.' represents root. Every path should start from root.

        ``encoding`` is encoding in wich file's data will be encoded. It may vary from the initial encoding.

        Additional ``comment`` can be applied to the file.
        """

        if fp not in self.files:
            if fp[0] != '.':
                raise ValueError(f'Invalid filepath {fp}')
            self.files.update({fp: []})

        if isinstance(fd, bytes):
            crc: int = crc32(fd)
        elif isinstance(fd, (TextIO, BinaryIO)):
            crc: int = crc32(fd.read())
        elif isinstance(fd, str):
            fd: bytes = fd.encode(encoding)
            crc: int = crc32(fd)
            uncompressed_size: int = len(fd)
        else:
            raise TypeError(f'Expected file data to be str, bytes, io.TextIO or io.BinaryIO, not {type(fd).__name__}')

        bit_flag: list[str] = list('00000000')
        if self.encryption != 'Unencrypted':
            bit_flag[0] = '1'
        bit_flag: bytes = int("".join(bit_flag), 2).to_bytes(2, 'little')

        # TODO: make version_needed_to_exctract values table
        # TODO: make compression_method values table

        file = FileRaw(
            version_needed_to_exctract=10,  # placeholder
            bit_flag=bit_flag,
            compression_method=0,  # placeholder
            last_mod_time=0,  # placeholder
            last_mod_date=0,  # placeholder
            crc=crc,
            compressed_size=uncompressed_size,  # placeholder
            uncompressed_size=uncompressed_size,
            file_name_length=len(fn.encode(self.encoding)),
            extra_field_length=0,  # placeholder
            file_name=fn,
            extra_field=b'',  # palceholder
            contents=fd
        )

        cd_header = CDHeader(
            version_made_by=63,
            version_needed_to_exctract=10,  # placeholder
            bit_flag=bit_flag,
            compression_method=0,  # placeholder
            last_mod_time=0,  # placeholder
            last_mod_date=0,  # placeholder
            crc=crc,
            compressed_size=uncompressed_size,  # placeholder
            uncompressed_size=uncompressed_size,
            file_name_length=len(fn.encode(self.encoding)),
            extra_field_length=0,  # placeholder
            file_comment_length=len(comment.encode(self.encoding)),  # placeholder
            disk_number_start=0,  # placeholder
            internal_file_attrs=int('0').to_bytes(2, 'little'),
            external_file_attrs=int('0').to_bytes(4, 'little'),
            local_header_relative_offset=0,  # placeholder
            file_name=fn,
            extra_field=b'',  # palceholder
            file_comment=comment
        )
        self.files[fp].append(file)
        self.cd_headers[fp].append(cd_header)

    def save(self, fn: str, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', comment: str = ''):
        """Save new zip file with name ``fn`` at given ``path``.

        Additional ``comment`` can be applied to the file.
        """

        __path = path.join(__path, fn)
        endof_cd = CDEnd(  # This entire thing is a placeholder (it doesn't matter when unpacking)
            disk_num=0,
            disk_num_CD=0,
            total_entries=len(self.files.values()),
            total_CD_entries=len(self.files.values()),
            sizeof_CD=0,
            offset=0,
            comment_length=0,
            comment=comment
        )

        with open(__path, 'wb') as z:
            for file in self.files['.']:
                z.write(b'PK\x03\x04' + file.encode(self.encoding))
            for header in self.cd_headers['.']:
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
                raw_file = FileRaw.__init_raw__(f, encoding)
                files.append(raw_file.decode(pwd))
            elif signature == b'PK\x05\x06':
                raise BadFile('Empty zip file.')
            else:
                raise BadFile('File should be in .ZIP format.')

            while True:
                signature = f.read(4)
                if signature == b'PK\x03\x04':  # Getting file headers
                    raw_file = FileRaw.__init_raw__(f, encoding)
                    files.append(raw_file.decode(pwd))
                elif signature == b'PK\x01\x02':  # Getting central directory headers of fieles
                    header = CDHeader.__init_raw__(f, encoding)
                    CD_headers.append(header)
                elif signature == b'PK\x05\x06':  # End of centeral directory (stop reading)
                    endof_cd = CDEnd.__init_raw__(f, encoding)
                    break
                else:
                    # print(signature)
                    break
        finally:
            if indirect:
                f.close()

        # Making sure zip file is not damaged
        for file, header in zip(files, CD_headers):
            if file.crc != header.crc:
                raise BadFile('File is corrupted or damaged.')

        return ZipFile(files, CD_headers, endof_cd)

    @staticmethod
    def new(pwd: Optional[str] = None, encoding: str = 'utf-8', encryption: str = UNECNCRYPTED) -> NewZipFile:
        """Initialize creation of new zip file.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding on files.
        It is also reccomended not to mix different encodings.
        """
        return NewZipFile(pwd, encoding, encryption)
