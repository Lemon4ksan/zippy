import io
import xz
import mp3
import bz2
# import lzma
# import pyppmd
import deflate
import zstandard
from zippy.utils import pwexplode
from zippy.utils import LZ77

from dataclasses import dataclass
from datetime import date, time, datetime
from typing import BinaryIO, Optional
from os import PathLike, mkdir, path

@dataclass
class File:
    """Clean representation of the file.

    Attributes:
        file_name (:obj:`str`): Name of the file.
        version_needed_to_exctract (:obj:`str`): Minimal version of zip required to unpack.
        encryption_method (:obj:`str`): Name of the encryption method. Unencrypted if none.
        compression_method (:obj:`str`): Name of the compression method. Stored if none.
        last_mod_time (:class:`datetime`): Datetime of last modification of the file.
        crc (:obj:`int`): CRC of the file. Used to check for corruptions.
        compressed_size (:obj:`int`): Compressed size of the file.
        uncompressed_size (:obj:`int`): Uncompressed size of the file.
        contents (:obj:`bytes`): Undecoded contents of the file.
    """

    file_name: str
    version_needed_to_exctract: str
    encryption_method: str
    compression_method: str
    last_mod_time: datetime
    crc: int
    compressed_size: int
    uncompressed_size: int
    contents: bytes

    def extract(self, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', encoding: str = 'utf-8'):
        """Extract single file to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded, its byte representation will be extracted instead.
        """

        contents = self.peek(encoding)
        if not path.exists(__path):
            mkdir(__path)
        __path = path.join(__path, self.file_name.replace('/', '\\'))

        if not path.exists(__path) and self.file_name[-1] == '/':
            # Create folder
            mkdir(__path)
        elif isinstance(contents, str):
            # Otherwise, write to file
            with open(__path, 'w') as f:
                f.write(contents)
        else:
            with open(__path, 'wb') as f:
                f.write(contents)

    def peek(self, encoding: str = 'utf-8', ignore_overflow: bool = False, char_limit: int = 8191) -> str | bytes:
        """Decode file contents.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit`` characters (bytes) will be partially shown.
        """

        try:
            content = io.BytesIO(self.contents).read().decode(encoding)
        except ValueError:  # Decoding falied
            content = io.BytesIO(self.contents).read()

        if len(content) > char_limit and not ignore_overflow:
            if isinstance(content, str):
                return content[:char_limit // 2] + '... File too large to display'
            else:
                return content[:char_limit // 32] + b'... File too large to display'
        else:
            return content


@dataclass
class FileRaw:
    """File extracted from archive. It's uncompressed, not decrypted (if it was)
     and contains data fields that user doesn't need."""

    version_needed_to_exctract: str
    bit_flag: str
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc: bytes
    compressed_size: int
    uncompressed_size: int
    file_name_length: int
    extra_field_length: int
    file_name: str
    extra_field: bytes
    contents: bytes

    def __init__(self, file: BinaryIO, encoding: str):
        version = [str(byte) for byte in file.read(2)]
        self.version_needed_to_exctract = str(f'{str(version[0])[0]}.{str(version[0])[1]}')
        if version[1] != '0':  # This byte is unused
            self.version_needed_to_exctract += f'({str(version[1])[0]}.{str(version[1])[1]})'
        self.bit_flag = "".join(format(bit, 'b') for bit in file.read(2))
        self.compression_method = int.from_bytes(file.read(2), 'little')
        self.last_mod_time = int.from_bytes(file.read(2), 'little')
        self.last_mod_date = int.from_bytes(file.read(2), 'little')
        self.crc = file.read(4)
        self.compressed_size = int.from_bytes(file.read(4), 'little')
        self.uncompressed_size = int.from_bytes(file.read(4), 'little')
        self.file_name_length = int.from_bytes(file.read(2), 'little')
        self.extra_field_length = int.from_bytes(file.read(2), 'little')
        self.file_name = file.read(self.file_name_length).decode(encoding)
        self.extra_field = file.read(self.extra_field_length)
        self.contents = file.read(self.compressed_size)

    def decode(self, pwd: Optional[str]):

        if self.bit_flag[0] == '0':
            encryption_method = 'Unencrypted'

        if self.compression_method == 0:
            compression_method = 'Stored'
            contents = self.contents
        elif self.compression_method in range(1, 6):
            raise NotImplemented('Shrinking and Reducing are no longer supported.')
        elif self.compression_method == 6:
            raise NotImplemented('Legacy Implode is no longer supported. Use PKWARE Data Compression Library Imploding instead.')
        elif self.compression_method == 7:
            raise NotImplemented('Tokenizing is not used by PKZIP.')
        elif self.compression_method == 8:
            compression_method = 'Deflate'
            contents = deflate.deflate_decompress(self.contents, self.uncompressed_size)
        elif self.compression_method == 9:
            compression_method = 'Deflate64'
            contents = deflate.deflate_decompress(self.contents, self.uncompressed_size)
        elif self.compression_method == 10:
            compression_method = 'PKWARE Data Compression Library Imploding'
            contents = pwexplode.explode(self.contents)  # Untested
        elif self.compression_method == 11:
            raise ValueError('Compression method 11 is reserved.')
        elif self.compression_method == 12:
            compression_method = 'BZIP2'
            contents = bz2.decompress(self.contents)
        elif self.compression_method == 13:
            raise ValueError('Compression method 13 is reserved.')
        elif self.compression_method == 14:
            # eos = self.bit_flag[-2]
            # compression_method = 'LZMA'
            # contents = lzma.decompress(self.contents, ???)  # Doesn't work for some reason.
            # Also don't know how to make it to use EOS.
            raise NotImplemented('LZMA compression is not implemented yet.')
        elif self.compression_method == 15:
            raise ValueError('Compression method 15 is reserved.')
        elif self.compression_method == 16:  # can't find this
            raise NotImplemented('IBM z/OS CMPSC Compression is not implemented.')
        elif self.compression_method == 17:
            raise ValueError('Compression method 17 is reserved.')
        elif self.compression_method == 18:  # can't find this, somebody uses it?
            raise NotImplemented('IBM TERSE is not implemented.')
        elif self.compression_method == 19:
            compression_method = 'LZ77'
            contents = LZ77.decompress(self.contents)  # Untested
        elif self.compression_method == 20:
            raise NotImplemented('Method 20 is deprecated. Use Zstandart compression instead.')
        elif self.compression_method == 93:
            compression_method = 'Zstandart'
            contents = zstandard.decompress(self.contents)
        elif self.compression_method == 94:
            compression_method = 'MP3'
            contents = mp3.Decoder(self.contents).read()
        elif self.compression_method == 95:
            compression_method = 'XZ'
            contents = xz.decompress(self.contents)
        elif self.compression_method == 96:
            raise NotImplemented('JPEG compression is not implemented yet.')
        elif self.compression_method == 97:
            raise NotImplemented('WavPack compression is not implemented yet.')
        elif self.compression_method == 98:
            # compression_method = 'PPMd'  # Docs says that only version I, Rev 1 of PPMd is supported
            # maybe that's the reason it doesn't work
            # contents = pyppmd.decompress(self.contents, mem_size=self.uncompressed_size)
            raise NotImplemented('PPMd compression is not implemented yet.')
        elif self.compression_method == 99:  # What is this??
            raise NotImplemented('AE-x encryption marker compression is not implemented yet.')

        # This conversion is based on java8 source code.
        # Some precision is lost, but I can't find more appropriate method of doing this.
        try:
            last_mod_time = time((self.last_mod_time >> 11) & 0x1F, (self.last_mod_time >> 5) & 0x3F,
                                 ((self.last_mod_time << 1) & 0x3E) - 2)
            last_mod_date = date((self.last_mod_date >> 9) + 1980, (self.last_mod_date >> 5) & 0xF,
                                 self.last_mod_date & 0x1F)
        except ValueError:
            last_mod_time = None
            last_mod_date = None

        crc = int.from_bytes(self.crc, 'little')

        return File(
            self.file_name,
            self.version_needed_to_exctract,
            encryption_method,
            compression_method,
            datetime.combine(last_mod_date, last_mod_time) if last_mod_time is not None else None,
            crc,
            self.compressed_size,
            self.uncompressed_size,
            contents
        )


@dataclass
class CDHeader:
    """Contents of Central Directory Header.
    See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT for full documentation.
    """

    version_made_by: bytes
    version_needed_to_exctract: int
    bit_flag: bytes
    compression: bytes
    last_mod_time: Optional[time]
    last_mod_date: Optional[date]
    crc: int
    compressed_size: int
    uncompressed_size: int
    file_name_length: int
    extra_field_length: int
    file_comment_length: int
    disk_number_start: int
    internal_file_attrs: bytes
    external_file_attrs: bytes
    local_header_relative_offset: int
    file_name: str
    extra_field: bytes
    file_comment: str

    def __init__(self, file: BinaryIO, encoding: str):
        self.version_made_by = file.read(2)
        self.version_needed_to_exctract = int.from_bytes(file.read(2), 'little')
        self.bit_flag = file.read(2)
        self.compression = file.read(2)
        last_mod_time = int.from_bytes(file.read(2), 'little')
        last_mod_date = int.from_bytes(file.read(2), 'little')
        # This conversion is based on java8 source code.
        # Some precision is lost, but I can't find more appropriate method of doing this.
        try:
            self.last_mod_time = time((last_mod_time >> 11) & 0x1F, (last_mod_time >> 5) & 0x3F,
                                      ((last_mod_time << 1) & 0x3E) - 2)
            self.last_mod_date = date((last_mod_date >> 9) + 1980, (last_mod_date >> 5) & 0xF, last_mod_date & 0x1F)
        except ValueError:
            self.last_mod_time = self.last_mod_date = None  # In case it's a folder
        crc = file.read(4)
        self.crc = int.from_bytes(crc, 'little')
        self.compressed_size = int.from_bytes(file.read(4), 'little')
        self.uncompressed_size = int.from_bytes(file.read(4), 'little')
        self.file_name_length = int.from_bytes(file.read(2), 'little')
        self.extra_field_length = int.from_bytes(file.read(2), 'little')
        self.file_comment_length = int.from_bytes(file.read(2), 'little')
        self.disk_number_start = int.from_bytes(file.read(2), 'little')
        self.internal_file_attrs = file.read(2)
        self.external_file_attrs = file.read(4)
        self.local_header_relative_offset = int.from_bytes(file.read(4), 'little')
        self.file_name = file.read(self.file_name_length).decode(encoding)
        self.extra_field = file.read(self.extra_field_length)
        self.file_comment = file.read(self.file_comment_length).decode(encoding)


@dataclass
class CDEnd:
    """Contents of End of Central Directory.
    See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT for full documentation.
    """
    disk_num: int
    disk_num_CD: int
    total_entries: int
    total_CD_entries: int
    sizeof_CD: int
    offset: int
    comment_length: int
    comment: str

    def __init__(self, file: BinaryIO, encoding: str):
        self.disk_num = int.from_bytes(file.read(2), 'little')
        self.disk_num_CD = int.from_bytes(file.read(2), 'little')
        self.total_entries = int.from_bytes(file.read(2), 'little')
        self.total_CD_entries = int.from_bytes(file.read(2), 'little')
        self.sizeof_CD = int.from_bytes(file.read(4), 'little')
        self.offset = int.from_bytes(file.read(4), 'little')
        self.comment_length = int.from_bytes(file.read(2), 'little')
        self.comment = file.read(self.comment_length).decode(encoding)
