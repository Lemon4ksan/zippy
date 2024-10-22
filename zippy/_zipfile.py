from dataclasses import dataclass
from datetime import date, time, datetime
from typing import BinaryIO, Optional

import xz
import mp3
import bz2
# import lzma
# import pyppmd
import deflate
import zstandard

from .utils import pwexplode
from .utils import LZ77
from .utils import ZipEncrypt
from ._base_classes import File
from .exceptions import *

@dataclass
class FileRaw:
    """File extracted from archive. It's uncompressed, not decrypted (if it was)
     and contains data fields that user doesn't need."""

    version_needed_to_exctract: int
    bit_flag: bytes
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    file_name_length: int
    extra_field_length: int
    file_name: str
    extra_field: bytes
    contents: bytes

    @classmethod
    def __init_raw__(cls, file: BinaryIO, encoding: str):
        version = [byte for byte in file.read(2)]
        version_needed_to_exctract = version[0]
        if version[1] != 0:  # This byte is unused
            raise BadFile('Unknown version value')
        bit_flag = file.read(2)
        compression_method = int.from_bytes(file.read(2), 'little')
        last_mod_time = int.from_bytes(file.read(2), 'little')
        last_mod_date = int.from_bytes(file.read(2), 'little')
        crc = int.from_bytes(file.read(4), 'little')
        compressed_size = int.from_bytes(file.read(4), 'little')
        uncompressed_size = int.from_bytes(file.read(4), 'little')
        file_name_length = int.from_bytes(file.read(2), 'little')
        extra_field_length = int.from_bytes(file.read(2), 'little')
        file_name = file.read(file_name_length).decode(encoding)
        extra_field = file.read(extra_field_length)
        contents = file.read(compressed_size)

        return cls(
            version_needed_to_exctract,
            bit_flag,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_name,
            extra_field,
            contents
        )

    def decode(self, pwd: Optional[str]) -> File:
        
        bit_flag = "".join(format(bit, 'b') for bit in self.bit_flag)
        
        if bit_flag[0] == '0':
            encryption_method = 'Unencrypted'
        else:
            encryption_method = 'ZipCrypto'
            zd = ZipEncrypt.ZipDecrypter(pwd)
            decrypted_content = list(map(zd, self.contents))
            decryption_header = decrypted_content[:13]
            # Each encrypted file has an extra 12 bytes stored at the start
            # of the data area defining the encryption header for that file.  The
            # encryption header is originally set to random values, and then
            # itself encrypted, using three, 32-bit keys.
            if self.version_needed_to_exctract >= 20:
                if int.from_bytes(decryption_header[-2], 'little') != self.crc.to_bytes(4, 'little')[-1]:
                    # After the header is decrypted,  the last 1 or 2 bytes in Buffer
                    # SHOULD be the high-order word/byte of the CRC for the file being
                    # decrypted, stored in Intel low-byte/high-byte order.  Versions of
                    # PKZIP prior to 2.0 used a 2 byte CRC check; a 1 byte CRC check is
                    # used on versions after 2.0.  This can be used to test if the password
                    # supplied is correct or not.

                    # ^ This is a lie, we're comparing only second last decryption_header byte with last crc byte
                    raise WrongPassword('given password is incorrect.')

            self.contents = b"".join(decrypted_content[12:])

        if self.compression_method == 0:
            compression_method = 'Stored'
            contents = self.contents
        elif self.compression_method in range(1, 6):
            raise NotImplemented('Shrinking and Reducing are not implemented yet.')
        elif self.compression_method == 6:
            raise Deprecated('Legacy Implode is no longer supported. Use PKWARE Data Compression Library Imploding instead.')
        elif self.compression_method == 7:
            raise Deprecated('Tokenizing is not used by PKZIP.')
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
            raise ReservedValue('Compression method 11 is reserved.')
        elif self.compression_method == 12:
            compression_method = 'BZIP2'
            contents = bz2.decompress(self.contents)
        elif self.compression_method == 13:
            raise ReservedValue('Compression method 13 is reserved.')
        elif self.compression_method == 14:
            # eos = bit_flag[-2]
            # compression_method = 'LZMA'
            # contents = lzma.decompress(self.contents, ???)  # Doesn't work for some reason.
            # Also don't know how to make it to use EOS.
            raise NotImplementedError('LZMA compression is not implemented yet.')
        elif self.compression_method == 15:
            raise ReservedValue('Compression method 15 is reserved.')
        elif self.compression_method == 16:  # can't find this
            raise NotImplementedError('IBM z/OS CMPSC Compression is not implemented.')
        elif self.compression_method == 17:
            raise ReservedValue('Compression method 17 is reserved.')
        elif self.compression_method == 18:  # can't find this, somebody uses it?
            raise NotImplementedError('IBM TERSE is not implemented.')
        elif self.compression_method == 19:
            compression_method = 'LZ77'
            contents = LZ77.decompress(self.contents)  # Untested
        elif self.compression_method == 20:
            raise Deprecated('Method 20 is deprecated. Use Zstandart compression instead.')
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
            raise NotImplementedError('JPEG compression is not implemented yet.')
        elif self.compression_method == 97:
            raise NotImplementedError('WavPack compression is not implemented yet.')
        elif self.compression_method == 98:
            # compression_method = 'PPMd'  # Docs says that only version I, Rev 1 of PPMd is supported
            # maybe that's the reason it doesn't work
            # contents = pyppmd.decompress(self.contents, mem_size=self.uncompressed_size)
            raise NotImplementedError('PPMd compression is not implemented yet.')
        elif self.compression_method == 99:  # What is this??
            raise NotImplementedError('AE-x encryption marker is not implemented yet.')

        # This conversion is based on java8 source code.
        # Some precision is lost, but I can't find more appropriate method of doing this.
        try:
            last_mod_time = time((self.last_mod_time >> 11) & 0x1F, (self.last_mod_time >> 5) & 0x3F,
                                 ((self.last_mod_time << 1) & 0x3E) - 2)
            last_mod_date = date((self.last_mod_date >> 9) + 1980, (self.last_mod_date >> 5) & 0xF,
                                 self.last_mod_date & 0x1F)
        except ValueError:
            last_mod_time = last_mod_date = None

        return File(
            self.file_name,
            self.version_needed_to_exctract,
            encryption_method,
            compression_method,
            datetime.combine(last_mod_date, last_mod_time) if last_mod_time is not None else None,
            self.crc,
            self.compressed_size,
            self.uncompressed_size,
            contents
        )

    def encode(self, encoding: str) -> bytes:
        byte_str: bytes = b''
        byte_str += self.version_needed_to_exctract.to_bytes(2, 'little')
        byte_str += self.bit_flag
        byte_str += self.compression_method.to_bytes(2, 'little')
        byte_str += self.last_mod_time.to_bytes(2, 'little')
        byte_str += self.last_mod_date.to_bytes(2, 'little')
        byte_str += self.crc.to_bytes(4, 'little')
        byte_str += self.compressed_size.to_bytes(4, 'little')
        byte_str += self.uncompressed_size.to_bytes(4, 'little')
        byte_str += self.file_name_length.to_bytes(2, 'little')
        byte_str += self.extra_field_length.to_bytes(2, 'little')
        byte_str += self.file_name.encode(encoding)
        byte_str += self.extra_field
        byte_str += self.contents
        return byte_str


@dataclass
class CDHeader:
    """Contents of Central Directory Header.
    See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT for full documentation.
    """

    version_made_by: int
    version_needed_to_exctract: int
    bit_flag: bytes
    compression_method: int
    last_mod_time: int
    last_mod_date: int
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

    @classmethod
    def __init_raw__(cls, file: BinaryIO, encoding: str):
        version_made_by = int.from_bytes(file.read(2), 'little')
        version_needed_to_exctract = int.from_bytes(file.read(2), 'little')
        bit_flag = file.read(2)
        compression_method = int.from_bytes(file.read(2), 'little')
        last_mod_time = int.from_bytes(file.read(2), 'little')
        last_mod_date = int.from_bytes(file.read(2), 'little')
        crc = int.from_bytes(file.read(4), 'little')
        compressed_size = int.from_bytes(file.read(4), 'little')
        uncompressed_size = int.from_bytes(file.read(4), 'little')
        file_name_length = int.from_bytes(file.read(2), 'little')
        extra_field_length = int.from_bytes(file.read(2), 'little')
        file_comment_length = int.from_bytes(file.read(2), 'little')
        disk_number_start = int.from_bytes(file.read(2), 'little')
        internal_file_attrs = file.read(2)
        external_file_attrs = file.read(4)
        local_header_relative_offset = int.from_bytes(file.read(4), 'little')
        file_name = file.read(file_name_length).decode(encoding)
        extra_field = file.read(extra_field_length)
        file_comment = file.read(file_comment_length).decode(encoding)

        return cls(
            version_made_by,
            version_needed_to_exctract,
            bit_flag,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc,
            compressed_size,
            uncompressed_size,
            file_name_length,
            extra_field_length,
            file_comment_length,
            disk_number_start,
            internal_file_attrs,
            external_file_attrs,
            local_header_relative_offset,
            file_name,
            extra_field,
            file_comment
        )

    def encode(self, encoding: str) -> bytes:
        byte_str: bytes = b''
        byte_str += self.version_made_by.to_bytes(2, 'little')
        byte_str += self.version_needed_to_exctract.to_bytes(2, 'little')
        byte_str += self.bit_flag
        byte_str += self.compression_method.to_bytes(2, 'little')
        byte_str += self.last_mod_time.to_bytes(2, 'little')
        byte_str += self.last_mod_date.to_bytes(2, 'little')
        byte_str += self.crc.to_bytes(4, 'little')
        byte_str += self.compressed_size.to_bytes(4, 'little')
        byte_str += self.uncompressed_size.to_bytes(4, 'little')
        byte_str += self.file_name_length.to_bytes(2, 'little')
        byte_str += self.extra_field_length.to_bytes(2, 'little')
        byte_str += self.file_comment_length.to_bytes(2, 'little')
        byte_str += self.disk_number_start.to_bytes(2, 'little')
        byte_str += self.internal_file_attrs
        byte_str += self.external_file_attrs
        byte_str += self.local_header_relative_offset.to_bytes(4, 'little')
        byte_str += self.file_name.encode(encoding)
        byte_str += self.extra_field
        byte_str += self.file_comment.encode(encoding)
        return byte_str

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

    @classmethod
    def __init_raw__(cls, file: BinaryIO, encoding: str):
        disk_num = int.from_bytes(file.read(2), 'little')
        disk_num_CD = int.from_bytes(file.read(2), 'little')
        total_entries = int.from_bytes(file.read(2), 'little')
        total_CD_entries = int.from_bytes(file.read(2), 'little')
        sizeof_CD = int.from_bytes(file.read(4), 'little')
        offset = int.from_bytes(file.read(4), 'little')
        comment_length = int.from_bytes(file.read(2), 'little')
        comment = file.read(comment_length).decode(encoding)

        return cls(
            disk_num,
            disk_num_CD,
            total_entries,
            total_CD_entries,
            sizeof_CD,
            offset,
            comment_length,
            comment
        )

    def encode(self, encoding: str) -> bytes:
        byte_str: bytes = b''
        byte_str += self.disk_num.to_bytes(2, 'little')
        byte_str += self.disk_num_CD.to_bytes(2, 'little')
        byte_str += self.total_entries.to_bytes(2, 'little')
        byte_str += self.total_CD_entries.to_bytes(2, 'little')
        byte_str += self.sizeof_CD.to_bytes(4, 'little')
        byte_str += self.offset.to_bytes(4, 'little')
        byte_str += self.comment_length.to_bytes(2, 'little')
        byte_str += self.comment.encode(encoding)
        return byte_str
