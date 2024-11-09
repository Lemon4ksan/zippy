from dataclasses import dataclass
from datetime import date, time, datetime
from typing import BinaryIO, Optional

from .._base_classes import File
from ..compressions import *
from ..exceptions import *
from ._zip_algorythms import decrypt, decompress

@dataclass
class FileRaw:
    """Raw file representation. It's uncompressed, not decrypted (if it was)
     and contains data fields that user doesn't need."""

    version_needed_to_exctract: int
    bit_flag: str
    compression_method: int
    last_mod_time: bytes
    last_mod_date: bytes
    crc: int
    compressed_size: int
    uncompressed_size: int
    filename_length: int
    extra_field_length: int
    filename: str
    extra_field: bytes
    contents: bytes

    @classmethod
    def __init_raw__(cls, file: BinaryIO, encoding: str):
        version: list[int] = [byte for byte in file.read(2)]
        version_needed_to_exctract: int = version[0]
        if version[1] != 0:  # This byte is unused
            raise BadFile('Unknown version value')
        bit_flag: str = "".join("".join(format(bit, '0>8b')[::-1]) for bit in file.read(2))
        compression_method: int = int.from_bytes(file.read(2), 'little')
        last_mod_time: bytes = file.read(2)
        last_mod_date: bytes = file.read(2)
        crc: int = int.from_bytes(file.read(4), 'little')
        compressed_size: int = int.from_bytes(file.read(4), 'little')
        uncompressed_size: int = int.from_bytes(file.read(4), 'little')
        filename_length: int = int.from_bytes(file.read(2), 'little')
        extra_field_length: int = int.from_bytes(file.read(2), 'little')
        filename: str = file.read(filename_length).decode(encoding)
        extra_field: bytes = file.read(extra_field_length)
        if compressed_size == 4_294_967_295 and extra_field[:2] == b'\x01\x00':  # zip64
            uncompressed_size = int.from_bytes(extra_field[4:12], 'little')
            compressed_size = int.from_bytes(extra_field[12:20], 'little')
        contents: bytes = file.read(compressed_size)

        if bit_flag[3] == '1':
            _s: bytes = file.read(4)
            if _s == b'PK\x07\x08':  # This signature is unofficial
                _s = file.read(4)
            crc = int.from_bytes(_s, 'little')
            compressed_size = int.from_bytes(file.read(4), 'little')
            uncompressed_size = int.from_bytes(file.read(4), 'little')
        if bit_flag[13] == '1':
            raise NotImplementedError('Central Directory decryption is not implemented yet.')

        return cls(
            version_needed_to_exctract,
            bit_flag,
            compression_method,
            last_mod_time,
            last_mod_date,
            crc,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_field_length,
            filename,
            extra_field,
            contents
        )

    def decode(self, pwd: Optional[str]) -> File:
        
        encryption_method, contents = decrypt(
            self.bit_flag, self.version_needed_to_exctract, self.crc, pwd, self.contents
        )
    
        compression_method, contents = decompress(self.compression_method, self.uncompressed_size, contents)

        last_mod_date = int.from_bytes(self.last_mod_date, 'little')
        last_mod_time = int.from_bytes(self.last_mod_time, 'little')

        # This conversion is based on java8 source code.
        try:
            decoded_last_mod_time = time((last_mod_time >> 11) & 0x1F, (last_mod_time >> 5) & 0x3F,
                                 (last_mod_time << 1) & 0x3E)
            decoded_last_mod_date = date((last_mod_date >> 9) + 1980, (last_mod_date >> 5) & 0xF,
                                 last_mod_date & 0x1F)
            final_last_mod_time = datetime.combine(decoded_last_mod_date, decoded_last_mod_time)
        except ValueError:
            final_last_mod_time = None

        if compression_method in (DEFLATE, DEFLATE64):
            match self.bit_flag[1:3]:
                case '00':
                    compression_level = NORMAL
                case '10':
                    compression_level = MAXIMUM
                case '01':
                    compression_level = FAST
                case '11':
                    compression_level = FAST
        else:
            compression_level = NORMAL

        return File(
            self.filename,
            self.filename[-1] == '/',
            self.version_needed_to_exctract,
            encryption_method,
            compression_method,
            compression_level,
            final_last_mod_time,
            self.crc,
            self.compressed_size,
            self.uncompressed_size,
            contents
        )

    def encode(self, encoding: str) -> bytes:
        byte_str: bytes = b''
        byte_str += self.version_needed_to_exctract.to_bytes(2, 'little')
        byte_str += int(self.bit_flag[::-1], 2).to_bytes(2, 'little')
        byte_str += self.compression_method.to_bytes(2, 'little')
        byte_str += self.last_mod_time
        byte_str += self.last_mod_date
        byte_str += self.crc.to_bytes(4, 'little')
        byte_str += self.compressed_size.to_bytes(4, 'little')
        byte_str += self.uncompressed_size.to_bytes(4, 'little')
        byte_str += self.filename_length.to_bytes(2, 'little')
        byte_str += self.extra_field_length.to_bytes(2, 'little')
        byte_str += self.filename.encode(encoding)
        byte_str += self.extra_field
        byte_str += self.contents
        return byte_str


@dataclass
class CDHeader:
    """Contents of Central Directory Header.
    See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT for full documentation.
    """

    version_made_by: int
    platform: int
    version_needed_to_exctract: int
    bit_flag: str
    compression_method: int
    last_mod_time: bytes
    last_mod_date: bytes
    crc: int
    compressed_size: int
    uncompressed_size: int
    filename_length: int
    extra_field_length: int
    comment_length: int
    disk_number_start: int
    internal_file_attrs: bytes
    external_file_attrs: bytes
    local_header_relative_offset: int
    filename: str
    extra_field: bytes
    comment: str

    @classmethod
    def __init_raw__(cls, file: BinaryIO, encoding: str):
        version_made_by = int.from_bytes(file.read(1), 'little')
        platform = int.from_bytes(file.read(1), 'little')
        version_needed_to_exctract = int.from_bytes(file.read(2), 'little')
        bit_flag = "".join("".join(format(bit, '0>8b')[::-1]) for bit in file.read(2))
        compression_method = int.from_bytes(file.read(2), 'little')
        last_mod_time = file.read(2)
        last_mod_date = file.read(2)
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
        filename = file.read(file_name_length).decode(encoding)
        extra_field = file.read(extra_field_length)
        if compressed_size == 4_294_967_295 and extra_field[:2] == b'\x01\x00':  # zip64
            uncompressed_size = int.from_bytes(extra_field[4:12], 'little')
            compressed_size = int.from_bytes(extra_field[12:20], 'little')
        file_comment = file.read(file_comment_length).decode(encoding)

        return cls(
            version_made_by,
            platform,
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
            filename,
            extra_field,
            file_comment
        )

    def encode(self, encoding: str) -> bytes:
        byte_str: bytes = b''
        byte_str += self.version_made_by.to_bytes(1, 'little')
        byte_str += self.platform.to_bytes(1, 'little')
        byte_str += self.version_needed_to_exctract.to_bytes(2, 'little')
        byte_str += int(self.bit_flag[::-1], 2).to_bytes(2, 'little')
        byte_str += self.compression_method.to_bytes(2, 'little')
        byte_str += self.last_mod_time
        byte_str += self.last_mod_date
        byte_str += self.crc.to_bytes(4, 'little')
        byte_str += self.compressed_size.to_bytes(4, 'little')
        byte_str += self.uncompressed_size.to_bytes(4, 'little')
        byte_str += self.filename_length.to_bytes(2, 'little')
        byte_str += self.extra_field_length.to_bytes(2, 'little')
        byte_str += self.comment_length.to_bytes(2, 'little')
        byte_str += self.disk_number_start.to_bytes(2, 'little')
        byte_str += self.internal_file_attrs
        byte_str += self.external_file_attrs
        byte_str += self.local_header_relative_offset.to_bytes(4, 'little')
        byte_str += self.filename.encode(encoding)
        byte_str += self.extra_field
        byte_str += self.comment.encode(encoding)
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
