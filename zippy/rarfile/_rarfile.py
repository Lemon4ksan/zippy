from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO, Optional

from .._base_classes import File
from ..exceptions import BadFile

def u_LEB128(r: BinaryIO) -> int:
    """Decode the unsigned leb128 encoded bytes from a reader."""
    a = bytearray()
    while True:
        b = r.read(1)
        if len(b) != 1:
            raise EOFError
        b = ord(b)
        a.append(b)
        if (b & 0x80) == 0:
            break
    
    def decode(b: bytearray) -> int:
        """Decode the unsigned leb128 encoded bytearray."""
        r = 0
        for i, e in enumerate(b):
            r += (e & 0x7f) << (i * 7)
        return r
    return decode(a)

@dataclass
class MainHeader:
    h_flags: int
    a_flags: int
    volume_number: Optional[int]
    extra_area: Optional[bytes]

    @staticmethod
    def __init_raw__(f: BinaryIO) -> 'MainHeader':
        """Initialise from a stream."""
        h_flags = u_LEB128(f)
        if h_flags & 0x0001:
            extra_area_size = u_LEB128(f)
        else:
            extra_area_size = None
        a_flags = u_LEB128(f)
        if a_flags & 0x0002:
            volume_number = u_LEB128(f)
        else:
            volume_number = None
        if extra_area_size:
            extra_area = f.read(extra_area_size)
        else:
            extra_area = None
        
        return MainHeader(
            h_flags,
            a_flags,
            volume_number,
            extra_area
        )

@dataclass
class FileHeader:
    h_flags: int
    f_flags: int
    compressed_size: int
    attributes: int
    cmp_information: int
    host_os: int
    filename_length: int
    filename: str
    extra_area_size: Optional[int]
    extra_area: Optional[bytes]
    data_size: Optional[int]
    data_crc32: Optional[int]
    data: Optional[bytes]
    mtime: Optional[int]
    
    @staticmethod
    def __init_raw__(f: BinaryIO) -> 'FileHeader':
        """Initialise from a stream."""
        h_flags: int = u_LEB128(f)
        if h_flags & 0x0001:
            extra_area_size: Optional[int] = u_LEB128(f)
        else:
            extra_area_size = None
        if h_flags & 0x0002:
            data_size: Optional[int] = u_LEB128(f)
        else:
            data_size = None
        f_flags: int = u_LEB128(f)
        compressed_size: int = u_LEB128(f)
        attributes: int = u_LEB128(f)
        if f_flags & 0x0002:
            mtime: Optional[int] = int.from_bytes(f.read(4), 'little')
        else:
            mtime = None
        if f_flags & 0x0004:
            data_crc32: Optional[int] = int.from_bytes(f.read(4), 'little')
        else:
            data_crc32 = None
        cmp_information: int = u_LEB128(f)
        host_os: int = u_LEB128(f)
        name_length: int = u_LEB128(f)
        name: str = f.read(name_length).decode('utf-8')
        if extra_area_size is not None:
            extra_area: Optional[bytes] = f.read(extra_area_size)
        else:
            extra_area = None
        if data_size is not None:
            data: Optional[bytes] = f.read(data_size)
        else:
            data = None
        
        return FileHeader(
            h_flags,
            f_flags,
            compressed_size,
            attributes,
            cmp_information,
            host_os,
            name_length,
            name,
            extra_area_size,
            extra_area,
            data_size,
            data_crc32,
            data,
            mtime
        )
    
    def decode(self):
        
        if self.filename is None or self.data_crc32 is None or self.data_size is None or self.compressed_size is None or self.data is None:
            raise BadFile("One of key attributes of decoding is not present.")
        
        if self.mtime is not None:
            mtime = datetime.fromtimestamp(self.mtime)
        else:
            mtime = None
        
        return File(
            filename=self.filename,
            is_dir=False,
            encryption_method='Unencrypted',
            compression_method='RAR',
            compression_level='Normal',
            last_mod_time=mtime,
            crc=self.data_crc32,
            compressed_size=self.data_size,
            uncompressed_size=self.compressed_size,
            contents=self.data,
            specifications={'host_os': self.host_os, 'cmp_information': self.cmp_information}
        )

@dataclass
class ServiceHeader:
    h_flags: int
    f_flags: int
    unpacked_size: int
    attributes: int
    cmp_information: int
    host_os: int
    name_length: int
    name: str
    extra_area_size: Optional[int]
    extra_area: Optional[bytes]
    data_size: Optional[int]
    data_crc32: Optional[int]
    data: Optional[bytes]
    mtime: Optional[int]
    
    @staticmethod
    def __init_raw__(f: BinaryIO) -> 'ServiceHeader':
        """Initialise from a stream."""
        h_flags: int = u_LEB128(f)
        if h_flags & 0x0001:
            extra_area_size: Optional[int] = u_LEB128(f)
        else:
            extra_area_size = None
        if h_flags & 0x0002:
            data_size: Optional[int] = u_LEB128(f)
        else:
            data_size = None
        f_flags: int = u_LEB128(f)
        unpacked_size: int = u_LEB128(f)
        attributes: int = u_LEB128(f)
        if f_flags & 0x0002:
            mtime: Optional[int] = int.from_bytes(f.read(4), 'little')
        else:
            mtime = None
        if f_flags & 0x0004:
            data_crc32: Optional[int] = int.from_bytes(f.read(4), 'little')
        else:
            data_crc32 = None
        cmp_information: int = u_LEB128(f)
        host_os: int = u_LEB128(f)
        name_length: int = u_LEB128(f)
        name: str = f.read(name_length).decode('utf-8')
        if extra_area_size is not None:
            extra_area: Optional[bytes] = f.read(extra_area_size)
        else:
            extra_area = None
        if data_size is not None:
            data: Optional[bytes] = f.read(data_size)
        else:
            data = None
        
        return ServiceHeader(
            h_flags,
            f_flags,
            unpacked_size,
            attributes,
            cmp_information,
            host_os,
            name_length,
            name,
            extra_area_size,
            extra_area,
            data_size,
            data_crc32,
            data,
            mtime
        )

@dataclass
class EOAHeader:
    h_flags: int
    EOA_flags: int

    @staticmethod
    def __init_raw__(f: BinaryIO):
        """Initialise from a stream."""
        h_flags: int = u_LEB128(f)
        EOA_flags: int = u_LEB128(f)
        
        return EOAHeader(h_flags, EOA_flags)