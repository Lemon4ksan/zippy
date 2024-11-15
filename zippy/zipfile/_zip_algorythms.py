import xz
import bz2
import deflate
import zstandard
from os import urandom
from typing import Optional

from .utils import pwexplode
from .utils import LZ77 as LZ77_module
from .utils.ZipEncrypt import ZipDecrypter, ZipEncrypter
from ..compressions import *
from ..exceptions import *

def decrypt(bit_flag: str, v: int, crc: int, pwd: Optional[str], data: bytes) -> tuple[str, bytes]:
    """Decrypt ``data``.
    Returns tuple with first element being encryption method and second being decrypted data.
    """

    if bit_flag[0] == '0':
        encryption_method = 'Unencrypted'
        return encryption_method, data
    else:
        if not pwd:
            raise WrongPassword('Zip file requires password to be unpacked.')
        if not v >= 20:
            raise BadFile('Incorrect version specified.')
            # This should be implemented, but you will never see encrypted file before 2.0

        encryption_method = 'ZipCrypto'
        zd = ZipDecrypter(pwd)
        decrypted_content = list(map(zd, data))
        decryption_header = decrypted_content[:12]

        # Each encrypted file has an extra 12 bytes stored at the start
        # of the data area defining the encryption header for that file. The
        # encryption header is originally set to random values, and then
        # itself encrypted, using three, 32-bit keys.
        if int.from_bytes(decryption_header[-1], 'little') != crc.to_bytes(4, 'little')[-1]:
            # After the header is decrypted,  the last 1 or 2 bytes in Buffer
            # SHOULD be the high-order word/byte of the CRC for the file being
            # decrypted, stored in Intel low-byte/high-byte order.  Versions of
            # PKZIP prior to 2.0 used a 2 byte CRC check; a 1 byte CRC check is
            # used on versions after 2.0. This can be used to test if the password
            # supplied is correct or not.

            raise WrongPassword('Given password is incorrect.')

        return encryption_method, b"".join(decrypted_content[12:])

def encrypt(data: bytes, pwd: Optional[str], crc: int) -> bytes:
    """Encrypt ``data``. Returns encrypted data."""

    if not pwd:
        raise WrongPassword('Zip file requires password to be encrypted.')
    
    ze = ZipEncrypter(pwd)
    check_byte = crc.to_bytes(4, 'little')[-1]
    encryption_header = b"".join(map(ze, urandom(11) + check_byte.to_bytes(1, 'little')))
    return encryption_header + b"".join(map(ze, data))

def decompress(compression_method: int, uncompressed_size: int, data: bytes) -> tuple[str, bytes]:
    """Decompress ``contents``.
    Returns tuple with first element being compression method and second being decompressed data.
    """

    if compression_method == 0:
        method = 'Stored'
    elif compression_method in range(1, 6):
        raise NotImplementedError('Shrinking and Reducing are not implemented yet.')
    elif compression_method == 6:
        raise Deprecated('Legacy Implode is no longer supported. Use PKWARE Data Compression Library Imploding instead.')
    elif compression_method == 7:
        raise Deprecated('Tokenizing is not used by PKZIP.')
    elif compression_method == 8:
        method = 'Deflate'
        data = deflate.deflate_decompress(data, uncompressed_size)
    elif compression_method == 9:
        method = 'Deflate64'
        data = deflate.deflate_decompress(data, uncompressed_size)
    elif compression_method == 10:
        method = 'PKWARE Data Compression Library Imploding'
        data = pwexplode.explode(data)  # Untested
    elif compression_method == 11:
        raise ReservedValue('Compression method 11 is reserved.')
    elif compression_method == 12:
        method = 'BZIP2'
        data = bz2.decompress(data)
    elif compression_method == 13:
        raise ReservedValue('Compression method 13 is reserved.')
    elif compression_method == 14:
        method = 'LZMA'
        data = b''
    elif compression_method == 19:
        method = 'LZ77'
        data = LZ77_module.decompress(data)  # Untested
    elif compression_method == 93:
        method = 'Zstandart'
        data = zstandard.decompress(data)
    elif compression_method == 95:
        method = 'XZ'
        data = xz.decompress(data)
    else:
        raise BadFile('Unknown file compression method.')

    return method, data

def compress(method: int, level: str, data: bytes) -> bytes:
    """Compress ``data``. Returns compressed data."""
    
    if method in (8, 9):
        if level == FAST:
            level_value = 3
        elif level == NORMAL:
            level_value = 6
        elif level == MAXIMUM:
            level_value = 12
        else:
            raise ValueError(f'Unknown compression level {level}.')
        return deflate.deflate_compress(data, level_value)
    # elif compression_method == 10:
    #     compression_method = 'PKWARE Data Compression Library Imploding'
    #     contents = pwexplode.explode(contents)  # Untested
    elif method == 12:
        return bz2.compress(data)
    # elif compression_method == 14:
        # eos = bit_flag[-2]
        # compression_method = 'LZMA'
        # contents = lzma.decompress(contents, ???)  # Doesn't work for some reason.
        # Also don't know how to make it to use EOS.
        # raise NotImplementedError('LZMA compression is not implemented yet.')
    # elif method == 19:
    #     return LZ77_module.compress(data)  # Untested
    elif method == 93:
        return zstandard.compress(data)
    elif method == 95:
        return xz.compress(data)
    # elif compression_method == 98:
        # compression_method = 'PPMd'  # Docs says that only version I, Rev 1 of PPMd is supported
        # maybe that's the reason it doesn't work
        # contents = pyppmd.decompress(contents, mem_size=uncompressed_size)
        # raise NotImplementedError('PPMd compression is not implemented yet.')
    else:
        return data
