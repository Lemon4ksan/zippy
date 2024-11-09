import xz
import bz2
import deflate
import zstandard
from typing import AnyStr

from .utils import pwexplode
from .utils import LZ77
from .utils import ZipEncrypt
from zippy.compressions import *
from zippy.exceptions import *

def decrypt(bit_flag: str, v: int, crc: int, pwd: str, contents: bytes) -> tuple[str, bytes]:
    """Decrypt ``contents``.
    Returns tuple with first element being encryption method and second being decrypted data.
    """

    if bit_flag[0] == '0':
        encryption_method = 'Unencrypted'
        return encryption_method, contents
    else:
        if not pwd:
            raise WrongPassword('Zip file requires password to be unpacked.')
        if not v >= 20:
            raise BadFile('Incorrect version specified.')
            # This should be implemented, but you will never see encrypted file before 2.0

        encryption_method = 'ZipCrypto'
        zd = ZipEncrypt.ZipDecrypter(pwd)
        decrypted_content = list(map(zd, contents))
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

def decompress(compression_method: int, uncompressed_size: int, contents: bytes) -> tuple[str, bytes]:
    """Decompress ``contents``.
    Returns tuple with first element being compression method and second being decompressed data.
    """

    # Note that values past 14 are ignored according to Info-ZIP note, 20040528.
    # They don't have practical application.
    if compression_method == 0:
        compression_method = 'Stored'
    elif compression_method in range(1, 6):
        raise NotImplementedError('Shrinking and Reducing are not implemented yet.')
    elif compression_method == 6:
        raise Deprecated('Legacy Implode is no longer supported. Use PKWARE Data Compression Library Imploding instead.')
    elif compression_method == 7:
        raise Deprecated('Tokenizing is not used by PKZIP.')
    elif compression_method == 8:
        compression_method = 'Deflate'
        contents = deflate.deflate_decompress(contents, uncompressed_size)
    elif compression_method == 9:
        compression_method = 'Deflate64'
        contents = deflate.deflate_decompress(contents, uncompressed_size)
    elif compression_method == 10:
        compression_method = 'PKWARE Data Compression Library Imploding'
        contents = pwexplode.explode(contents)  # Untested
    elif compression_method == 11:
        raise ReservedValue('Compression method 11 is reserved.')
    elif compression_method == 12:
        compression_method = 'BZIP2'
        contents = bz2.decompress(contents)
    elif compression_method == 13:
        raise ReservedValue('Compression method 13 is reserved.')
    elif compression_method == 14:
        # eos = bit_flag[-2]
        # compression_method = 'LZMA'
        # contents = lzma.decompress(contents, ???)  # Doesn't work for some reason.
        # Also don't know how to make it use EOS.
        raise NotImplementedError('LZMA compression is not implemented yet.')
    elif compression_method == 19:
        compression_method = 'LZ77'
        contents = LZ77.decompress(contents)  # Untested
    elif compression_method == 93:
        compression_method = 'Zstandart'
        contents = zstandard.decompress(contents)
    elif compression_method == 95:
        compression_method = 'XZ'
        contents = xz.decompress(contents)
    else:
        raise BadFile('Unknown file compression method.')

    return compression_method, contents

def compress(method: int, level: str, contents: AnyStr) -> bytes:
    """Compress ``contents``. Returns compressed data."""

    if method in (8, 9):
        if level == FAST:
            level = 3
        elif level == NORMAL:
            level = 6
        elif level == MAXIMUM:
            level = 12
        else:
            raise ValueError(f'Unknown compression level {level}.')
        contents = deflate.deflate_compress(contents, level)
    # elif compression_method == 10:
    #     compression_method = 'PKWARE Data Compression Library Imploding'
    #     contents = pwexplode.explode(contents)  # Untested
    elif method == 12:
        contents = bz2.compress(contents)
    # elif compression_method == 14:
        # eos = bit_flag[-2]
        # compression_method = 'LZMA'
        # contents = lzma.decompress(contents, ???)  # Doesn't work for some reason.
        # Also don't know how to make it to use EOS.
        # raise NotImplementedError('LZMA compression is not implemented yet.')
    # elif compression_method == 19:
    #     compression_method = 'LZ77'
    #     contents = LZ77.decompress(contents)  # Untested
    elif method == 93:
        contents = zstandard.decompress(contents)
    elif method == 95:
        contents = xz.decompress(contents)
    # elif compression_method == 98:
        # compression_method = 'PPMd'  # Docs says that only version I, Rev 1 of PPMd is supported
        # maybe that's the reason it doesn't work
        # contents = pyppmd.decompress(contents, mem_size=uncompressed_size)
        # raise NotImplementedError('PPMd compression is not implemented yet.')

    return contents
