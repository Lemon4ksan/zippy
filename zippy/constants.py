"""Constants with names of possible compressions. Only supported algorythms are available."""
from typing import Literal, TypeAlias

UNENCRYPTED: TypeAlias = Literal['Unencrypted']
ZIP_CRYPTO: TypeAlias = Literal['ZipCrypto']

STORED: TypeAlias = Literal['Stored']
DEFLATE: TypeAlias = Literal['Deflate']
DEFLATE64: TypeAlias = Literal['Deflate64']
PKWARE_IMPLODING: TypeAlias = Literal['PKWARE Imploding']
BZIP: TypeAlias = Literal['BZIP2']
LZ77: TypeAlias = Literal['LZ77']
ZSTANDART: TypeAlias = Literal['Zstandart']
XZ: TypeAlias = Literal['XZ']

FAST: TypeAlias = Literal['Fast']
NORMAL: TypeAlias = Literal['Normal']
MAXIMUM: TypeAlias = Literal['Maximum']

ZipCompressions: TypeAlias = Literal[STORED, DEFLATE, DEFLATE64, PKWARE_IMPLODING, BZIP, LZ77, ZSTANDART, XZ]
ZipEncryptions: TypeAlias = Literal[UNENCRYPTED, ZIP_CRYPTO]
ZipLevels: TypeAlias = Literal[FAST, NORMAL, MAXIMUM]

ZIP_COMPRESSION_FROM_STR: dict[ZipCompressions, int] = {
    'Stored': 0,
    'Deflate': 8,
    'Deflate64': 9,
    'PKWARE Imploding': 10,
    'BZIP2': 12,
    'LZ77': 19,
    'Zstandart': 93,
    'XZ': 95
}
