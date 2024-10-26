"""Constants with names of possible compressions. Only supported algorythms are available."""

STORED: str = 'Stored'
DEFLATE: str = 'Deflate'
DEFLATE64: str = 'Deflate64'
PKWARE_IMPLODING: str = 'PKWARE Data Compression Library Imploding'
BZIP: str = 'BZIP2'
LZ77: str = 'LZ77'
ZSTANDART: str = 'Zstandart'
XZ: str = 'XZ'

COMPRESSION_FROM_STR: dict[str, int] = {
    STORED: 0,
    DEFLATE: 8,
    DEFLATE64: 9,
    PKWARE_IMPLODING: 10,
    BZIP: 12,
    LZ77: 19,
    ZSTANDART: 93,
    XZ: 95
}

# Compression levels
FAST = 'Fast'
NORMAL = 'Normal'
MAXIMUM = 'Maximum'
