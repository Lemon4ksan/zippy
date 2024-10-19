from ._dataclasses import File, FileRaw, CDHeader, CDEnd
from ._base_archive import Archive
from typing import BinaryIO, Optional, Self
from os import PathLike

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
            f: str | PathLike[str] | PathLike[bytes] | BinaryIO,
            pwd: Optional[str] = None,
            encoding: str = 'utf-8'
    ) -> 'ZipFile':
        """Open zip file and return its representation.

        ``f`` must be a filename, pathlike string or a binary data stream.

        If file contents couldn't be decoded, initial stream of bytes will be used.

        Raises Exception if target file is damaged (either crc or number of file entries doesn't match)
        and inbuild open function exceptions.
        """

        files: list[File] = []
        CD_headers: list[CDHeader] = []
        indirect: bool = False  # Binary stream is already initialised

        if isinstance(f, str) or isinstance(f, PathLike):
            f: BinaryIO = open(f, 'rb')
            indirect = True
        elif not isinstance(f, BinaryIO):
            raise TypeError(f'expected str, bytes or os.PathLike object, not {type(f).__name__}.')

        try:
            signature = f.read(4)
            if signature == b'PK\x03\x04':  # First check
                raw_file = FileRaw(f, encoding)
                files.append(raw_file.decode(pwd, encoding))
            else:
                raise Exception('file should be in .ZIP format.')

            while True:
                signature = f.read(4)
                if signature == b'PK\x03\x04':  # Getting file headers
                    raw_file = FileRaw(f, encoding)
                    files.append(raw_file.decode(pwd, encoding))
                elif signature == b'PK\x01\x02':  # Getting central directory headers of fieles
                    header = CDHeader(f, encoding)
                    CD_headers.append(header)
                elif signature == b'PK\x05\06':  # End of centeral directory (stop reading)
                    endof_cd = CDEnd(f, encoding)
                else:
                    # print(signature)
                    break
        finally:
            if indirect:
                f.close()

        # Making sure zip file is not damaged
        for file, header in zip(files, CD_headers):
            if file.crc != header.crc:
                raise Exception('file is corrupted or damaged.')

        return ZipFile(files, CD_headers, endof_cd)

