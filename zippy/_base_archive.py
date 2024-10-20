from ._dataclasses import File
from os import PathLike


class Archive:
    """Base class for all archives"""

    def __init__(
            self,
            files: list[File],
            comment: str,
            total_entries: int
    ):
        self.files: list[File] = files
        self.comment: str = comment
        self.total_entries: int = total_entries

        compression_method = files[0].compression_method
        for file in files:
            if compression_method != file.compression_method and file.file_name[-1] != '/':
                # Folders are always stored so we don't count them
                self.compression_method = 'Mixed'
                break
        else:
            self.compression_method = compression_method

    def extract_all(self, path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', encoding: str = 'utf-8'):
        """Extract all files from the archive to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded, its byte representation will be extracted instead.
        """
        for file in self.files:
            file.extract(path, encoding)

    def peek_all(self, encoding: str = 'utf-8', ignore_overflow: bool = False, char_limit: int = 8191) -> list[tuple[str, str | bytes]]:
        """Decode files content. Returns a list of tuples, where first element is filename and second is its decoded content.
        If content could not be decoded, its byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit`` characters (bytes) will be partially shown.
        """
        files = []
        for file in self.files:
            if file.file_name[-1] != '/':
                files.append((file.file_name, file.peek(encoding, ignore_overflow, char_limit)))
        return files
