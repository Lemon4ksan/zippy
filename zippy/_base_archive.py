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

    def extract_all(self, path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.'):
        """Extract all files from the archive ещ given ``path``. If not specified, extracts files to current working directory."""
        for file in self.files:
            file.extract(path)
