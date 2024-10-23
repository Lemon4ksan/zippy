from dataclasses import dataclass
from datetime import datetime
from os import PathLike, mkdir, path


@dataclass
class File:
    """Clean representation of the file.

    Attributes:
        file_name (:obj:`str`): Name of the file.
        is_dir (:obj:`bool`): True if file is a directory.
        version_needed_to_exctract (:obj:`int`): Minimal version of zip required to unpack.
        encryption_method (:obj:`str`): Name of the encryption method. Unencrypted if none.
        compression_method (:obj:`str`): Name of the compression method. Stored if none.
        last_mod_time (:class:`datetime`): Datetime of last modification of the file.
        crc (:obj:`int`): CRC of the file.
        compressed_size (:obj:`int`): Compressed size of the file.
        uncompressed_size (:obj:`int`): Uncompressed size of the file.
        contents (:obj:`bytes`): Undecoded contents of the file.
    """

    file_name: str
    is_dir: bool
    version_needed_to_exctract: int
    encryption_method: str
    compression_method: str
    last_mod_time: datetime
    crc: int
    compressed_size: int
    uncompressed_size: int
    contents: bytes
    comment: str = ''

    def extract(self, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', encoding: str = 'utf-8'):
        """Extract single file to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded using given ``encoding``, its byte representation will be extracted instead.
        """

        contents = self.peek(encoding, ignore_overflow=True)
        if not path.exists(__path):
            mkdir(__path)
        __path = path.join(__path, self.file_name.replace('/', '\\'))  # get final file path

        if path.exists(__path) and path.isdir(__path):
            # Folder already extracted
            return

        if not path.exists(__path) and self.is_dir:
            # Create folder
            mkdir(__path)
        elif isinstance(contents, str):
            # Otherwise, write to file
            with open(__path, 'w') as f:
                f.write(contents)
        else:
            with open(__path, 'wb') as f:
                f.write(contents)

    def peek(self, encoding: str = 'utf-8', ignore_overflow: bool = False, char_limit: int = 8191) -> str | bytes:
        """Decode file contents. If content couldn't be decoded using given
        ``encoding``, its byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds
        ``char_limit`` characters (bytes) will be partially shown.
        """

        if self.is_dir:
            return 'Folder'

        try:
            content = self.contents.decode(encoding)
        except ValueError:  # Decoding falied
            content = self.contents

        if len(content) > char_limit and not ignore_overflow:
            if isinstance(content, str):
                return content[:char_limit // 2] + ' |...| File too large to display'
            else:
                return content[:char_limit // 32] + b' |...| File too large to display'
        else:
            return content


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

    def extract_all(self, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.', encoding: str = 'utf-8'):
        """Extract all files from the archive to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded, its byte representation will be extracted instead.
        """
        for file in self.files:
            file.extract(__path, encoding)

    def peek_all(self, encoding: str = 'utf-8', ignore_overflow: bool = False, char_limit: int = 8191) -> list[tuple[str, str | bytes]]:
        """Decode files content. Returns a list of tuples, where first element is filename and second is its decoded content.
        If content could not be decoded, its byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit`` characters (bytes) will be partially shown.
        """
        files = []
        for file in self.files:
            if not file.is_dir:
                files.append((file.file_name, file.peek(encoding, ignore_overflow, char_limit)))
        return files
