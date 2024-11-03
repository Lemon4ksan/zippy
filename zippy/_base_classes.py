from dataclasses import dataclass
from datetime import datetime
from os import PathLike, mkdir, path
from abc import abstractmethod, ABCMeta
from typing import Optional, Any, TextIO, BinaryIO


@dataclass
class File:
    """Final representation of the file.

    Attributes:
        file_name (:obj:`str`): Name of the file.
        is_dir (:obj:`bool`): True if file is a directory.
        version_needed_to_exctract (:obj:`int`): Minimal version of zip required to unpack.
        encryption_method (:obj:`str`): Name of the encryption method. Unencrypted if none.
        compression_method (:obj:`str`): Name of the compression method. Stored if none.
        last_mod_time (:class:`datetime`, optional): Datetime of last modification of the file.
            None if time is not specified.
        crc (:obj:`int`): CRC of the file.
        compressed_size (:obj:`int`): Compressed size of the file.
        uncompressed_size (:obj:`int`): Uncompressed size of the file.
        contents (:obj:`bytes`): Undecoded contents of the file.
        specifications (:obj:`list`[:obj:`Any`]`, optional): Miscelenious information about the
            file that may vary based on archive's structure.
    """

    file_name: str
    is_dir: bool
    version_needed_to_exctract: int
    encryption_method: str
    compression_method: str
    last_mod_time: Optional[datetime]
    crc: int
    compressed_size: int
    uncompressed_size: int
    contents: bytes
    comment: str = ''
    specifications: Optional[list[Any]] = None

    def extract(
            self,
            __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.',
            encoding: str = 'utf-8'
    ) -> None:
        """Extract single file to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded using given ``encoding``, its byte representation will be extracted instead.
        """

        contents = self.peek(encoding, ignore_overflow=True)
        if not path.exists(__path):
            mkdir(__path)
        __path = path.join(__path, self.file_name.replace('/', '\\'))  # get final file path

        if path.exists(__path) and self.is_dir:
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

    def peek(self, encoding: str = 'utf-8', ignore_overflow: bool = True, char_limit: int = 8191) -> str | bytes:
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


class NewArchive:
    """Abstract class with methods that should be implemented in any archive type."""

    @abstractmethod
    def get_structure(self, fp: str | PathLike[str] = '.') -> list[str]:
        """Get structure of the archive. If ``fp`` is specified, returns the structure of given folder."""
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def add_file(
            self,
            fn: str,
            fd: str | bytes | PathLike[str] | PathLike[bytes] | TextIO | BinaryIO,
            fp: str | PathLike[str] = '.',
            compression: str = 'AnyStr',
            level: str = 'AnyStr',
            *,
            last_mod_time: Optional[datetime] = None,
            encoding: str = 'utf-8'
    ) -> None:
        """Add file to archive.

        ``fn`` is filename inside archive.

        ``fd`` is file's data. It can be string, bytes object, os.PathLike, text or binary stream.
        If it's os.PathLike, contents of the file path is leading to will be used.

        ``fp`` is file's path inside archive. '.' represents root. Every path should start from root.

        ``encoding`` is encoding in wich file's data will be encoded.

        If ``last_mod_date`` is not provided and fd is not os.PathLike, current time will be used instead.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def edit_file(
            self,
            fn: str,
            fd: str | bytes | TextIO | BinaryIO,
            fp: str | PathLike[str] = '.'
    ) -> None:
        """Edit file inside archive.

        ``fn`` is filename to be edited.

        ``fd`` is filedata that will replace previous one.

        ``fp`` is path to the folder in which target file is located.
        '.' represents root. Every path should start from root.

        Raises FileNotFound exception if file is not present at given path.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def remove_file(self, fn: str, fp: str | PathLike[str] = '.') -> None:
        """Remove file inside archive.

        ``fn`` is filename to be deleted.

        ``fp`` is path to the folder in which target file is located.
        '.' represents root. Every path should start from root.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def create_folder(self, fp: str | PathLike[str] = '.') -> str:
        """Create folder inside archive.

        ``fp`` is folder's path. '.' represents root. Every path should start from root.

        Returns string representing final path. Used to add new files to the folder.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def add_folder(self, fd: str | PathLike[str], fp: str | PathLike[str] = '.') -> None:
        """Add folder from disk to the archive.

        ``fd`` is path to the file that will be added. It can be both absolute and relative.

        ``fp`` is file's path inside archive. '.' represents root. Every path should start from root.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def remove_folder(self, fp: str | PathLike[str] = '.') -> list[str]:
        """Remove folder and its contents.

        ``fp`` is path to the target folder. '.' represents root. Every path should start from root.

        Returns list of paths of deleted files and folders.
        """
        raise NotImplementedError('This method should be implemented in the child class.')

    @abstractmethod
    def save(
            self,
            fn: str,
            fp: int | str | bytes | PathLike[str] | PathLike[bytes] = '.',
            comment: str = ''
    ) -> None:
        """Save new archive file with name ``fn`` at given ``fp``.

        Additional ``comment`` can be applied to the file.
        """
        raise NotImplementedError('This method should be implemented in the child class.')


class Archive:
    """Base class for all archives"""

    def __init__(
            self,
            files: list[File],
            comment: str,
            total_entries: int,
            encoding: str
    ):
        self.files: list[File] = files
        self.comment: str = comment
        self.total_entries: int = total_entries
        self.encoding: str = encoding

        compression_method = files[0].compression_method
        for file in files:
            if compression_method != file.compression_method and file.file_name[-1] != '/':
                # Folders are always stored so we don't count them
                self.compression_method = 'Mixed'
                break
        else:
            self.compression_method = compression_method

    def extract_all(
            self,
            __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.',
            encoding: str = 'utf-8'
    ) -> None:
        """Extract all files from the archive to given ``path``. If not specified, extracts to current working directory.
        If file couldn't be decoded, its byte representation will be extracted instead.
        """
        for file in self.files:
            file.extract(__path, encoding)

    def peek_all(
            self,
            encoding: str = 'utf-8',
            ignore_overflow: bool = True,
            char_limit: int = 8191
    ) -> list[tuple[str, str | bytes]]:
        """Decode files content. Returns a list of tuples, where first element is filename and
        second is its decoded content. If content could not be decoded, its byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit``
        characters (bytes) will be partially shown.
        """
        files = []
        for file in self.files:
            if not file.is_dir:
                files.append((file.file_name, file.peek(encoding, ignore_overflow, char_limit)))
        return files
