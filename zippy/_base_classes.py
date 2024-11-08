from dataclasses import dataclass
from datetime import datetime
from os import PathLike, mkdir, path
from abc import abstractmethod, ABCMeta
from typing import Optional, Any, TextIO, BinaryIO, Self


@dataclass
class File:
    """Final representation of the file.

    Attributes:
        file_name (:obj:`str`): Name of the file.
        is_dir (:obj:`bool`): True if file is a directory.
        version_needed_to_exctract (:obj:`int`): Minimal version of zip required to unpack.
        encryption_method (:obj:`str`): Name of the encryption method. 'Unencrypted' if none.
        compression_method (:obj:`str`): Name of the compression method. 'Stored' if none.
        compression_level (:obj:`str`, optional): Level of compression.
        last_mod_time (:class:`datetime`, optional): Datetime of last modification of the file.
            None if time is not specified.
        crc (:obj:`int`): CRC of the file.
        compressed_size (:obj:`int`): Compressed size of the file.
        uncompressed_size (:obj:`int`): Uncompressed size of the file.
        contents (:obj:`bytes`): Undecoded content of the file.
        specifications (:obj:`list`[:obj:`Any`]`, optional): Miscelenious information about the
            file that may vary based on archive's structure.
    """

    file_name: str
    is_dir: bool
    version_needed_to_exctract: int
    encryption_method: str
    compression_method: str
    compression_level: Optional[str]
    last_mod_time: Optional[datetime]
    crc: int
    compressed_size: int
    uncompressed_size: int
    contents: bytes
    comment: str = ''
    specifications: Optional[list[Any]] = None

    def extract(self, __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.') -> None:
        """Extract single file to given ``path``. If not specified, extracts to current working directory."""

        if not path.exists(__path):
            # Folder to extract
            mkdir(__path)
        __path = path.join(__path, self.file_name.replace('/', '\\'))  # get final file path

        if path.exists(__path) and self.is_dir:
            # Folder already extracted
            return
        elif not path.exists(__path) and self.is_dir:
            # Create folder
            mkdir(__path)
        else:
            # Write to file
            with open(__path, 'wb') as f:
                f.write(self.contents)

    def peek(self, encoding: str = 'utf-8', ignore_overflow: bool = True, char_limit: int = 8191) -> str | bytes:
        """Decode file content. If decoding with given ``encoding`` failed, byte representation will be used instead.

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


class NewArchive(metaclass=ABCMeta):
    """Class with methods that should be implemented in any new archive."""

    def __init__(
            self,
            pwd: Optional[str],
            encoding: str,
            encryption: str
    ):
        self._pwd: Optional[str] = pwd
        self._encoding: str = encoding
        self._encryption: str = encryption

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @property
    def pwd(self):
        return self._pwd

    @property
    def encoding(self):
        return self._encoding

    @property
    def encryption(self):
        return self._encryption

    @abstractmethod
    def add_file(
            self,
            fn: str,
            fd: str | bytes | PathLike[str] | PathLike[bytes] | TextIO | BinaryIO,
            fp: str | PathLike[str] = '.',
            compression: str = 'AnyStr',
            level: str = 'AnyStr',
            encoding: str = 'utf-8'
    ) -> None:
        """Add file with name ``fn`` and data ``fd`` to archive in ``fp`` directory.

        ``fd`` can be string, bytes object, os.PathLike, text or binary stream.
        If it's os.PathLike, contents of the file path is leading to will be used.
        If it's text stream, content will be encoded with given ``encoding``.

        ``fp`` must start from '.' (root).

        ``level`` is only used for Deflate and Deflate64 compression.
        """

    @abstractmethod
    def edit_file(
            self,
            fn: str,
            fp: str | PathLike[str],
            fd: str | bytes | TextIO | BinaryIO
    ) -> None:
        """Edit file with name ``fn`` inside archive in ``fp`` directory with new ``fd`` data.

        ``fp`` must start from '.' (root).

        Raises FileNotFound exception if file is not present at given path.
        """

    @abstractmethod
    def remove_file(self, fn: str, fp: str | PathLike[str]) -> None:
        """Remove file with name ``fn`` in ``fp`` directory.

        ``fp`` must start from '.' (root).
        """

    @abstractmethod
    def create_folder(self, fn: str, fp: str | PathLike[str] = '.') -> str:
        """Create folder ``fn`` inside archive in ``fp`` directory.

        ``fn`` can also be a full path of new directory (``fp`` must be default).

        ``fp`` should start from '.' (root).

        Returns string representing final path. Used to add new files to the folder.
        """

    @abstractmethod
    def add_folder(self, fd: str | PathLike[str], fp: str | PathLike[str] = '.', use_mp: bool = True) -> None:
        """Add folder from disk at ``fd`` directory to the archive in ``fp`` folder.

        ``fd`` path can be both absolute and relative.

        ``fp`` should start from '.' (root).

        If ``use_mp`` is True, all CPU cores will be used to add large amount of files faster.
        Note that to use this, you must use main idiom.
        """

    @abstractmethod
    def remove_folder(self, fn: str, fp: str | PathLike[str] = '.') -> list[str]:
        """Remove folder with name ``fn`` in ``fp`` directory and its content.

        ``fn`` can also be a full path to the folder that will be removed (``fp`` must be default).

        ``fp`` should start from '.' (root).

        Returns list of paths of deleted files and folders.
        """

    @abstractmethod
    def get_structure(self, fp: str | PathLike[str] = '.') -> list[str]:
        """Get structure of the archive. If ``fp`` is specified, returns the structure of given folder."""

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

    @abstractmethod
    def _mp_add_file(
            self,
            fn: str,
            fd: str | bytes | PathLike[str] | PathLike[bytes] | TextIO | BinaryIO,
            fp: str | PathLike[str],
            platform: int,
            extra_field: bytes
    ) -> tuple[dict, dict, int]:
        """Multiprocessing backstage of ``add_file`` method."""


class Archive(metaclass=ABCMeta):
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

        compression_method: str = files[0].compression_method
        for file in files:
            if compression_method != file.compression_method and file.file_name[-1] != '/':
                # Folders are always stored so we don't count them
                self.compression_method = 'Mixed'
                break
        else:
            self.compression_method = compression_method

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @staticmethod
    @abstractmethod
    def open(
            f: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            pwd: Optional[str] = None,
            encoding: str = 'utf-8'
    ) -> 'Archive':
        """Open archive and return its representation.

        ``f`` must be a filename, pathlike string or a binary data stream.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding to extract files.

        Raises BadFile exception if target file is damaged.
        """

    @staticmethod
    @abstractmethod
    def new(pwd: Optional[str] = None, encryption: str = 'Unencrypted', encoding: str = 'utf-8') -> NewArchive:
        """Return new editable archive class with given ``password`` and ``encryption``.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding on files.
        It is also reccomended not to mix different encodings.
        """

    @abstractmethod
    def edit(self, pwd: str, encryption: str = 'Unencrypted') -> NewArchive:
        """Return new editable archive class with given ``password``."""

    @abstractmethod
    def set_password(self, pwd: str, encryption: str = 'AnyStr') -> NewArchive:
        """Set password for an archive. Returns NewArchive object."""

    def extract_all(
            self,
            __path: int | str | bytes | PathLike[str] | PathLike[bytes] = '.'
    ) -> None:
        """Extract all files to given ``path``. If not specified, extracts to current working directory."""
        for file in self.files:
            file.extract(__path)

    def peek_all(
            self,
            encoding: str = 'utf-8',
            ignore_overflow: bool = True,
            char_limit: int = 8191
    ) -> list[tuple[str, str | bytes]]:
        """Decode files content. Returns a list of tuples, where first element is filename and
        second is its content. If decoding failed, byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit``
        characters (bytes) will be partially shown.
        """
        files = []
        for file in self.files:
            if not file.is_dir:
                files.append((file.file_name, file.peek(encoding, ignore_overflow, char_limit)))
        return files
