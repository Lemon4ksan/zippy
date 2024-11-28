from abc import abstractmethod, ABCMeta
from dataclasses import dataclass
from datetime import datetime
from os import PathLike, mkdir, sep
from os import path as os_path
from types import TracebackType
from typing import Optional, Any, TextIO, BinaryIO, Self

@dataclass
class File:
    """Final representation of the file.

    **Attributes**:
        * filename (`str`): Name of the file.
        * is_dir (`bool`): True if file is a directory.
        * version_needed_to_exctract (`int`): Minimal version of zip required to unpack.
        * encryption_method (`str`): Name of the encryption method. 'Unencrypted' if none.
        * compression_method (`str`): Name of the compression method. 'Stored' if none.
        * compression_level (`str`): Level of compression.
        * last_mod_time (`datetime`, optional): Datetime of last modification of the file.
        None if time is not specified.
        * crc (`int`): CRC of the file.
        * compressed_size (`int`): Compressed size of the file.
        * uncompressed_size (`int`): Uncompressed size of the file.
        * contents (`bytes`): Undecoded content of the file.
        * specifications (`dict[Any, Any]`, optional): Miscelenious information about the
        file that may vary based on archive's structure.
    """

    filename: str
    is_dir: bool
    version_needed_to_exctract: int
    encryption_method: str
    compression_method: str
    compression_level: str
    last_mod_time: Optional[datetime]
    crc: int
    compressed_size: int
    uncompressed_size: int
    contents: bytes
    comment: str = ''
    specifications: Optional[dict[Any, Any]] = None

    def extract(self, path: str | bytes | PathLike[str] | PathLike[bytes] = '.') -> None:
        """Extract file to given ``path``. If not specified, extracts to current working directory."""

        if not os_path.exists(path):
            # Folder to extract
            mkdir(path)
        path = os_path.join(str(path), self.filename).replace('/', sep)  # get final file path

        if self.is_dir:
            if not os_path.exists(path):
                mkdir(path)
        else:
            # Write to file
            with open(path, 'wb') as f:
                f.write(self.contents)

    def peek(
            self,
            encoding: str = 'utf-8',
            *,
            ignore_overflow: bool = True,
            char_limit: int = 8191
    ) -> str | bytes:
        """Decode file content. If decoding with given ``encoding`` failed, byte representation will be used instead.

        If ``ignore_overflow`` is set to False, content that exceeds
        ``char_limit`` characters (bytes) will be partially shown.
        """

        try:
            data: str | bytes = self.contents.decode(encoding)
        except UnicodeDecodeError:
            data = self.contents

        if len(data) > char_limit and not ignore_overflow:
            if isinstance(data, str):
                return data[:char_limit // 2] + ' |...| File too large to display'
            return bytes(data[:char_limit // 32]) + b' |...| File too large to display'

        return data

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
        self.debug: bool = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: TracebackType | None,
    ) -> None:
        pass

    @property
    def pwd(self) -> Optional[str]:
        return self._pwd

    @property
    def encoding(self) -> str:
        return self._encoding

    @property
    def encryption(self) -> str:
        return self._encryption
    
    @abstractmethod
    def get_files(self, encoding: str = 'utf-8') -> dict[str, File]:
        """Get dictionary containing files inside archive. Key is path to the file.
        Note that folder names have separator at the end to differentiate them.
        """

    @abstractmethod
    def get_structure(self, path: str = '', /) -> list[str]:
        """Get structure of the archive. If ``path`` is specified, returns the structure of given folder with absolute paths."""
    
    @abstractmethod
    def create_file(
            self,
            path: str,
            contents: str | bytes | TextIO | BinaryIO,
            /,
            compression = 'AnyStr',
            level = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        """Create file ``path`` with ``contents`` data. Data is compressed using ``compression``
        method with ``level`` if it's supported and encoded with given ``encoding``.

        If file already exists, it will be overwritten.

        ``contents`` is a text or byte string or a data stream.

        Additional ``comment`` can be applied to the file.
        """

    @abstractmethod
    def add_file(
            self,
            source: int | str | bytes | PathLike[str] | PathLike[bytes],
            path: str = '',
            /,
            compression = 'AnyStr',
            level = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        """Create file ``path`` with data from ``source``. Data is compressed using ``compression``
        method with ``level`` if it's supported and encoded with given ``encoding``.

        If path is an empty string, file will be added to root folder with source's filename.
        Path mast be specified if source is a file descriptor.

        If any of the files already exists, they will be overwritten.

        ``source`` is a text or byte string giving the name (and the path if the file
        isn't in the current working directory) of the file which data will be used.

        Additional ``comment`` can be applied to the file.
        """

    @abstractmethod
    def edit_file(
            self,
            path: str,
            contents: str | bytes | TextIO | BinaryIO,
            /
    ) -> None:
        """Replace data of the file ``path`` with new ``contents`` data.

        ``contents`` is a text or byte string or a data stream.

        Raises FileNotFound exception if file is not present at given path.
        """

    @abstractmethod
    def remove(self, path: str = '', /) -> None:
        """Remove file ``path``.

        If path is a folder, it will be removed with its child files included.

        If path is an empty string, all files will be removed."""

    @abstractmethod
    def create_folder(self, path: str, /, encoding: str = 'utf-8') -> None:
        """Create folder ``path``."""

    @abstractmethod
    def add_folder(
        self,
        source: str | bytes | PathLike[str] | PathLike[bytes],
        path: str = '',
        /,
        compression = 'AnyStr',
        level = 'AnyStr',
        encoding: str = 'utf-8',
        comment: str = '',
        *,
        use_mp: bool = False
    ) -> None:
        """Add folder ``source`` from disk to the archive in ``path`` folder.

        If ``use_mp`` is True, all CPU cores will be used to add large amount of files faster.
        Note that to use this, you must use main idiom.
        """

    @abstractmethod
    def add_from_archive(
            self,
            archive: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            path: str = '.',
            new_path: str = '.',
            /,
            pwd: Optional[str] = None,
            compression = 'AnyStr',
            level = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        """Add file ``path`` inside ``archive`` to ``new_path`` inside this archive.

        ``archive`` is a text or byte string giving the name (and the path if the file
        isn't in the current working directory) of the file to be opened or a binary data stream.

        ``path`` must be a path to the file or folder that will be added. If file is a folder, make sure
        to add separator at the end to differentiate it from other files and add all its child files.
        Otherwise, only folder itself will be added.

        ``new_fp`` must be a path to the folder the new file will be added to.

        ``pwd`` must be provided if target archive is encrypted.

        Should be universal for all kinds of archives, but only works with the same archive type for now.
        """

    @abstractmethod
    def save(
            self,
            path: int | str | bytes | PathLike[str] | PathLike[bytes],
            /,
            comment: str = ''
    ) -> None:
        """Save new archive as ``path``.

        Additional ``comment`` can be applied to the file.
        """

class Archive(metaclass=ABCMeta):
    """Base class for all archives"""

    def __init__(
            self,
            files: list[File],
            comment: str,
            total_entries: int,
            encoding: str
    ):
        self._files: list[File] = files
        self._comment: str = comment
        self._total_entries: int = total_entries
        self._encoding: str = encoding

        compression_method: str = next((file.compression_method for file in files if file.filename[-1] != '/'), files[0].compression_method)
        self._compression_method: str = 'Mixed' if any(
            compression_method != f.compression_method and f.filename[-1] != '/' for f in files
        ) else compression_method

        self._encryption_method: str = next((file.encryption_method for file in files if file.filename[-1] != '/'), files[0].encryption_method)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: TracebackType | None,
    ) -> None:
        pass
    
    @property
    def compression_method(self) -> str:
        return self._compression_method
    
    @property
    def encryption_method(self) -> str:
        return self._encryption_method

    @property
    def comment(self) -> str:
        return self._comment
    
    @property
    def total_entries(self) -> int:
        return self._total_entries
    
    @property
    def encoding(self) -> str:
        return self._encoding

    @staticmethod
    @abstractmethod
    def open(
            f: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            pwd: Optional[str] = None,
            encoding: str = 'utf-8'
    ) -> 'Archive':
        """Open archive and return its representation.

        ``f`` is either a text or byte string giving the name
        (and the path if the archive isn't in the current working directory)
        of the archive to be opened or an integer file descriptor of the file to be wrapped.

        ``encoding`` is only used to decode filenames and comments. You may use different encoding to extract files.

        Raises BadFile exception if target file is damaged.
        """

    @staticmethod
    @abstractmethod
    def new(pwd: Optional[str] = None, encryption = 'Unencrypted', encoding: str = 'utf-8') -> NewArchive:
        """Return new editable archive class with given ``password`` and ``encryption``.

        ``encoding`` is only used to encode filenames and comments. You may use different encoding on files.
        It is also reccomended not to mix different encodings.
        """

    @abstractmethod
    def edit(self, pwd: Optional[str] = None, encryption = 'Unencrypted') -> NewArchive:
        """Return editable archive class with existing files and given ``password``."""

    @abstractmethod
    def set_password(self, pwd: str, encryption = 'AnyStr') -> NewArchive:
        """Set new password for an archive. Returns editable class with all files."""

    def extract_all(
            self,
            path: str | bytes | PathLike[str] | PathLike[bytes] = '.'
    ) -> None:
        """Extract all files to given ``path``. If not specified, extracts to current working directory."""
        for file in self._files:
            file.extract(path)

    def get_files(
            self,
            encoding: str = 'utf-8',
            *,
            include_folders: bool = True,
            ignore_overflow: bool = True,
            char_limit: int = 8191
    ) -> dict[str, str | bytes]:
        """Get dictionary containing files inside archive. Key is path to the file.
        Note that folder names have separator at the end to differentiate them.

        If ``include_folders`` is set to False, folders will be ignored.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit``
        characters (bytes) will be partially shown.
        """
        files = {}
        for file in self._files:
            if not file.is_dir or include_folders:
                files[file.filename.replace('/', sep)] = file.peek(encoding, ignore_overflow=ignore_overflow, char_limit=char_limit)
        return files
