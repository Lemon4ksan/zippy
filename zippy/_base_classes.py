from dataclasses import dataclass
from datetime import datetime
from os import PathLike, mkdir, path
from abc import abstractmethod, ABCMeta
from typing import AnyStr, Optional, Any, TextIO, BinaryIO, Self


@dataclass
class File:
    """Final representation of the file.

    Attributes:
        filename (:obj:`str`): Name of the file.
        is_dir (:obj:`bool`): True if file is a directory.
        version_needed_to_exctract (:obj:`int`): Minimal version of zip required to unpack.
        encryption_method (:obj:`str`): Name of the encryption method. 'Unencrypted' if none.
        compression_method (:obj:`str`): Name of the compression method. 'Stored' if none.
        compression_level (:obj:`str`): Level of compression.
        last_mod_time (:class:`datetime`, optional): Datetime of last modification of the file.
            None if time is not specified.
        crc (:obj:`int`): CRC of the file.
        compressed_size (:obj:`int`): Compressed size of the file.
        uncompressed_size (:obj:`int`): Uncompressed size of the file.
        contents (:obj:`bytes`): Undecoded content of the file.
        specifications (:obj:`list`[:obj:`Any`]`, optional): Miscelenious information about the
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
    specifications: Optional[list[Any]] = None

    def extract(self, __path: str | bytes | PathLike[str] | PathLike[bytes] = '.') -> None:
        """Extract file to given ``path``. If not specified, extracts to current working directory."""

        if not path.exists(__path):
            # Folder to extract
            mkdir(__path)
        __path = path.join(str(__path), self.filename.replace('/', '\\'))  # get final file path

        if self.is_dir:
            if not path.exists(__path):
                mkdir(__path)
        else:
            # Write to file
            with open(__path, 'wb') as f:
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
                data = data[:char_limit // 2] + ' |...| File too large to display'
            elif isinstance(data, bytes):
                data = data[:char_limit // 32] + b' |...| File too large to display'

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
    def create_file(
            self,
            fn: str,
            fd: str | bytes | TextIO | BinaryIO,
            fp: str = '.',
            /,
            compression: str = 'AnyStr',
            level: str = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        """Create file ``fn`` in ``fp`` directory with data ``fd`` inside archive. It will be compressed with
        ``compression`` method with ``level`` strength if it's supported and encoded with given ``encoding``.

        ``fd`` is a text or byte string or a data stream.

        ``fp`` must start from '.' (root).

        Additional ``comment`` can be applied to the file.
        """

    @abstractmethod
    def add_file(
            self,
            fn: str,
            fd: int | str | bytes | PathLike[str] | PathLike[bytes],
            fp: str = '.',
            /,
            compression: str = 'AnyStr',
            level: str = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ) -> None:
        """Add file ``fd`` to archive in ``fp`` directory with name ``fn``. It will be compressed with
        ``compression`` method with ``level`` strength if it's supported and encoded with given ``encoding``.

        ``fd`` is a text or byte string giving the name (and the path if the file
        isn't in the current working directory) of the file to be opened.

        ``fp`` must start from '.' (root).

        Additional ``comment`` can be applied to the file.
        """

    @abstractmethod
    def edit_file(
            self,
            fn: str,
            fp: str,
            fd: str | bytes | TextIO | BinaryIO,
            /
    ) -> None:
        """Replace file ``fn`` in ``fp`` directory inside archive with new ``fd`` data.

        ``fp`` must start from '.' (root).

        ``fd`` is a text or byte string or a data stream.

        Raises FileNotFound exception if file is not present at given path.
        """

    @abstractmethod
    def remove_file(self, fn: str, fp: str, /) -> None:
        """Remove file ``fn`` in ``fp`` directory inside archive.

        ``fp`` must start from '.' (root).
        """

    @abstractmethod
    def create_folder(self, fn: str, fp: str = '.', /, encoding: str = 'utf-8') -> str:
        """Create folder ``fn`` inside archive in ``fp`` directory.

        ``fn`` can also be a full path of new directory, starting from '.' (``fp`` must be default).

        ``fp`` should start from '.' (root).

        Returns string representing final path. Used to add new files to the folder.
        """

    @abstractmethod
    def add_folder(
        self,
        fd: str | bytes | PathLike[str] | PathLike[bytes],
        fp: str = '.',
        /,
        compression: str = 'AnyStr',
        level: str = 'AnyStr',
        comment: str = '',
        use_mp: bool = True
        ) -> None:
        """Add folder from disk at ``fd`` directory to the archive in ``fp`` folder.

        ``fd`` path can be both absolute and relative.

        ``fp`` should start from '.' (root).

        If ``use_mp`` is True, all CPU cores will be used to add large amount of files faster.
        Note that to use this, you must use main idiom.
        """

    @abstractmethod
    def remove_folder(self, fn: str, fp: str = '.', /) -> list[str]:
        """Remove folder with name ``fn`` in ``fp`` directory and its contents.

        ``fn`` can also be a full path to the folder that will be removed, starting from '.' (``fp`` must be default).

        ``fp`` should start from '.' (root).

        Returns list of paths of deleted files and folders.
        """

    @abstractmethod
    def add_from_archive(
            self,
            ap: str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
            fp: str = '.',
            new_fp: str = '.',
            /,
            pwd: Optional[str] = None,
            compression: str = 'AnyStr',
            level: str = 'AnyStr',
            encoding: str = 'utf-8',
            comment: str = ''
    ):
        """Add file or folder with path ``fp`` from ``ap`` archive to ``new_fp`` of this archive.

        ``ap`` is a text or byte string giving the name (and the path if the file
        isn't in the current working directory) of the file to be opened or a binary data stream.

        ``fp`` must be a path to the file or folder that will be added, starting from '.' (root).

        ``new_fp`` must be a path to the folder the new file will be added to, starting from '.' (root).

        ``pwd`` must be provided if archive is encrypted.

        Should be universal for all kinds of archives, but only works with the same archive type for now.
        """

    @abstractmethod
    def get_structure(self, fp: str = '.', /) -> list[str]:
        """Get structure of the archive. If ``fp`` is specified, returns the structure of given folder."""

    @abstractmethod
    def save(
            self,
            fn: str,
            fp: str | bytes | PathLike[str] | PathLike[bytes] = '.',
            /,
            comment: str = ''
    ) -> None:
        """Save new archive file with name ``fn`` at given ``fp``.

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

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    @property
    def compression_method(self):
        return self._compression_method
    
    @property
    def encryption_method(self):
        return self._encryption_method

    @property
    def comment(self):
        return self._comment
    
    @property
    def total_entries(self):
        return self._total_entries
    
    @property
    def encoding(self):
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
    def new(pwd: Optional[str] = None, encryption: str = 'Unencrypted', encoding: str = 'utf-8') -> NewArchive:
        """Return new editable archive class with given ``password`` and ``encryption``.

        ``encoding`` is only used to encode filenames and comments. You may use different encoding on files.
        It is also reccomended not to mix different encodings.
        """

    @abstractmethod
    def edit(self, pwd: Optional[str] = None, encryption: str = 'Unencrypted') -> NewArchive:
        """Return editable archive class with existing files and given ``password``."""

    @abstractmethod
    def set_password(self, pwd: str, encryption: str = 'AnyStr') -> NewArchive:
        """Set new password for an archive. Returns editable class with all files."""

    def extract_all(
            self,
            __path: str | bytes | PathLike[str] | PathLike[bytes] = '.'
    ) -> None:
        """Extract all files to given ``path``. If not specified, extracts to current working directory."""
        for file in self._files:
            file.extract(__path)

    def peek_all(
            self,
            encoding: str = 'utf-8',
            *,
            include_folders: bool = True,
            ignore_overflow: bool = True,
            char_limit: int = 8191
    ) -> list[tuple[str, str | bytes]]:
        """Decode files contents. Returns a list of tuples, where first element is filename and
        second is its contents. If decoding failed, byte representation will be used instead.

        If ``include_folders`` is set to False, folders will be ignored.

        If ``ignore_overflow`` is set to False, content that exceeds ``char_limit``
        characters (bytes) will be partially shown.
        """
        files = []
        for file in self._files:
            if not file.is_dir or include_folders:
                files.append(
                    ('.\\' + file.filename.replace('/', '\\'),
                     file.peek(encoding, ignore_overflow=ignore_overflow, char_limit=char_limit))
                )
        return files
