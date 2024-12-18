"""RAR file format is proprietary and read-only without using WinRAR app. All rights reserved."""

from os import PathLike
from typing import BinaryIO, Optional

from .._base_classes import Archive, File, NewArchive
from ..constants import *
from ..exceptions import *
from ._rarfile import u_LEB128, MainHeader, FileHeader, ServiceHeader, EOAHeader

INT32_MAX: int = 4_294_967_295
ILLEGAL_CHARS: list[str] = [
    '#', '%', '&', '{', '}', 
    '<', '>', '*', '?','$',
    '!', "'", '"', ':', '@',
    '+', '`', '|', '='
]

class RarFile(Archive):
    """Class representing the rar file and its contents. RAR files are read-only."""

    def __init__(
            self,
            files: list[File],
            comment: str,
            total_entries: int,
            encoding: str
    ):
        super().__init__(files, comment, total_entries, encoding)

    @staticmethod
    def open(
        f: int | str | bytes | PathLike[str] | PathLike[bytes] | BinaryIO,
        pwd: str | None = None,
        encoding: str = 'utf-8'
    ) -> 'RarFile':

        files: list[File] = []
        file_headers: list[FileHeader] = []
        service_headers: list[ServiceHeader] = []
        indirect: bool = False

        if isinstance(f, (int, str, bytes, PathLike)):
            f = open(f, 'rb')
            indirect = True
        elif not isinstance(f, BinaryIO):
            raise TypeError(f"Expected argument f to be int, str, bytes or os.PathLike object, got '{type(f).__name__}' instead.")
        
        self_extract_bytes: bytes = b''
        i: int = 0
        while b'Rar!\x1a\x07\x01\x00' not in self_extract_bytes:
            byte = f.read(1)
            self_extract_bytes += byte
            i += 1
            if i == 1_048_577 or byte == b'':  # 1 mb
                raise BadFile('File is not in .RAR format.')
        self_extract_bytes = self_extract_bytes[:-8]

        try:
            while True:
                h_crc: int = int.from_bytes(f.read(4), 'little')
                h_size: int = u_LEB128(f)
                h_type: int = u_LEB128(f)
            
                match h_type:
                    case 1:
                        main_header: MainHeader = MainHeader.__init_raw__(f)
                    case 2:
                        f_header: FileHeader = FileHeader.__init_raw__(f)
                        file_headers.append(f_header)
                        files.append(f_header.decode())
                    case 3:
                        s_header: ServiceHeader = ServiceHeader.__init_raw__(f)
                        service_headers.append(s_header)
                    case 4:
                        pass
                    case 5:
                        EOA_header: EOAHeader = EOAHeader.__init_raw__(f)
                        break
                    case _:
                        raise BadFile(f"Unknown header type '{h_type}'.")

        finally:
            if indirect:
                f.close()
        
        return RarFile(files, '', len(files), encoding)
    
    @staticmethod
    def new(pwd: Optional[str] = None, encryption: str = 'Unencrypted', encoding: str = 'utf-8') -> NewArchive:
        raise ZippyException("RAR files can be read but not created. See UnRAR License for more info.")

    def edit(self, pwd: Optional[str] = None, encryption: str = 'Unencrypted') -> NewArchive:
        raise ZippyException("RAR files can be read but not created. See UnRAR License for more info.")

    def set_password(self, pwd: str, encryption: str = 'AES256') -> NewArchive:
        raise ZippyException("RAR files can be read but not created. See UnRAR License for more info.")
