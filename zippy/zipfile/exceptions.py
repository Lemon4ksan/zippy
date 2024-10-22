class ZippyException(Exception):
    """Base class for all zippy exceptions."""

class BadFile(ZippyException):
    """Bad file given to unpack."""

class ReservedValue(BadFile):
    """Reserved value found while processing file."""

class Deprecated(BadFile):
    """Unsupported proccess found."""

class EncryptionError(ZippyException):
    """Base class for all encryption related exceptions."""

class WrongPassword(EncryptionError):
    """Given password is incorrect."""


