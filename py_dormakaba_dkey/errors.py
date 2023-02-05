"""Exceptions."""

from bleak.exc import BleakError
from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS

from .models import DisconnectReason, ErrorCode


class DkeyError(Exception):
    """Base class for exceptions."""


class CommandFailed(DkeyError):
    """Raised when the lock rejects a command."""

    def __init__(self, error: ErrorCode):
        self.error = error
        super().__init__(error.name)


class Disconnected(DkeyError):
    """Raised when the connection is lost."""

    def __init__(self, reason: DisconnectReason):
        self.reason = reason
        super().__init__(reason.name)


class InvalidCommand(DkeyError):
    """Raised when a received command can't be parsed."""


class InvalidActivationCode(DkeyError):
    """Raised when trying to associate with an invalid activation code."""


class NotAssociated(DkeyError):
    """Raised when not associated."""


class NotAuthenticated(DkeyError):
    """Raised when trying to execute a command which requires authentication."""


class NotConnected(DkeyError):
    """Raised when connection is lost while sending a command."""


class Timeout(BleakError, DkeyError):
    """Raised when trying to associate with wrong activation code."""


class UnsupportedProtocolVersion(DkeyError):
    """Unsupported protocol version."""


class WrongActivationCode(DkeyError):
    """Raised when trying to associate with wrong activation code."""


DKEY_EXCEPTIONS = (
    *BLEAK_EXCEPTIONS,
    CommandFailed,
    Disconnected,
    InvalidCommand,
)
