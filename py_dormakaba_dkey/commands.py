"""Models for commands which can be sent to and received from a lock."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
import struct
from typing import Any, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .errors import InvalidCommand
from .models import ErrorCode


class Command(ABC):
    """Base class for commands."""

    cmd_id: int
    _format: str
    _len: int

    @property
    @abstractmethod
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> Command:
        """Initialize from serialized representation of the command."""

    @property
    def _header(self) -> bytes:
        """Return packed header."""
        return struct.pack("!BB", self.cmd_id, self._len)

    def _pack(self, *args: Any) -> bytes:
        """Pack the command to bytes."""
        return self._header + struct.pack(self._format, *args)

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) != 2 + cls._len:
            raise InvalidCommand("Invalid length", data.hex())
        if data[0] != cls.cmd_id or data[1] != cls._len:
            raise InvalidCommand("Invalid header", data.hex())


_CMD_T = TypeVar("_CMD_T", bound=Command)


class AuthChallengeBase(Command):
    """Authentication Base Command."""

    _format = "!16s"
    _len = struct.calcsize(_format)
    _nonce_label: str

    def __init__(self, nonce: bytes) -> None:
        """Initialize."""
        self.nonce = nonce

    def __str__(self) -> str:
        return f"{self.__class__.__name__} {self._nonce_label}: {self.nonce.hex()}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.nonce)

    @classmethod
    def from_bytes(cls, data: bytes) -> AuthChallengeBase:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (challenge,) = struct.unpack_from(cls._format, data, 2)
        return cls(challenge)


class ECDHPublicReplyCmdBase(Command):
    """ECDH Public Base Command."""

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        """Initialize."""
        self.public_key = public_key
        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self._format = f"!{len(public_key_bytes[1:])}s"
        self._len = struct.calcsize(self._format)

    def __str__(self) -> str:
        public_bytes = self.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return f"{self.__class__.__name__} peer public key: {public_bytes[1:].hex()}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        public_bytes = self.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return self._pack(public_bytes[1:])

    @classmethod
    def _calc_format(cls, data: bytes) -> str:
        return f"!{len(data)-2}s"

    @classmethod
    def _calc_len(cls, data: bytes) -> int:
        return struct.calcsize(cls._calc_format(data))

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) < 2:
            raise InvalidCommand("Invalid length", data.hex())
        if len(data) != 2 + cls._calc_len(data):
            raise InvalidCommand("Invalid length", data.hex())
        if data[0] != cls.cmd_id or data[1] != cls._calc_len(data):
            raise InvalidCommand("Invalid header", data.hex())

    @classmethod
    def from_bytes(cls, data: bytes) -> ECDHPublicReplyCmdBase:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        fmt = cls._calc_format(data)
        (public_key_bytes,) = struct.unpack_from(fmt, data, 2)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + public_key_bytes
        )
        return cls(public_key)


class HandshakeCheckBase(Command):
    """Base for handshake check."""

    _format = "!14s"
    _len = struct.calcsize(_format)

    _expected_msg: str = "handshakecheck"

    def __init__(self, msg: str) -> None:
        """Initialize."""
        self.msg = msg

    def __str__(self) -> str:
        return f"{self.__class__.__name__} msg: {self.msg}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.msg)

    @classmethod
    def from_bytes(cls, data: bytes) -> HandshakeCheckBase:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        msg_bytes: bytes
        (msg_bytes,) = struct.unpack_from(cls._format, data, 2)
        msg = msg_bytes.decode("UTF-8")
        return cls(msg)


class UnknownCommand(Command):
    """Unknown command."""

    def __init__(self, data: bytes):
        """Initialize."""
        self.data = data
        self.cmd_id = data[0]

    def __str__(self) -> str:
        return f"{self.__class__.__name__} data: {self.data.hex()}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> UnknownCommand:
        """Initialize from serialized representation of the command."""
        return cls(data)


class GetIdentificationCmd(Command):
    """Get Identification Command."""

    cmd_id = 0x00
    _format = "!4s"
    _len = struct.calcsize(_format)

    def __init__(self, ident: bytes):
        """Initialize."""
        self.ident = ident

    def __str__(self) -> str:
        return f"{self.__class__.__name__} ident: {self.ident.hex()}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.ident)

    @classmethod
    def from_bytes(cls, data: bytes) -> GetIdentificationCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (ident,) = struct.unpack_from(cls._format, data, 2)
        return cls(ident)


class AuthChallengeCmd(AuthChallengeBase):
    """Authentication Challenge Command."""

    cmd_id = 0x01
    _nonce_label = "challenge"


class AuthChallengeAcceptedCmd(HandshakeCheckBase):
    """Authentication Challenge Accepted Command."""

    cmd_id = 0x02


class UnlockType(IntEnum):
    """Unlock type."""

    DIRECT_UNLOCK = 0
    AUTO_UNLOCK = 1
    DIRECT_UNLOCK_LOCK = 2
    AUTO_UNLOCK_LOCK = 3
    HANDSFREE_UNLOCK = 4
    HANDSFREE_UNLOCK_LOCK = 5


class InOutStatus(IntEnum):
    """In/out status."""

    OUT = 0
    IN = 1
    UNKNOWN = -1


class UnlockCmd(Command):
    """Unlock Command."""

    cmd_id = 0x03
    _format = "!BBbBBBB"
    _len = struct.calcsize(_format)

    def __init__(
        self, unlock_type: UnlockType, in_out_settings: int, in_out_status: InOutStatus
    ) -> None:
        """Initialize."""
        self.unlock_type = unlock_type
        self.in_out_settings = in_out_settings
        self.in_out_status = in_out_status
        self._unknown_1 = 0x8D
        self._unknown_2 = 0x80
        self._unknown_3 = 0x8D
        self._unknown_4 = 0x89

    @classmethod
    def defaults(cls) -> UnlockCmd:
        """Return an instance with default settings."""
        return cls(UnlockType.AUTO_UNLOCK, 0, InOutStatus.IN)

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} unlock_type: {self.unlock_type.name}, "
            f"in_out_status: {self.in_out_status.name}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(
            self.unlock_type,
            self.in_out_settings,
            self.in_out_status,
            self._unknown_1,
            self._unknown_2,
            self._unknown_3,
            self._unknown_4,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> UnlockCmd:
        """Initialize from serialized representation of the command."""
        raise NotImplementedError


class DisconnectReason(IntEnum):
    """Disconnect reason."""

    REMOTE_DISCONNECT = 0
    KICKED_OUT = 1
    TIMEOUT = 2
    OOR = 3
    ASSOCIATION = 4
    KEY_DISABLED = 5
    DEFAULT = -1


class DisconnectReqCmd(Command):
    """Disconnect request command."""

    cmd_id = 0x04
    _format = "!b"
    _len = struct.calcsize(_format)

    def __init__(self, disconnect_reason: DisconnectReason) -> None:
        """Initialize."""
        self.disconnect_reason = disconnect_reason

    def __str__(self) -> str:
        return f"{self.__class__.__name__} reason: {self.disconnect_reason.name}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.disconnect_reason)

    @classmethod
    def from_bytes(cls, data: bytes) -> DisconnectReqCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (disconnect_reason,) = struct.unpack_from(cls._format, data, 2)
        return cls(DisconnectReason(disconnect_reason))


class AssociationParametersCmd(Command):
    """Association Parameters Command."""

    cmd_id = 0x09
    _format = "!4s16s"
    _len = struct.calcsize(_format)

    def __init__(self, key_holder_id: bytes, secret: bytes) -> None:
        """Initialize."""
        self.key_holder_id = key_holder_id
        self.secret = secret

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} key_holder_id: {self.key_holder_id!r}, "
            f"secret: {self.secret.hex()}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(
            self.key_holder_id,
            self.secret,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> AssociationParametersCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (key_holder_id, secret) = struct.unpack_from(cls._format, data, 2)
        return cls(key_holder_id, secret)


class NotAssociatedCmd(Command):
    """Not Associated Command."""

    cmd_id = 0x13
    _format = ""
    _len = struct.calcsize(_format)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack()

    @classmethod
    def from_bytes(cls, data: bytes) -> NotAssociatedCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        return cls()


class DoorType(IntEnum):
    """Door type."""

    UNKNOWN_DOOR = 0
    FRONT_DOOR = 1
    BACK_DOOR = 2
    GARAGE_DOOR = 3
    OTHER_DOOR = 4
    NO_DOOR = -2
    DEFAULT = -1


class DetectorSide(IntEnum):
    """Detector side."""

    DETECTOR_INSIDE = 1
    DETECTOR_OUTSIDE = 3


class KeyFeatures(IntEnum):
    """Key features."""

    HANDSFREE = 1
    KEY_DISABLED = 2
    CODE_REQUIRED = 4
    ONE_TIME = 8
    LOCK_HASH_REQUIRED = 16
    SHELL_PROTECTION = 32
    AUTO_LOCK = 64
    AWAY_MODE = 128


class DetTypeNameCmd(Command):
    """Detector Type and Name Command."""

    cmd_id = 0x15

    def __init__(
        self,
        device_id: bytes,
        door_type: DoorType,
        detector_side: DetectorSide,
        device_name: str,
        key_features: int,
        initialized: bool | None,
    ) -> None:
        """Initialize."""
        self.device_id = device_id
        self.door_type = door_type
        self.detector_side = detector_side
        self.device_name = device_name
        self.key_features = key_features
        self.initialized = initialized

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} device_id: {self.device_id.hex()}, door_type: "
            f"{self.door_type}, detector_side: {self.detector_side}, device_name: "
            f"{self.device_name}, key_features: {self.key_features}, initialized: "
            f"{self.initialized}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        raise NotImplementedError

    @classmethod
    def _calc_format(cls, data: bytes) -> str:
        return "!4sbB12sBB" if len(data) == 22 else "!4sbB12sB"

    @classmethod
    def _calc_len(cls, data: bytes) -> int:
        return struct.calcsize(cls._calc_format(data))

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) != 2 + cls._calc_len(data):
            raise InvalidCommand("Invalid length", data.hex())
        if data[0] != cls.cmd_id or data[1] != cls._calc_len(data):
            raise InvalidCommand("Invalid header", data.hex())

    @classmethod
    def from_bytes(cls, data: bytes) -> DetTypeNameCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        fmt = cls._calc_format(data)
        if len(data) == 22:
            (
                device_id,
                door_type,
                side,
                device_name_bytes,
                key_features,
                initialized,
            ) = struct.unpack_from(fmt, data, 2)
        else:
            (
                device_id,
                door_type,
                side,
                device_name_bytes,
                key_features,
            ) = struct.unpack_from(fmt, data, 2)
            initialized = None
        door_type = DoorType(door_type)
        side = DetectorSide(side)
        device_name = device_name_bytes.decode("ISO_8859_1")
        return cls(device_id, door_type, side, device_name, key_features, initialized)


class ECDHPublicCmd(ECDHPublicReplyCmdBase):
    """ECDH Public Key Command."""

    cmd_id = 0x17


class ECDHPublicReplyCmd(ECDHPublicReplyCmdBase):
    """ECDH Public Key Reply Command."""

    cmd_id = 0x18


class GetNotificationsMaskCmd(Command):
    """Get Notifications Mask Command."""

    cmd_id = 0x1B
    _format = ""
    _len = struct.calcsize(_format)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack()

    @classmethod
    def from_bytes(cls, data: bytes) -> GetNotificationsMaskCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        return cls()


class SetEnabledNotificationsMaskCmd(Command):
    """Get Enabled Notifications Mask Command."""

    cmd_id = 0x1C
    _format = "!B"
    _len = struct.calcsize(_format)

    def __init__(self, notifications_mask: int) -> None:
        """Initialize."""
        self.notifications_mask = notifications_mask  # Same as notifications?

    def __str__(self) -> str:
        return f"{self.__class__.__name__} mask: {self.notifications_mask:02x}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.notifications_mask)

    @classmethod
    def from_bytes(cls, data: bytes) -> SetEnabledNotificationsMaskCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (notifications_mask,) = struct.unpack_from(cls._format, data, 2)
        return cls(notifications_mask)


class DoorPosition(IntEnum):
    """Door position."""

    CLOSED = 0
    OPEN = 1
    UNKNOWN = -1


class UnlockStatus(IntEnum):
    """Unlock status."""

    UNLOCKED = 0
    LOCKED = 1
    SECURITY_LOCKED = 2
    UNLOCKED_SECURITY_LOCKED = 3
    UNLOCKED_FORCED_UNLOCK = 4
    UNKNOWN = -1


class DoorHandleState(IntEnum):
    """Door handle state."""

    HANDLE_IDLE = 0
    HANDLE_UP_DOWN = 1
    UNKNOWN = 255


class UnlockMode(IntEnum):
    """Unlock mode."""

    UNLOCKED = 0
    LOCKED = 1
    UNKNOWN = -1


class AwayMode(IntEnum):
    """Away mode."""

    ENABLED = 1
    DISABLED = 2
    UNKNOWN = -1


class ShellProtectionStatus(IntEnum):
    """Shell protection status."""

    ENABLED = 1
    DISABLED = 2
    UNKNOWN = -1


class NotificationType(IntEnum):
    """Notification type."""

    BATTERY = 0
    DOOR_POSITION = 1
    UNLOCK_STATUS = 2
    UNLOCK_MODE = 3
    AWAY_MODE = 4
    SHELL_PROTECTION_STATUS = 5
    SHB_DELAYED_UNLOCK = 6


class Notifications:
    """Notifications."""

    battery: int | None = None
    door_position: DoorPosition | None = None
    unlock_status: UnlockStatus | None = None
    door_handle_state: DoorHandleState | None = None
    unlock_mode: UnlockMode | None = None
    away_mode: AwayMode | None = None
    shell_protection_status: ShellProtectionStatus | None = None
    shb_delayed_unlock: int | None = None  # 0 means off

    def __str__(self) -> str:
        values = []
        for attr in ("battery", "shb_delayed_unlock"):
            if (value := getattr(self, attr)) is not None:
                values.append(f"{attr}: {value}")
        for attr in (
            "door_position",
            "unlock_status",
            "door_handle_state",
            "unlock_mode",
            "away_mode",
            "shell_protection_status",
        ):
            if (value := getattr(self, attr)) is not None:
                values.append(f"{attr}: {value.name}")
        return ", ".join(values)

    def update(self, other: Notifications) -> None:
        """Merge notifications."""
        for attr in (
            "battery",
            "door_position",
            "unlock_status",
            "door_handle_state",
            "unlock_mode",
            "away_mode",
            "shell_protection_status",
            "shb_delayed_unlock",
        ):
            if (value := getattr(other, attr)) is not None:
                setattr(self, attr, value)

    @classmethod
    def from_bytes(cls, data: bytes) -> Notifications:
        """Initialize from serialized representation."""
        if len(data) & 0x1:
            raise InvalidCommand("Invalid data", data.hex())

        instance = cls()

        pos = 0
        while pos < len(data):
            notification_type = NotificationType(data[pos])
            value = data[pos + 1]
            pos += 2
            if notification_type == NotificationType.BATTERY:
                instance.battery = value
                continue
            if notification_type == NotificationType.DOOR_POSITION:
                instance.door_position = DoorPosition(value)
                continue
            if notification_type == NotificationType.UNLOCK_STATUS:
                instance.unlock_status = UnlockStatus(value & 0x7F)
                instance.door_handle_state = DoorHandleState((value & 0x80) >> 7)
                continue
            if notification_type == NotificationType.UNLOCK_MODE:
                instance.unlock_mode = UnlockMode(value)
                continue
            if notification_type == NotificationType.AWAY_MODE:
                instance.away_mode = AwayMode(value)
                continue
            if notification_type == NotificationType.SHELL_PROTECTION_STATUS:
                instance.shell_protection_status = ShellProtectionStatus(value)
                continue
            if notification_type == NotificationType.SHB_DELAYED_UNLOCK:
                instance.shb_delayed_unlock = value
                continue
            raise InvalidCommand("Unknown notification", notification_type, data.hex())

        return instance


class NotificationsUpdateBase(Command):
    """Notifications update base."""

    def __init__(self, notifications: Notifications) -> None:
        """Initialize."""
        self.notifications = notifications

    def __str__(self) -> str:
        return f"{self.__class__.__name__} notifications: {self.notifications}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.notifications)

    @classmethod
    def _calc_format(cls, data: bytes) -> str:
        return f"!{len(data)-2}s"

    @classmethod
    def _calc_len(cls, data: bytes) -> int:
        return struct.calcsize(cls._calc_format(data))

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) < 2:
            raise InvalidCommand("Invalid length", data.hex())
        if len(data) != 2 + cls._calc_len(data):
            raise InvalidCommand("Invalid length", data.hex())
        if data[0] != cls.cmd_id or data[1] != cls._calc_len(data):
            raise InvalidCommand("Invalid header", data.hex())

    @classmethod
    def from_bytes(cls, data: bytes) -> NotificationsUpdateBase:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        notifications = Notifications.from_bytes(data[2:])
        return cls(notifications)


class NotificationsUpdateCmd(NotificationsUpdateBase):
    """Set Enabled Notifications Mask Response."""

    cmd_id = 0x1D


class AuthPinChallengeCmd(AuthChallengeBase):
    """Authenticate PIN Challenge Command."""

    cmd_id = 0x23
    _nonce_label = "challenge"


class AuthPinChallengeReplyCmd(AuthChallengeBase):
    """Authenticate PIN Challenge Reply Command."""

    cmd_id = 0x24
    _nonce_label = "reply"


class AuthCheckCmd(HandshakeCheckBase):
    """Authentication Check Command."""

    cmd_id = 0x25


class LockMode(IntEnum):
    """Lock mode."""

    LOCK_MODE = 1
    SHB_MODE = 2
    IN_MODE = 3
    OUT_MODE = 4
    REMOTE_INIT = 5
    FORCED_UNLOCK = 6


class ChangeModeCmd(Command):
    """Change Mode Command."""

    cmd_id = 0x27
    _format = "!B"
    _len = struct.calcsize(_format)

    def __init__(self, mode: LockMode) -> None:
        """Initialize."""
        self.mode = mode

    def __str__(self) -> str:
        return f"{self.__class__.__name__} mode: {self.mode.name}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.mode)

    @classmethod
    def from_bytes(cls, data: bytes) -> ChangeModeCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (mode,) = struct.unpack_from(cls._format, data, 2)
        return cls(LockMode(mode))


class RequestChallengeCmd(Command):
    """Request Challenge Command."""

    cmd_id = 0x34
    _format = "!B4s"
    _len = struct.calcsize(_format)

    def __init__(self, ver: int, key_holder_id: bytes) -> None:
        """Initialize."""
        self.key_holder_id = key_holder_id
        self.ver = ver

    @classmethod
    def defaults(cls) -> RequestChallengeCmd:
        """Return an instance with default settings."""
        return cls(1, bytes.fromhex("fffffffe"))

    def __str__(self) -> str:
        return f"{self.__class__.__name__} ver:{self.ver}, id:{self.key_holder_id!r}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.ver, self.key_holder_id)

    @classmethod
    def from_bytes(cls, data: bytes) -> RequestChallengeCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (ver, key_holder_id) = struct.unpack_from(cls._format, data, 2)
        return cls(ver, key_holder_id)


class StatusReportType(IntEnum):
    """Status report type"""

    STUCK = 1
    STUCK_V2 = 2
    INIT_REPORT = 3
    LOCK_UNLOCK_REPORT = 4
    MISSING_TIMEOUT = 10
    GENERIC_STATUS_REPORT = -16


class StatusReportCmd(Command):
    """Status Report Command."""

    cmd_id = 0x35

    def __init__(
        self, status_report_type: StatusReportType, status_report: bytes
    ) -> None:
        """Initialize."""
        self._format = f"!b{len(status_report[1:])}s"
        self._len = struct.calcsize(self._format)
        self.status_report_type = status_report_type
        self.status_report = status_report

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} type:{self.status_report_type.name}, report:"
            f"{self.status_report.hex()}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.status_report_type, self.status_report)

    @classmethod
    def _calc_format(cls, data: bytes) -> str:
        return f"!b{len(data)-3}s"

    @classmethod
    def _calc_len(cls, data: bytes) -> int:
        return struct.calcsize(cls._calc_format(data))

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) < 3:
            raise InvalidCommand("Invalid length", data.hex())
        if len(data) != 2 + cls._calc_len(data):
            raise InvalidCommand("Invalid length", data.hex())
        if data[0] != cls.cmd_id or data[1] != cls._calc_len(data):
            raise InvalidCommand("Invalid header", data.hex())

    @classmethod
    def from_bytes(cls, data: bytes) -> StatusReportCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        fmt = cls._calc_format(data)
        (status_report_type, status_report) = struct.unpack_from(fmt, data, 2)
        return cls(StatusReportType(status_report_type), status_report)


class DeviceType(IntEnum):
    """Device type."""

    DETECTOR = 1
    FOB = 2
    KEYPAD = 3
    ANDROID_KEY_APP = 4
    ANDROID_ADMIN_APP = 5
    IOS_KEY_APP = 6
    IOS_ADMIN_APP = 7
    GATEWAY = 8
    SMART_HOME_BTN = 9
    PARTNER_KEY = 10


class GetIdentificationRsp(Command):
    """Get Identification Response."""

    cmd_id = 0x50
    _format = "!HBBB4sB7sB"
    _len = struct.calcsize(_format)

    def __init__(
        self,
        protocol_version: int,
        sw_version_major: int,
        sw_version_minor: int,
        sw_version_patch: int,
        key_holder_id: bytes,
        has_cookie: bool,
        user_id: bytes,
        device_type: DeviceType,
    ) -> None:
        """Initialize."""
        self.protocol_version = protocol_version
        self.sw_version_major = sw_version_major
        self.sw_version_minor = sw_version_minor
        self.sw_version_patch = sw_version_patch
        self.key_holder_id = key_holder_id
        self.has_cookie = has_cookie
        self.user_id = user_id
        self.device_type: DeviceType = device_type

    @classmethod
    def defaults(cls, key_holder_id: bytes) -> GetIdentificationRsp:
        """Return an instance with default settings."""
        device_type = DeviceType.ANDROID_KEY_APP
        user_id = "sweDoor".encode("ASCII")
        return cls(27, 1, 2, 6, key_holder_id, False, user_id, device_type)

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} protocol_ver: {self.protocol_version}, sw_ver:"
            f" {self.sw_version} , key_holder_id: {self.key_holder_id!r}, has_cookie:"
            f" {self.has_cookie}, user_id: {self.user_id!r}, device_type: "
            f"{self.device_type.name}"
        )

    @property
    def sw_version(self) -> str:
        "Return sw version."
        return (
            f"{self.sw_version_major}.{self.sw_version_minor}."
            f"{self.sw_version_patch}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(
            self.protocol_version,
            self.sw_version_major,
            self.sw_version_minor,
            self.sw_version_patch,
            self.key_holder_id,
            self.has_cookie,
            self.user_id,
            self.device_type,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> GetIdentificationRsp:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (
            protocol_version,
            sw_version_major,
            sw_version_minor,
            sw_version_patch,
            key_holder_id,
            has_cookie,
            user_id,
            device_type,
        ) = struct.unpack_from(cls._format, data, 2)
        return cls(
            protocol_version,
            sw_version_major,
            sw_version_minor,
            sw_version_patch,
            key_holder_id,
            has_cookie,
            user_id,
            DeviceType(device_type),
        )


class AckRsp(Command):
    """Acknowledge Response."""

    cmd_id = 0x51
    _format = "!BB"
    _len = struct.calcsize(_format)

    def __init__(self, error_code: ErrorCode, cmd_id: int):
        """Initialize."""
        self.error_code = error_code
        self.ack_cmd_id = cmd_id

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} error: {self.error_code.name}, cmd_id: "
            f"{self.ack_cmd_id:02x}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.error_code, self.ack_cmd_id)

    @classmethod
    def from_bytes(cls, data: bytes) -> AckRsp:
        """Initialize from serialized representation of the command."""
        (error_code, ack_cmd_id) = struct.unpack_from(cls._format, data, 2)
        return cls(ErrorCode(error_code), ack_cmd_id)


class AuthChallengeRsp(AuthChallengeBase):
    """Authentication Challenge Response."""

    cmd_id = 0x52
    _nonce_label = "response"


class GetNotificationsMaskRsp(Command):
    """Get Notifications Mask Response."""

    cmd_id = 0x57
    _format = "!B"
    _len = struct.calcsize(_format)

    def __init__(self, notifications_mask: int) -> None:
        """Initialize."""
        self.notifications_mask = notifications_mask

    def __str__(self) -> str:
        return f"{self.__class__.__name__} mask: {self.notifications_mask:02x}"

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.notifications_mask)

    @classmethod
    def from_bytes(cls, data: bytes) -> GetNotificationsMaskRsp:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        (notifications_mask,) = struct.unpack_from(cls._format, data, 2)
        return cls(notifications_mask)


class SetEnabledNotificationsMaskRsp(NotificationsUpdateBase):
    """Set Enabled Notifications Mask Response."""

    cmd_id = 0x58


class UnlockRsp(Command):
    """Unlock Response."""

    cmd_id = 0x5A
    _format = "!Bl"
    _len = struct.calcsize(_format)

    def __init__(self, error_code: ErrorCode, timeout: int):
        """Initialize."""
        self.error_code = error_code
        self.timeout = timeout

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} error: {self.error_code.name}, timeout: "
            f"{self.timeout}"
        )

    @property
    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self.error_code, self.timeout)

    @classmethod
    def from_bytes(cls, data: bytes) -> UnlockRsp:
        """Initialize from serialized representation of the command."""
        (error_code, timeout) = struct.unpack_from(cls._format, data, 2)
        return cls(ErrorCode(error_code), timeout)


COMMAND_TYPES: dict[int, type[Command]] = {
    0x00: GetIdentificationCmd,
    0x01: AuthChallengeCmd,
    0x02: AuthChallengeAcceptedCmd,
    0x04: DisconnectReqCmd,
    0x09: AssociationParametersCmd,
    0x13: NotAssociatedCmd,
    0x15: DetTypeNameCmd,
    0x17: ECDHPublicCmd,
    0x1D: NotificationsUpdateCmd,
    0x23: AuthPinChallengeCmd,
    0x25: AuthCheckCmd,
    0x35: StatusReportCmd,
    0x50: GetIdentificationRsp,
    0x51: AckRsp,
    0x57: GetNotificationsMaskRsp,
    0x58: SetEnabledNotificationsMaskRsp,
    0x5A: UnlockRsp,
}


def parse_command(data: bytes) -> Command:
    """Parse data and return Command."""
    if len(data) < 2 or (len(data) - 2) != data[1]:
        raise InvalidCommand("Invalid length", data.hex())

    if command_type := COMMAND_TYPES.get(data[0]):
        return command_type.from_bytes(data)

    return UnknownCommand.from_bytes(data)
