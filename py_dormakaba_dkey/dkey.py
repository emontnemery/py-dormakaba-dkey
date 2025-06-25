"""Dormakaba DKEY Manager"""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from collections import deque
from collections.abc import Callable
import logging
import os
from typing import TypeVar, cast

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak_retry_connector import (
    BLEAK_RETRY_EXCEPTIONS,
    BleakClientWithServiceCache,
    establish_connection,
    retry_bluetooth_connection_error,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import commands as cmds
from .commands import _CMD_T, Command, LockMode, Notifications, parse_command
from .crypto import AESCrypto, TripleAESCrypto
from .errors import (
    CommandFailed,
    Disconnected,
    DkeyError,
    InvalidActivationCode,
    InvalidCommand,
    NotAssociated,
    NotAuthenticated,
    NotConnected,
    Timeout,
    UnsupportedProtocolVersion,
    WrongActivationCode,
)
from .models import AssociationData, DeviceInfo, DisconnectReason, ErrorCode

_LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")

ADDRESS = "F0:94:0A:BD:3D:0A"

SERVICE_UUID = "e7a60000-6639-429f-94fd-86de8ea26897"
CHARACTERISTIC_UUID_TO_SERVER = "e7a60001-6639-429f-94fd-86de8ea26897"
CHARACTERISTIC_UUID_FROM_SERVER = "e7a60002-6639-429f-94fd-86de8ea26897"

# Enable to debug framing and deframing of commands
DEBUG_COMMAND_FRAMING = True

# Enable to debug decrypt/encrypt of commands
DEBUG_COMMAND_CRYPT = True

DISCONNECT_DELAY = 30

DEFAULT_ATTEMPTS = 3

ACTIVATION_CODE_ALLOWED = "BCDFGHJKLMNPQRSTVWXZ0123456789"

SUPPORTED_PROTOCOL_VERSIONS = (26, 27, 28)


def device_filter(advertisement_data: AdvertisementData) -> bool:
    """Return True if the device is supported."""
    uuids = advertisement_data.service_uuids
    if SERVICE_UUID in uuids or CHARACTERISTIC_UUID_TO_SERVER in uuids:
        return True

    return False


class BaseProcedure(ABC):
    """Base class for procedures."""

    enable_notifications: bool = False
    need_auth: bool = False

    def __init__(self, lock: DKEYLock) -> None:
        """Initialize."""
        self._lock = lock

    @abstractmethod
    async def execute(self) -> bool:
        """Execute the procedure"""


class AssociateProcedure(BaseProcedure):
    """Associate with a lock."""

    # Associate procedure:
    # -> GetIdentificationCmd
    # <- GetIdentificationRsp
    # <- GetIdentificationCmd
    # -> GetIdentificationRsp
    # -> RequestChallengeCmd
    # <- AuthPinChallengeCmd
    # -> AckRsp
    # -> AuthPinChallengeReplyCmd
    # <- AckRsp (SUCCESS | WRONG_PIN)
    # - ENABLE ENCRYPTION -
    # <- AuthCheckCmd
    # -> AckRsp
    # <- ECDHPublicCmd
    # -> AckRsp
    # -> ECDHPublicReplyCmd
    # <- AckRsp
    # <- AssociationParametersCmd

    def __init__(self, lock: DKEYLock, activation_code: str) -> None:
        """Initialize."""
        super().__init__(lock)
        self._activation_code = activation_code
        self.key_holder_id: bytes | None = None
        self.secret: bytes | None = None

    async def execute(self) -> bool:
        """Execute the procedure"""
        iv_last_bytes = os.urandom(4)

        ident_cmd_fut = self._lock.receive_once(cmds.GetIdentificationCmd)
        ident_rsp_fut = self._lock.receive_once(cmds.GetIdentificationRsp)
        await self._lock.send_cmd(cmds.GetIdentificationCmd(iv_last_bytes))
        await asyncio.gather(ident_cmd_fut, ident_rsp_fut)
        self._lock.on_identification(ident_rsp_fut.result())

        # Set key holder id to -2 to trigger association sequence
        await self._lock.send_cmd(
            cmds.GetIdentificationRsp.defaults(bytes.fromhex("fffffffe"))
        )

        auth_challenge_fut = self._lock.receive_once(cmds.AuthPinChallengeCmd)
        await self._lock.send_cmd(cmds.RequestChallengeCmd.defaults())
        await auth_challenge_fut
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.AuthPinChallengeCmd.cmd_id)
        )
        iv_lock = auth_challenge_fut.result().nonce

        crypto = AESCrypto(iv_lock, iv_last_bytes, self._activation_code)
        reply = crypto.handle_auth_pin_challenge()

        ack_fut = self._lock.receive_once(cmds.AckRsp)
        auth_check_fut = self._lock.receive_once(cmds.AuthCheckCmd)
        self._lock.set_crypto(crypto, 2)
        await self._lock.send_cmd(cmds.AuthPinChallengeReplyCmd(reply))
        await ack_fut
        if ack_fut.result().error_code != ErrorCode.SUCCESS:
            auth_check_fut.cancel()
            if ack_fut.result().error_code == ErrorCode.WRONG_PIN:
                raise WrongActivationCode
            raise CommandFailed(ack_fut.result().error_code)
        await auth_check_fut
        ecdh_public_fut = self._lock.receive_once(cmds.ECDHPublicCmd)
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.AuthCheckCmd.cmd_id)
        )
        await ecdh_public_fut
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.ECDHPublicCmd.cmd_id)
        )

        peer_public_key = ecdh_public_fut.result().public_key
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        _LOGGER.debug(
            "%s: Private key: %s",
            self._lock.name,
            private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).hex(),
        )
        association_params_fut = self._lock.receive_once(cmds.AssociationParametersCmd)
        await self._lock.send_cmd(cmds.ECDHPublicReplyCmd(public_key))
        await association_params_fut
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.AssociationParametersCmd.cmd_id)
        )

        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        _LOGGER.debug("%s: Shared secret: %s", self._lock.name, shared_secret.hex())

        iv = crypto.iv
        key = shared_secret[0:16]
        msg = association_params_fut.result().secret
        encryptor = Cipher(algorithms.AES128(key), modes.CFB(iv)).encryptor()
        _hash = encryptor.update(msg) + encryptor.finalize()

        self.key_holder_id = association_params_fut.result().key_holder_id
        self.secret = _hash + shared_secret[16:]

        _LOGGER.debug("%s: Hash: %s", self._lock.name, _hash.hex())

        det_type_name_fut = self._lock.receive_once(cmds.DetTypeNameCmd)
        await det_type_name_fut
        self._lock.on_lock_type_name(det_type_name_fut.result())
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.DetTypeNameCmd.cmd_id)
        )

        return True


class AuthenticateProcedure(BaseProcedure):
    """Authenticate with a lock."""

    # Auth procedure:
    # -> GetIdentificationCmd
    # <- GetIdentificationRsp
    # <- GetIdentificationCmd
    # -> GetIdentificationRsp
    # <- AuthChallengeCmd | NotAssociatedCmd
    # -> AuthChallengeRsp
    # - ENABLE ENCRYPTION -
    # <- AuthChallengeAcceptedCmd
    # -> AckRsp
    # <- DetTypeNameCmd
    # -> AckRsp

    def __init__(self, lock: DKEYLock, key_holder_id: bytes, secret: bytes) -> None:
        """Initialize."""
        super().__init__(lock)
        self._key_holder_id = key_holder_id
        self._secret = secret

    async def execute(self) -> bool:
        """Execute the procedure"""
        iv_last_bytes = os.urandom(4)

        ident_cmd_fut = self._lock.receive_once(cmds.GetIdentificationCmd)
        ident_rsp_fut = self._lock.receive_once(cmds.GetIdentificationRsp)
        await self._lock.send_cmd(cmds.GetIdentificationCmd(iv_last_bytes))
        await asyncio.gather(ident_cmd_fut, ident_rsp_fut)
        self._lock.on_identification(ident_rsp_fut.result())

        auth_challenge_fut = self._lock.receive_once(cmds.AuthChallengeCmd)
        not_associated_fut = self._lock.receive_once(cmds.NotAssociatedCmd)
        await self._lock.send_cmd(
            cmds.GetIdentificationRsp.defaults(self._key_holder_id)
        )

        done, pending = await asyncio.wait(
            (auth_challenge_fut, not_associated_fut),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if isinstance(done.pop().result(), cmds.NotAssociatedCmd):
            raise NotAssociated

        iv_lock = auth_challenge_fut.result().nonce
        crypto = TripleAESCrypto(iv_lock, iv_last_bytes, self._secret)
        reply = crypto.handle_auth_challenge()
        _LOGGER.debug("%s: Auth reply: %s", self._lock.name, reply.hex())

        auth_challenge_accepted_fut = self._lock.receive_once(
            cmds.AuthChallengeAcceptedCmd
        )
        self._lock.set_crypto(crypto, 1)
        await self._lock.send_cmd(cmds.AuthChallengeRsp(reply))

        await auth_challenge_accepted_fut
        _LOGGER.debug("%s: Challenge accepted", self._lock.name)
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.AuthChallengeAcceptedCmd.cmd_id)
        )

        det_type_name_fut = self._lock.receive_once(cmds.DetTypeNameCmd)
        await det_type_name_fut
        self._lock.on_lock_type_name(det_type_name_fut.result())
        await self._lock.send_cmd(
            cmds.AckRsp(ErrorCode.SUCCESS, cmds.DetTypeNameCmd.cmd_id)
        )

        return True


class EnableNotificationsProcedure(BaseProcedure):
    """Enable notifications on a lock."""

    need_auth = True
    # Enable notification procedure:
    # -> GetNotificationsMaskCmd
    # <- GetNotificationsMaskRsp
    # -> SetEnabledNotificationsMaskCmd
    # <- SetEnabledNotificationsMaskRsp
    # <- NotificationsUpdateCmd

    async def execute(self) -> bool:
        """Execute the procedure"""

        def handle_status_report(
            cmd: cmds.StatusReportCmd,
        ) -> None:
            asyncio.create_task(
                self._lock.send_cmd(
                    cmds.AckRsp(ErrorCode.SUCCESS, cmds.StatusReportCmd.cmd_id)
                )
            )

        def handle_notification_update(
            cmd: cmds.NotificationsUpdateCmd,
        ) -> None:
            asyncio.create_task(
                self._lock.send_cmd(
                    cmds.AckRsp(ErrorCode.SUCCESS, cmds.NotificationsUpdateCmd.cmd_id)
                )
            )
            self._lock.on_notification(cmd.notifications)

        def handle_disconnect_request(
            cmd: cmds.DisconnectReqCmd,
        ) -> None:
            asyncio.create_task(
                self._lock.send_cmd(
                    cmds.AckRsp(ErrorCode.SUCCESS, cmds.DisconnectReqCmd.cmd_id)
                )
            )
            self._lock.on_disconnect_req()

        self._lock.receive_notifications(
            cmds.DisconnectReqCmd, handle_disconnect_request
        )
        self._lock.receive_notifications(
            cmds.NotificationsUpdateCmd, handle_notification_update
        )
        self._lock.receive_notifications(cmds.StatusReportCmd, handle_status_report)

        notifications_mask_fut = self._lock.receive_once(cmds.GetNotificationsMaskRsp)
        await self._lock.send_cmd(cmds.GetNotificationsMaskCmd())
        await notifications_mask_fut

        enabled_notifications_fut = self._lock.receive_once(
            cmds.SetEnabledNotificationsMaskRsp
        )
        await self._lock.send_cmd(cmds.SetEnabledNotificationsMaskCmd(0x7F))
        # Nothing
        # await self._lock.send_cmd(SetEnabledNotificationsMaskCmd(0x01))
        # Door_position
        # await self._lock.send_cmd(SetEnabledNotificationsMaskCmd(0x02))
        # unlock status
        # await self._lock.send_cmd(SetEnabledNotificationsMaskCmd(0x04))
        await enabled_notifications_fut
        self._lock.on_notification(enabled_notifications_fut.result().notifications)

        return True


class ChangeModeProcedure(BaseProcedure):
    """Change mode of a lock."""

    enable_notifications = True
    need_auth = True

    # Change mode procedure:
    # -> ChangeModeCmd
    # <- StatusReportCmd (if lock/unlock)

    def __init__(self, lock: DKEYLock, mode: cmds.LockMode) -> None:
        """Initialize."""
        super().__init__(lock)
        self._mode = mode

    async def execute(self) -> bool:
        """Execute the procedure"""

        await self._lock.send_cmd(cmds.ChangeModeCmd(self._mode))

        return True


class UnlockProcedure(BaseProcedure):
    """Unlock a lock."""

    enable_notifications = True
    need_auth = True

    # Unlock procedure:
    # -> UnlockCmd
    # <- UnlockRsp
    # <- StatusReportCmd

    async def execute(self) -> bool:
        """Execute the procedure"""
        unlock_rsp_fut = self._lock.receive_once(cmds.UnlockRsp)
        await self._lock.send_cmd(cmds.UnlockCmd.defaults())
        await unlock_rsp_fut

        return True


class NullProcedure(BaseProcedure):
    """Do nothing."""

    enable_notifications = True
    need_auth = True

    async def execute(self) -> bool:
        """Execute the procedure"""
        return True


class DKEYLock:
    """Manage a Dormakaba DKEY lock."""

    _key_holder_id: bytes | None = None
    _secret: bytes | None = None

    def __init__(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData | None = None
    ):
        """Initialize."""
        self._advertisement_data = advertisement_data
        self._authenticated: bool = False
        self._ble_device = ble_device
        self._callbacks: list[Callable[[cmds.Notifications], None]] = []
        self._client: BleakClient | None = None
        self._command_handlers: dict[int, Callable[[Command], None]] = {}
        self._command_handlers_oneshot: dict[int, asyncio.Future[Command]] = {}
        self._connect_lock: asyncio.Lock = asyncio.Lock()
        self._crypto: AESCrypto | TripleAESCrypto | None = None
        self._crypto_delay: int = 0
        self._disconnect_reason: DisconnectReason | None = None
        self._disconnect_timer: asyncio.TimerHandle | None = None
        self._expected_disconnect: bool = False
        self._notifications_enabled: bool = False
        self._procedure_lock: asyncio.Lock = asyncio.Lock()
        self._rx_segment: bytearray | None = None
        self._rx_segment_cmd_id: int | None = None
        self._tx_queue: deque[tuple[str, bytes]] = deque()
        self.loop = asyncio.get_running_loop()
        self.device_info = DeviceInfo()
        self.state: Notifications = Notifications()

    def set_ble_device_and_advertisement_data(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Set the ble device."""
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data

    @property
    def address(self) -> str:
        """Get the address of the device."""
        return str(self._ble_device.address)

    @property
    def battery_level(self) -> int | None:
        """Get the battery level of the device."""
        battery_level = self.state.battery

        if battery_level is None:
            return None
        if battery_level >= 28:
            return 100
        if battery_level >= 25:
            return 75
        if battery_level >= 23:
            return 50
        if battery_level >= 20:
            return 25
        if battery_level > 17:
            return 5
        if battery_level > 0:
            return 1
        return 0

    @property
    def battery_criticl(self) -> bool | None:
        """Return True if the battery level is critically low."""
        if (battery_level := self.state.battery) is None:
            return None
        return battery_level <= 17

    @property
    def battery_warning(self) -> bool | None:
        """Return True if the battery level is low."""
        if (battery_level := self.state.battery) is None:
            return None
        return battery_level < 20

    @property
    def name(self) -> str:
        """Get the name of the device."""
        return str(self._ble_device.name or self._ble_device.address)

    @property
    def rssi(self) -> int | None:
        """Get the rssi of the device."""
        if self._advertisement_data:
            return self._advertisement_data.rssi
        return None

    def set_association_data(self, association_data: AssociationData) -> None:
        """Set key holder id and secret."""
        _LOGGER.debug(
            "%s: Set association data %s", self.name, association_data.to_json()
        )
        self._key_holder_id = association_data.key_holder_id
        self._secret = association_data.secret

    @staticmethod
    def _validate_activation_code(activation_code: str) -> str:
        """Validate the activation code, raises if it's not valid."""
        trans = str.maketrans("", "", "- \t")
        activation_code = activation_code.translate(trans)
        activation_code = activation_code.upper()
        if any(c not in ACTIVATION_CODE_ALLOWED for c in activation_code):
            raise InvalidActivationCode
        return activation_code

    async def associate(self, activation_code: str) -> AssociationData:
        """Associate with the lock."""
        _LOGGER.debug("%s: Associate %s", self.name, activation_code)
        activation_code = self._validate_activation_code(activation_code)
        associate_proc = AssociateProcedure(self, activation_code)
        if (
            not await self._execute(associate_proc)
            or associate_proc.key_holder_id is None
            or associate_proc.secret is None
        ):
            raise DkeyError
        association_data = AssociationData(
            associate_proc.key_holder_id, associate_proc.secret
        )
        self.set_association_data(association_data)
        return association_data

    async def connect(self) -> None:
        """Connect the lock.

        Note: A connection is automatically established when performing an operation
        on the lock. This can be called to ensure the lock is in range.
        """
        _LOGGER.debug("%s: Connect", self.name)
        await self._ensure_connected()

    async def disconnect(self) -> None:
        """Disconnect from the lock."""
        _LOGGER.debug("%s: Disconnect", self.name)
        await self._execute_disconnect(DisconnectReason.USER_REQUESTED)

    def _fire_callbacks(self, notifications: Notifications) -> None:
        """Fire the callbacks."""
        _LOGGER.debug("_fire_callbacks")
        for callback in self._callbacks:
            callback(notifications)

    def register_callback(
        self, callback: Callable[[Notifications], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when the state changes."""

        def unregister_callback() -> None:
            self._callbacks.remove(callback)

        self._callbacks.append(callback)
        return unregister_callback

    async def lock(self) -> bool:
        """Lock the lock."""
        _LOGGER.debug("%s: Lock", self.name)
        change_mode_proc = ChangeModeProcedure(self, LockMode.LOCK_MODE)
        return await self._execute(change_mode_proc)

    async def set_mode(self, mode: LockMode) -> bool:
        """Lock the lock."""
        _LOGGER.debug("%s: Set mode %s", self.name, mode.name)
        change_mode_proc = ChangeModeProcedure(self, mode)
        return await self._execute(change_mode_proc)

    async def unlock(self) -> bool:
        """Unlock the lock."""
        _LOGGER.debug("%s: Unlock", self.name)
        unlock_proc = UnlockProcedure(self)
        return await self._execute(unlock_proc)

    async def update(self) -> bool:
        """Update the lock's status."""
        _LOGGER.debug("%s: Update", self.name)
        null_proc = NullProcedure(self)
        return await self._execute(null_proc)

    @retry_bluetooth_connection_error(DEFAULT_ATTEMPTS)  # type: ignore[misc]
    async def _execute(self, procedure: BaseProcedure) -> bool:
        """Execute a procedure."""
        if self._procedure_lock.locked():
            _LOGGER.debug(
                "%s: Procedure already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        async with self._procedure_lock:
            try:
                if procedure.need_auth:
                    await self._enable_notifications_when_locked()
                else:
                    await self._ensure_connected()
                result = await procedure.execute()
                return result
            except asyncio.CancelledError as err:
                if self._disconnect_reason is None:
                    raise DkeyError from err
                if self._disconnect_reason == DisconnectReason.TIMEOUT:
                    raise Timeout from err
                raise Disconnected(self._disconnect_reason) from err
            except DkeyError:
                self._disconnect(DisconnectReason.ERROR)
                raise

    async def _enable_notifications_when_locked(self) -> None:
        """Enable notifications."""
        await self._ensure_authenticated()
        if self._notifications_enabled:
            return
        notify_proc = EnableNotificationsProcedure(self)
        await notify_proc.execute()
        self._notifications_enabled = True

    async def _ensure_authenticated(self) -> None:
        """Ensure we're authenticated with the lock."""
        await self._ensure_connected()
        if self._authenticated:
            return

        if self._key_holder_id is None or self._secret is None:
            raise NotAuthenticated
        auth_proc = AuthenticateProcedure(self, self._key_holder_id, self._secret)
        await auth_proc.execute()
        self._authenticated = True

    async def _ensure_connected(self) -> None:
        """Ensure connection to device is established."""
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        if self._client and self._client.is_connected:
            self._reset_disconnect_timer()
            return
        async with self._connect_lock:
            # Check again while holding the lock
            if self._client and self._client.is_connected:
                self._reset_disconnect_timer()
                return
            _LOGGER.debug("%s: Connecting; RSSI: %s", self.name, self.rssi)
            client = await establish_connection(
                BleakClientWithServiceCache,
                self._ble_device,
                self.name,
                self._disconnected,
                use_services_cache=True,
                ble_device_callback=lambda: self._ble_device,
            )
            await client.pair()
            _LOGGER.debug("%s: Connected; RSSI: %s", self.name, self.rssi)
            # services = client.services
            # for service in services:
            #    _LOGGER.debug("%s:service: %s", self.name, service.uuid)
            #    characteristics = service.characteristics
            #    for char in characteristics:
            #        _LOGGER.debug("%s:characteristic: %s", self.name, char.uuid)
            # resolved = self._resolve_characteristics(client.services)
            # if not resolved:
            #    # Try to handle services failing to load
            #    resolved = self._resolve_characteristics(await client.get_services())

            self._client = client
            self._disconnect_reason = None
            self._reset_disconnect_timer()

            _LOGGER.debug(
                "%s: Subscribe to notifications; RSSI: %s", self.name, self.rssi
            )
            await client.start_notify(
                CHARACTERISTIC_UUID_TO_SERVER, self._notification_handler
            )
            await client.start_notify(
                CHARACTERISTIC_UUID_FROM_SERVER, self._notification_handler
            )

    def _raise_if_not_connected(self) -> None:
        """Raise if the connection to device is lost."""
        if self._client and self._client.is_connected:
            self._reset_disconnect_timer()
            return
        raise NotConnected

    def _reset_disconnect_timer(self) -> None:
        """Reset disconnect timer."""
        if self._disconnect_timer:
            self._disconnect_timer.cancel()
        self._expected_disconnect = False
        self._disconnect_timer = self.loop.call_later(
            DISCONNECT_DELAY, self._timed_disconnect
        )

    def _disconnected(self, client: BleakClient) -> None:
        """Disconnected callback."""
        if self._expected_disconnect:
            _LOGGER.debug(
                "%s: Disconnected from device; RSSI: %s", self.name, self.rssi
            )
            return
        _LOGGER.warning(
            "%s: Device unexpectedly disconnected; RSSI: %s",
            self.name,
            self.rssi,
        )
        self._client = None
        self._disconnect(DisconnectReason.UNEXPECTED)

    def _timed_disconnect(self) -> None:
        """Disconnect from device."""
        self._disconnect_timer = None
        asyncio.create_task(self._execute_timed_disconnect())

    async def _execute_timed_disconnect(self) -> None:
        """Execute timed disconnection."""
        _LOGGER.debug(
            "%s: Disconnecting after timeout of %s",
            self.name,
            DISCONNECT_DELAY,
        )
        await self._execute_disconnect(DisconnectReason.TIMEOUT)

    def _disconnect(self, reason: DisconnectReason) -> None:
        """Disconnect from device."""
        asyncio.create_task(self._execute_disconnect(reason))

    async def _execute_disconnect(self, reason: DisconnectReason) -> None:
        """Execute disconnection."""
        _LOGGER.debug("%s: Execute disconnect", self.name)
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        async with self._connect_lock:
            client = self._client
            self._client = None
            if client and client.is_connected:
                self._expected_disconnect = True
                await client.stop_notify(CHARACTERISTIC_UUID_TO_SERVER)
                await client.stop_notify(CHARACTERISTIC_UUID_FROM_SERVER)
                await client.disconnect()
            self._reset(reason)
        _LOGGER.debug("%s: Execute disconnect done", self.name)

    def _reset(self, reason: DisconnectReason) -> None:
        """Reset."""
        _LOGGER.debug("%s: reset", self.name)
        self._authenticated = False
        self._command_handlers = {}
        for fut in self._command_handlers_oneshot.values():
            fut.cancel()
        self._command_handlers_oneshot = {}
        self._crypto = None
        self._crypto_delay = 0
        self._disconnect_reason = reason
        if self._disconnect_timer:
            self._disconnect_timer.cancel()
        self._disconnect_timer = None
        self._notifications_enabled = False
        self._rx_segment = None
        self._rx_segment_cmd_id = None
        self._tx_queue.clear()

    async def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytes
    ) -> None:
        """Notification handler."""
        self._reset_disconnect_timer()
        if self._crypto and self._crypto_delay:
            self._crypto_delay -= 1
        elif self._crypto and not self._crypto_delay:
            if DEBUG_COMMAND_CRYPT:
                _LOGGER.debug("RX ct: %02x: %s", characteristic.handle, data.hex())
            try:
                data = self._crypto.decrypt_incoming(data)
            except InvalidCommand as err:
                _LOGGER.warning("Could not decrypt received data %s", err)
                self._disconnect(DisconnectReason.INVALID_COMMAND)
                return
            # Validate and truncate padded decrypted packet
            if not (data[0] & 0x80):
                if data[1] > 16:
                    _LOGGER.warning("Received invalid command %s", data.hex())
                    self._disconnect(DisconnectReason.INVALID_COMMAND)
                    return
                data = data[0 : data[1] + 2]

        if len(data) < 2:
            _LOGGER.warning("Received invalid command %s", data.hex())
            self._disconnect(DisconnectReason.INVALID_COMMAND)
            return

        if data[0] & 0x80:
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug(
                    "RX: segment: %02x: %s", characteristic.handle, data.hex()
                )
            # Segmented packet
            if not self._rx_segment:
                self._rx_segment = bytearray()
                self._rx_segment_cmd_id = data[0] & 0x7F
            if self._rx_segment_cmd_id != data[0] & 0x7F:
                _LOGGER.warning(
                    "RX: got %s, expected %s", data[0] & 0x7F, self._rx_segment_cmd_id
                )
                self._disconnect(DisconnectReason.INVALID_COMMAND)
                return

            segment_len = 15
            self._rx_segment.extend(data[1 : segment_len + 2])
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug("RX: appending %s", data[1:segment_len].hex())

            # ACK the segment
            try:
                await self.send_cmd(
                    cmds.AckRsp(ErrorCode.SUCCESS, self._rx_segment_cmd_id)
                )
            except BLEAK_RETRY_EXCEPTIONS:
                _LOGGER.warning("Failed to send ACK, disconnecting")
                self._disconnect(DisconnectReason.TIMEOUT)

            return

        if self._rx_segment:
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug(
                    "RX: segment: %02x: %s", characteristic.handle, data.hex()
                )
            if self._rx_segment_cmd_id != data[0]:
                _LOGGER.warning(
                    "RX: got %s, expected %s", data[0] & 0x7F, self._rx_segment_cmd_id
                )
                self._disconnect(DisconnectReason.INVALID_COMMAND)
                return

            segment_len = data[1]
            self._rx_segment.extend(data[2 : segment_len + 2])
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug("RX: appending %s", data[2:segment_len].hex())

            # Assemble the completed package
            data = data[0:1] + bytes((len(self._rx_segment),)) + self._rx_segment
            self._rx_segment = None
            self._rx_segment_cmd_id = None

        _LOGGER.debug("RX: %02x: %s", characteristic.handle, data.hex())

        try:
            command = parse_command(data)
        except InvalidCommand as err:
            _LOGGER.warning("Received invalid command %s", err)
            self._disconnect(DisconnectReason.INVALID_COMMAND)
            return
        _LOGGER.debug("RX: %s (%s)", command, command.cmd_id)
        if command_handler := self._command_handlers.get(command.cmd_id):
            command_handler(command)
        if fut := self._command_handlers_oneshot.pop(command.cmd_id, None):
            if fut and not fut.done():
                fut.set_result(command)

    def _fragmentize(self, dest: str, cmd_id: int, data: bytes) -> None:
        """Split a command in fragments and enqueue them."""
        mtu = 16 if self._crypto and not self._crypto_delay else 20
        size = len(data)
        pos = 0

        while True:
            if (remain := size - pos) <= mtu:
                fragment_size = remain
                fragment_head = bytes((cmd_id, fragment_size))
            else:
                fragment_size = mtu - 1
                fragment_head = bytes((cmd_id | 0x80,))
            fragment = fragment_head + data[pos : pos + fragment_size]
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug("TX: enqueue fragment %s", fragment.hex())
            self._tx_queue.append((dest, fragment))
            pos += fragment_size
            if pos >= size:
                break

    async def send_cmd(self, command: Command) -> None:
        """Send a command."""
        if command.cmd_id >= 0x50:
            char_specifier = CHARACTERISTIC_UUID_FROM_SERVER
        else:
            char_specifier = CHARACTERISTIC_UUID_TO_SERVER
        data = command.as_bytes
        _LOGGER.debug("TX: %s", command)
        _LOGGER.debug("TX: %s: %s", char_specifier, data.hex())

        self._fragmentize(char_specifier, data[0], data[2:])

        crypto_enabled = self._crypto and not self._crypto_delay
        if self._crypto and self._crypto_delay:
            self._crypto_delay -= 1
        while self._tx_queue:
            dest, frag = self._tx_queue.popleft()
            if DEBUG_COMMAND_FRAMING:
                _LOGGER.debug("TX: send fragment %s", frag.hex())
            got_fragment_ack: asyncio.Future[cmds.AckRsp] | None = None
            if frag[0] & 0x80:
                got_fragment_ack = self.receive_once(cmds.AckRsp)
            if self._crypto and crypto_enabled:
                frag = self._crypto.encrypt_send(frag)
                if DEBUG_COMMAND_CRYPT:
                    _LOGGER.debug("TX ct: %s: %s", dest, frag.hex())
            self._raise_if_not_connected()
            assert self._client
            await self._client.write_gatt_char(dest, frag, True)
            if got_fragment_ack:
                if DEBUG_COMMAND_FRAMING:
                    _LOGGER.debug("TX: wait fragment ack")
                await got_fragment_ack

    def on_disconnect_req(self) -> None:
        """Handle disconnect request from the lock."""
        asyncio.create_task(self._execute_disconnect(DisconnectReason.LOCK_REQUESTED))

    def on_identification(self, identification: cmds.GetIdentificationRsp) -> None:
        """Handle identification from the lock."""
        if identification.protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise UnsupportedProtocolVersion(identification.protocol_version)
        self.device_info.sw_version = identification.sw_version
        self.device_info.device_id = f"{identification.key_holder_id.hex()}"

    def on_lock_type_name(self, type_name: cmds.DetTypeNameCmd) -> None:
        """Handle type and name of the lock."""
        self.device_info.device_name = type_name.device_name

    def on_notification(self, notifications: Notifications) -> None:
        """Handle status notifications from the lock."""
        self.state.update(notifications)
        _LOGGER.debug("Lock state: %s", self.state)
        self._fire_callbacks(notifications)

    def receive_notifications(
        self, cmd: type[_CMD_T], callback: Callable[[_CMD_T], None]
    ) -> None:
        """Receive a command or response."""
        self._command_handlers[cmd.cmd_id] = cast(Callable[[Command], None], callback)

    def receive_once(self, cmd: type[_CMD_T]) -> asyncio.Future[_CMD_T]:
        """Receive a command or response once."""
        fut: asyncio.Future[_CMD_T] = asyncio.Future()
        self._command_handlers_oneshot[cmd.cmd_id] = cast(asyncio.Future[Command], fut)
        return fut

    def set_crypto(self, crypto: AESCrypto | TripleAESCrypto, crypto_delay: int):
        """Set crypto."""
        self._crypto = crypto
        self._crypto_delay = crypto_delay
