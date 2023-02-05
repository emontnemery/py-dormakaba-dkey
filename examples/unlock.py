"""Example which unlocks a lock."""

from __future__ import annotations

import asyncio
import logging
import sys

from bleak import AdvertisementData, BleakScanner, BLEDevice
from bleak.exc import BleakError

from py_dormakaba_dkey import DKEYLock, Notifications
from py_dormakaba_dkey.models import AssociationData

_LOGGER = logger = logging.getLogger(__name__)

ADDRESS = "F0:94:0A:BD:3D:0A"


async def main(address: str) -> None:
    """Unlock a lock."""

    found_lock_evt = asyncio.Event()
    lock_device = None

    def callback(device: BLEDevice, advertising_data: AdvertisementData):
        nonlocal lock_device
        if device.address == address:
            lock_device = device
            found_lock_evt.set()

    async with BleakScanner(
        detection_callback=callback,
    ):
        await found_lock_evt.wait()

    if not lock_device:
        raise BleakError(f"A device with address {address} could not be found.")

    lock = DKEYLock(lock_device)

    key_holder_id = bytes.fromhex("2cf9002a")  # b"\xc1\x0c\x00)"
    secret = bytes.fromhex(
        "7e23fb0fe19095d996944b0428a0b2f55405e5c1a6676740d0afa8462801c4cb"
    )

    lock.set_association_data(AssociationData(key_holder_id, secret))

    def on_notifiction(notification: Notifications) -> None:
        _LOGGER.info("on_notifiction: %s", notification)

    lock.register_callback(on_notifiction)
    await lock.unlock()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("bleak.backends.bluezdbus.manager").setLevel(logging.WARNING)
    asyncio.run(main(sys.argv[1] if len(sys.argv) == 2 else ADDRESS))
