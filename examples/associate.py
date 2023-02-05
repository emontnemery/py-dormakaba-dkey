"""Example which associates with a lock."""

from __future__ import annotations

import asyncio
import logging
import sys

from bleak import AdvertisementData, BleakScanner, BLEDevice
from bleak.exc import BleakError

from py_dormakaba_dkey import DKEYLock

ADDRESS = "F0:94:0A:BD:3D:0A"

_LOGGER = logging.getLogger(__name__)


async def main(address: str) -> None:
    """Associate with a lock."""

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

    activation_code = "m8ll-41s4"
    associationdata = await lock.associate(activation_code)
    _LOGGER.info(
        "Association data: %s",
        associationdata.to_json() if associationdata else "<None>",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("bleak.backends.bluezdbus.manager").setLevel(logging.WARNING)
    asyncio.run(main(sys.argv[1] if len(sys.argv) == 2 else ADDRESS))
