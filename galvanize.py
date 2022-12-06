#!/usr/bin/env python3

import concurrent.futures
import logging
import os
import sys
import threading
import time

import hid

logging.basicConfig(
    format="%(levelname)s:%(threadName)s:%(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)
DEVICE = None


def discovery() -> None:
    global DEVICE
    threading.current_thread().name = (
        sys._getframe().f_code.co_name  # pylint: disable=protected-access
    )
    while True:
        if DEVICE:
            try:
                DEVICE.get_product_string()
            except OSError:
                logger.exception("Device is probably disconnected")
                DEVICE = None
        else:
            if hid.enumerate(vendor_id=0x04D8, product_id=0xF372):
                logger.debug("Found device, trying to open")
                try:
                    DEVICE = hid.device()
                    DEVICE.open(vendor_id=0x04D8, product_id=0xF372)
                    logger.info("Device found: %r", DEVICE)
                    break
                except OSError:
                    logger.debug("Failed to open device")
            logger.info("Device not found: %r", DEVICE)
            DEVICE = None
            time.sleep(5)


def main() -> None:
    logger.info("lol")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        try:
            while True:
                executor.submit(discovery).result()
        except KeyboardInterrupt:
            logger.info("Shutting down")
            os._exit(0)  # pylint: disable=protected-access


if __name__ == "__main__":
    main()
