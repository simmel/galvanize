#!/usr/bin/env python3

import concurrent.futures
import logging
import os
import subprocess
import sys
import threading
import time

import hid
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.layers.inet import UDP

logging.basicConfig(
    format="%(levelname)s:%(name)s:%(threadName)s:%(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)
DEVICE = None
IN_MEETING = False


def discovery() -> None:
    global DEVICE
    threading.current_thread().name = (
        sys._getframe().f_code.co_name  # pylint: disable=protected-access
    )
    logger.info("Waiting for device")
    while True:
        if DEVICE:
            try:
                DEVICE.get_product_string()
            except OSError:
                logger.debug("Device is probably disconnected")
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
            logger.debug("Device not found: %r", DEVICE)
            DEVICE = None
            time.sleep(5)


def worker() -> None:
    threading.current_thread().name = (
        sys._getframe().f_code.co_name  # pylint: disable=protected-access
    )
    try:
        is_muted = get_muted()
        logger.debug(is_muted)
        set_led(is_muted, [6, 1, 2])
        while True:
            data = DEVICE.read(0x8, 500)
            if data:
                logger.debug("%r", data)
            if data == [131, 1, 0, 0, 0, 0, 0, 0]:
                is_muted = get_muted()
                should_mute = not is_muted
                set_led(should_mute, [6, 1, 2])
                set_muted(should_mute)
    except OSError:
        logger.info("Lost device: %r", DEVICE)


def get_muted():
    pactl = subprocess.run(
        ["pactl", "get-source-mute", "@DEFAULT_SOURCE@"],
        capture_output=True,
        check=True,
    )
    logger.debug(pactl)
    return pactl.stdout == b"Mute: yes\n"


def set_muted(should_mute):
    pactl = subprocess.run(
        ["pactl", "set-source-mute", "@DEFAULT_SOURCE@", str(should_mute)], check=True
    )
    logger.info(pactl)


def set_led(should_shine, leds):
    if should_shine:
        for led in leds:
            DEVICE.write([1, led, 5, 0, 0, 255, 255, 255])
    else:
        for led in leds:
            DEVICE.write([1, led, 0, 0, 0, 255, 255, 255])


def main() -> None:
    logger.info("Starting up")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        try:
            while True:
                executor.submit(discovery).result()
                executor.submit(worker).result()
        except KeyboardInterrupt:
            logger.info("Shutting down")
            os._exit(0)  # pylint: disable=protected-access


if __name__ == "__main__":
    main()
