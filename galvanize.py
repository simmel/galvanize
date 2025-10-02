#!/usr/bin/env python3

import argparse
import concurrent.futures
import datetime
import gc
import logging
import os
import subprocess
import sys
import threading
import time
import tracemalloc

import hid
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.layers.inet import UDP

tracemalloc.start()

snapshot = tracemalloc.take_snapshot()


parser = argparse.ArgumentParser()
parser.add_argument("--debug", "-d", help="Enable debug logging", action="store_true")
args = parser.parse_args()

logging.basicConfig(
    format="%(levelname)s:%(name)s:%(threadName)s:%(message)s",
    level=logging.DEBUG if args.debug else logging.INFO,
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
                    # DEVICE.set_nonblocking(False)
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
            # if data:
            # logger.debug("%r", data)
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
    if DEVICE:
        if should_shine:
            for led in leds:
                DEVICE.write([1, led, 5, 0, 0, 255, 255, 255])
        else:
            for led in leds:
                DEVICE.write([1, led, 0, 0, 0, 255, 255, 255])


def meeting_detector():
    global IN_MEETING, snapshot
    logger.info("MeetingDetector started")
    threading.current_thread().name = (
        sys._getframe().f_code.co_name  # pylint: disable=protected-access
    )

    # sort routes by metric if one use top
    # else use conf.route
    # conf.route.route("0.0.0.0")
    # sorted(conf.route.routes, key=lambda r: r[5], reverse=True)
    _, _, _, interface, _, _ = sorted(conf.route.routes, key=lambda r: r[5], reverse=True)[0]
    logger.info("Using network interace %r", interface)
    conf.iface = interface
    md = None

    class MeetingDetector(Automaton):
        # pylint: disable=raising-bad-type
        def master_filter(self, pkt):
            should_accept = (
                UDP in pkt and pkt[UDP].dport >= 8801 and pkt[UDP].dport <= 8810
            )
            pkt = None
            return should_accept

        @ATMT.state(initial=1)
        def begin(self):
            logger.debug("State=BEGIN")
            raise self.waiting()

        @ATMT.state()
        def waiting(self):
            # logger.debug("in_meeting? %r", IN_MEETING)
            pass

        @ATMT.receive_condition(waiting)
        def chk_receive_data(self, pkt):
            raiser = self.receiving(pkt)
            pkt = None
            raise raiser

        # RECEIVED
        @ATMT.state()
        def receiving(self, _pkt):
            # logger.debug("State=receiving")
            global IN_MEETING
            IN_MEETING = True
            try:
                set_led(IN_MEETING, [3, 4, 5])
            except (OSError, AttributeError):
                logger.exception("Lost device: %r", DEVICE)
                MeetingDetector().destroy()
                MeetingDetector().run()
            _pkg = None
            raise self.waiting()

        @ATMT.timeout(waiting, 5)
        def timeout_waiting(self):
            logger.debug("State=timeout_waiting")
            global IN_MEETING
            if DEVICE and IN_MEETING:
                IN_MEETING = False
                try:
                    set_led(IN_MEETING, [3, 4, 5])
                except (OSError, AttributeError):
                    logger.exception("Lost device: %r", DEVICE)

            time_to_restart = (datetime.datetime.now() - started) > datetime.timedelta(
                minutes=10
            )
            if time_to_restart:
                logger.debug("time toooooooo")
                raise self.end()
            raise self.waiting()

        @ATMT.action(timeout_waiting)
        def retransmit_last_packet(self):
            logger.debug("hit timeout?")
            logger.debug("in meeting? %r", IN_MEETING)

        @ATMT.state(final=1)
        def end(self):
            logger.debug("State=END")

    while True:
        started = datetime.datetime.now()
        try:
            md = MeetingDetector()
            md.run()
            logger.debug("after run: %r", md)
            md.stop()
            logger.debug("after stop: %r", md)
            md.destroy()
            logger.debug("after destroy: %r", md)
        except IndexError as ex:
            logger.exception(ex)
            pass
        except Exception as ex:
            md.stop()
            md.destroy()
            logger.exception(ex)
        logger.debug("Restarting MeetingDetector")

        new_snapshot = tracemalloc.take_snapshot()
        top_stats = new_snapshot.statistics("lineno")
        print("[ Top 10 ]")
        for stat in top_stats[:10]:
            print(stat)
        top_stats = new_snapshot.compare_to(snapshot, "lineno")
        print("[ Top 10 differences ]")
        for stat in top_stats[:10]:
            print(stat)
        snapshot = new_snapshot
        gc.collect()


def main() -> None:
    logger.info("Starting up")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        a = executor.submit(meeting_detector)
        while True:
            try:
                futures = []
                futures.append(executor.submit(discovery))
                futures.append(executor.submit(worker))
                for future in concurrent.futures.as_completed(futures):
                    try:
                        logger.debug("Future result: %r", future.result())
                    except Exception:  # pylint: disable=broad-except
                        logger.exception("Exception in thread")
                if a.done():
                    logger.debug("getting a results")
                    logger.debug("Meeting detector result: %r", a.result())
            except KeyboardInterrupt:
                logger.info("Shutting down")
                os._exit(0)  # pylint: disable=protected-access


if __name__ == "__main__":
    main()
