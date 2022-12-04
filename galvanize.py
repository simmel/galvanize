#!/usr/bin/env python3

import logging

logging.basicConfig(
    format="%(levelname)s:%(threadName)s:%(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("lol")


if __name__ == "__main__":
  main()
