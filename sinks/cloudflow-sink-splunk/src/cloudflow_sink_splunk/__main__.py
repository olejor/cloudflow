"""CLI entry point: cloudflow-sink-splunk -c <config> [--stdout] [--once]."""

from __future__ import annotations

import argparse
import signal
import sys

from . import config as config_mod
from .consumer import Consumer, connect_redis
from .deadletter import DeadLetterWriter
from .hec import HecClient, StdoutSink
from .metrics import JsonLogger, Metrics


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloudflow-sink-splunk")
    parser.add_argument("-c", "--config", required=True, help="path to sink YAML config")
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print HEC-shaped JSON lines instead of POSTing to Splunk",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="process what is currently pending, then exit (for tests/milestone checks)",
    )
    return parser


def run(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    cfg = config_mod.load(args.config)
    logger = JsonLogger(cfg.service.name)
    metrics = Metrics(cfg.service.name, logger=logger)

    logger.info(
        "starting",
        consumer_name=cfg.service.consumer_name,
        streams=cfg.redis.streams,
        stdout_mode=args.stdout,
        once=args.once,
    )

    redis_client = connect_redis(cfg.redis)

    if args.stdout:
        sink = StdoutSink(stream=sys.stdout, metrics=metrics)
    else:
        sink = HecClient(cfg.splunk, metrics=metrics, logger=logger)

    deadletter = DeadLetterWriter(redis_client, metrics=metrics, logger=logger)

    consumer = Consumer(
        redis_client=redis_client,
        redis_config=cfg.redis,
        splunk_config=cfg.splunk,
        sink=sink,
        deadletter=deadletter,
        metrics=metrics,
        consumer_name=cfg.service.consumer_name,
        logger=logger,
    )

    def _handle_sigterm(signum, frame):  # noqa: ARG001
        logger.info("received SIGTERM, flushing and exiting")
        consumer.stop()

    signal.signal(signal.SIGTERM, _handle_sigterm)

    if args.once:
        consumer.run_once()
        metrics.emit()
    else:
        consumer.run_forever()  # emits final stats itself on shutdown

    logger.info("exiting")
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
