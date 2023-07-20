from __future__ import annotations
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from typing import Any, Generator
from concurrent.futures import ThreadPoolExecutor
import functools
import os
import socket
import sys
import threading
import traceback

from mssqlmap.model import DatabaseInstance, DatabaseServicePrincipal
from mssqlmap import default
from mssqlmap import util

local = threading.local()


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=default.HELP_FORMATTER)
    entrypoint.add_argument('--threads', type=int, default=default.THREAD_COUNT, help=f'default: {default.THREAD_COUNT}')
    entrypoint.add_argument('--timeout', type=int, default=default.TIMEOUT, help=f'in seconds, default: {default.TIMEOUT}')
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False)
    entrypoint.add_argument('--json', action=BooleanOptionalAction, default=os.isatty(sys.stdin.fileno()), help='emits JSONL output, default: if pipeline')
    entrypoint.add_argument('-t', '--targets', nargs='*', default=['-'], metavar='-|FILE|HOST[:PORT]')
    opts = entrypoint.parse_args()

    try:
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            for _ in pool.map(functools.partial(process, opts=opts), util.load_targets(opts.targets)):
                pass
    except KeyboardInterrupt:
        exit(1)


def process(target: DatabaseServicePrincipal, opts: Namespace) -> None:
    local.log = functools.partial(util.log, host=target.host, port=1434)
    try:
        for attrs in ping(target.host, opts.timeout):
            instance = DatabaseInstance.from_ping(host=target.host, **attrs)
            local.log(**instance.model_dump(), stdout=True)
    except OSError as e:
        local.log(error=dict(message=str(e), type=e.__class__.__name__))
    except Exception as e:
        local.log(error=dict(message=str(e), type=e.__class__.__name__))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)


def ping(host: str, timeout: int) -> Generator[dict[str, Any], None, None]:
    if not hasattr(local, 'sock'):
        local.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        local.sock.settimeout(timeout)

    # printf '\x03' | nc -vu $host 1434
    local.sock.sendto(b'\x03', (host, 1434))
    bindata, _ = local.sock.recvfrom(65535)

    if bindata:
        yield from parse(bindata)


def parse(bindata: bytes) -> Generator[dict[str, str], None, None]:
    pos = bindata.find(b'ServerName;')
    bindata = bindata[pos:]
    assert pos < 16, f'invalid response: {bindata}'

    try:
        data = bindata.decode('ascii')
    except Exception as e:
        raise AssertionError(f'invalid encoding: {bindata}') from e

    assert data.endswith(';;'), f'invalid response end: {bindata}'

    for block in data.split(';;'):
        if not block:
            continue
        assert block.startswith('ServerName'), f'invalid block start: {bindata}'
        items = block.split(';')
        attrs = {k.lower(): v for k, v in zip(items[:-1:2], items[1::2])}
        yield attrs


if __name__ == '__main__':
    main()
