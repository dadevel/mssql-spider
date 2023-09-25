from __future__ import annotations
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from typing import Generator
from concurrent.futures import ThreadPoolExecutor
import functools
import os
import socket
import sys
import threading
import traceback

from mssqlmap.connection import Connection
from mssqlmap import default
from mssqlmap import util

local = threading.local()


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=default.HELP_FORMATTER)
    entrypoint.add_argument('--threads', type=int, default=default.THREAD_COUNT, help=f'default: {default.THREAD_COUNT}')
    entrypoint.add_argument('--timeout', type=int, default=default.TIMEOUT, help=f'in seconds, default: {default.TIMEOUT}')
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False, help='write verbose logs to stderr')
    group = entrypoint.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]', help='default: read from stdin')
    opts = entrypoint.parse_args()

    try:
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            for _ in pool.map(functools.partial(process, opts=opts), util.load_targets(opts.targets, opts.json_input)):
                pass
    except KeyboardInterrupt:
        exit(1)


def process(target: Connection, opts: Namespace) -> None:
    local.log = functools.partial(util.log, host=target.host)
    try:
        for instance in udp_ping(target.host, opts.timeout):
            local.log(**instance.model_dump(exclude_unset=True), success=True, stdout=True)
    except TimeoutError as e:
        local.log(port=1434, error=dict(message=str(e), type=e.__class__.__name__))
    except OSError as e:
        local.log(port=1434, error=dict(message=str(e), type=e.__class__.__name__))
    except Exception as e:
        local.log(port=1434, error=dict(message=str(e), type=e.__class__.__name__))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)

    try:
        instance = tcp_ping(target.host, target.port, opts.timeout)
        local.log(**instance.model_dump(exclude_unset=True), success=True, stdout=True)
    except TimeoutError as e:
        local.log(port=target.port, error=dict(message=str(e), type=e.__class__.__name__))
    except OSError as e:
        local.log(port=target.port, error=dict(message=str(e), type=e.__class__.__name__))
    except Exception as e:
        local.log(port=target.port, error=dict(message=str(e), type=e.__class__.__name__))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)


def udp_ping(host: str, timeout: int) -> Generator[Connection, None, None]:
    if not hasattr(local, 'sock'):
        local.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        local.sock.settimeout(timeout)

    # printf '\x03' | nc -vu $host 1434
    local.sock.sendto(b'\x03', (host, 1434))
    bindata, _ = local.sock.recvfrom(65535)

    if bindata:
        for attrset in udp_parse(bindata):
            yield Connection.from_ping(host=host, **attrset)


def udp_parse(bindata: bytes) -> Generator[dict[str, str], None, None]:
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


def tcp_ping(host: str, port: int, timeout: int) -> Connection:
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        return Connection(host=host, port=port)


if __name__ == '__main__':
    main()
