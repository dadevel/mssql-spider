from typing import Generator, TextIO, TypeVar
import json
import os
import random
import string
import sys

from mssqlmap.connection import Connection


def log(stdout: bool = False, **kwargs) -> None:
    print(json.dumps(kwargs, indent=None, separators=(',', ':'), sort_keys=False), file=sys.stdout if stdout else sys.stderr)


def load_targets(args: list[str], json_input: bool) -> Generator[Connection, None, None]:
    if args:
        yield from load_args(args)
    else:
        yield from load_stdin(json_input)


def load_args(args: list[str]) -> Generator[Connection, None, None]:
    for arg in args:
        try:
            yield parse_host_tuple(arg)
        except Exception:
            log(error='invalid host tuple', input=arg)


def load_stdin(json_input: bool) -> Generator[Connection, None, None]:
    for line in sys.stdin:
        line = line.rstrip('\n')
        if not line:
            continue
        if json_input:
            try:
                yield Connection.model_validate(json.loads(line))
            except Exception:
                log(error='invalid model', input=line)
        else:
            try:
                yield parse_host_tuple(line)
            except Exception:
                log(error='invalid host tuple', input=line)


def parse_host_tuple(line: str) -> Connection:
    parts = line.split(':', maxsplit=1)
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 1433
    return Connection(host=host, port=port)


def load_wordlists(items: list[str]) -> Generator[str, None, None]:
    for item in items:
        if os.path.exists(item):
            with open(item, 'r') as file:
                for line in file:
                    yield line.rstrip('\n')
        else:
            yield item


def random_string(length: int = 8) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
