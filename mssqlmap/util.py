from typing import Generator, TextIO, TypeVar
import json
import os
import random
import string
import sys

from mssqlmap.model import DatabaseServicePrincipal

PIPELINE = not os.isatty(sys.stdout.fileno())


def log(stdout: bool = False, **kwargs) -> None:
    print(json.dumps(kwargs, indent=None if PIPELINE else 2, separators=(',', ':') if PIPELINE else None, sort_keys=False), file=sys.stdout if stdout else sys.stderr)


T = TypeVar('T')

def load_targets(targets: list[str], model: T|None = None) -> Generator[T|DatabaseServicePrincipal, None, None]:
    for target in targets:
        if target == '-':
            yield from load_target_file(sys.stdin, model)
        elif os.path.exists(target):
            with open(target, 'r') as file:
                yield from load_target_file(file, model)
        else:
            try:
                yield parse_host(target)
            except Exception:
                log(error='invalid host', target=target)


def load_target_file(file: TextIO, model: T|None) -> Generator[T|DatabaseServicePrincipal, None, None]:
    for line in file:
        line = line.rstrip('\n')
        if not line:
            continue
        if model:
            try:
                yield model.model_validate(json.loads(line))  # type: ignore
            except Exception:
                log(error='invalid model', target=line)
        else:
            try:
                yield parse_host(line)
            except Exception:
                log(error='invalid host', target=line)


def parse_host(target: str) -> DatabaseServicePrincipal:
    parts = target.split(':', maxsplit=1)
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 1433
    return DatabaseServicePrincipal(host=host, port=port)


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
