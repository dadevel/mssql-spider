from __future__ import annotations
from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
from typing import Any, Generator

import itertools
import logging
import os
import sys

from mssql_spider.client import MSSQLClient
from mssql_spider.modules import olecmd, sysinfo, xpcmdshell, xpdirtree

HEADER = '\n'.join((
    r'                              __                 _     __',
    r'   ____ ___  ______________ _/ /     _________  (_)___/ /__  _____',
    r'  / __ `__ \/ ___/ ___/ __ `/ /_____/ ___/ __ \/ / __  / _ \/ ___/',
    r' / / / / / (__  |__  ) /_/ / /_____(__  ) /_/ / / /_/ /  __/ /',
    r'/_/ /_/ /_/____/____/\__, /_/     /____/ .___/_/\__,_/\___/_/',
    r'                       /_/            /_/',
    r'',
    r'legend: => linked instance, -> impersonated user, ~> impersonated login',
    r'',
))


def main() -> None:
    entrypoint = ArgumentParser()

    entrypoint.add_argument('--depth', type=int, default=10, metavar='UINT', help='default: 10')
    entrypoint.add_argument('--threads', type=int, default=min((os.cpu_count() or 1) * 4, 16), metavar='UINT', help='default: based on CPU cores')
    entrypoint.add_argument('--timeout', type=int, default=5, metavar='SECONDS', help='default: 5')
    entrypoint.add_argument('--debug', action='store_true')

    group = entrypoint.add_argument_group('authentication')
    group.add_argument('-d', '--domain', default='', metavar='DOMAIN')
    group.add_argument('-u', '--user', metavar='USERNAME')

    exgroup = group.add_mutually_exclusive_group()
    exgroup.add_argument('-p', '--password', metavar='PASSWORD')
    exgroup.add_argument('-n', '--no-pass', action='store_true')
    exgroup.add_argument('-H', '--hashes', metavar='[LMHASH]:NTHASH')
    exgroup.add_argument('-a', '--aes-key', metavar='HEXKEY')

    group.add_argument('-w', '--windows-auth', action='store_true')
    group.add_argument('-k', '--kerberos', action='store_true')
    group.add_argument('-K', '--dc-ip', metavar='ADDRESS')
    group.add_argument('-D', '--database', metavar='NAME')

    group = entrypoint.add_argument_group('action')
    #group.add_argument('--whoami', action='store_true')
    group.add_argument('--sysinfo', action='store_true')

    exgroup = group.add_mutually_exclusive_group()
    #exgroup.add_argument('-q', '--query', metavar='SQL')
    exgroup.add_argument('-x', '--xpcmd', metavar='COMMAND', help='execute command and return output')
    exgroup.add_argument('--olecmd', metavar='COMMAND', help='execute command blindly')
    #exgroup.add_argument('--rundll', nargs='+', metavar='ASSEMBLY FUNCTION ARGS...')
    exgroup.add_argument('--xpdir', metavar='UNCPATH')

    entrypoint.add_argument('targets', nargs='+', metavar='HOST[:PORT]|FILE...')

    opts = entrypoint.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(levelname)s:%(module)s:%(funcName)s:%(lineno)s:%(message)s')
        logging.getLogger('impacket').setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
        logging.getLogger('impacket').setLevel(logging.CRITICAL)

    if not opts.password and not opts.hashes and not opts.no_pass and not opts.aes_key:
        opts.password = getpass('Password:')
    if opts.aes_key:
        opts.kerberos = True

    logging.info(HEADER)

    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        for _ in pool.map(_process_target, itertools.repeat(opts), _load_targets(opts.targets)):
            continue


def _load_targets(targets: list[str]) -> Generator[tuple[str, int], None, None]:
    for item in targets:
        if os.path.isfile(item):
            with open(item) as file:
                for line in file:
                    target = _parse_target(line)
                    yield target
        else:
            target = _parse_target(item)
            yield target


def _parse_target(value: str) -> tuple[str, int]:
    parts = value.strip().rsplit(':', maxsplit=1)
    if len(parts) == 1:
        return value, 1433
    else:
        return parts[0], int(parts[1])


def _process_target(opts: Namespace, target: tuple[str, int]) -> None:
    try:
        client = MSSQLClient.connect(target[0], target[1], timeout=opts.timeout)
    except Exception as e:
        logging.error(f'{target[0]}:{target[1]} con {_format_result(dict(error=str(e)))}')
        if opts.debug:
            logging.exception(e)
        return

    try:
        client.login(opts.database, opts.user, opts.password, opts.domain, opts.hashes, opts.aes_key, opts.dc_ip, opts.windows_auth, opts.kerberos)
    except (Exception, OSError) as e:
        logging.error(f'{target[0]}:{target[1]} auth {_format_result(dict(error=str(e)))}')
        if opts.debug:
            logging.exception(e)
        return

    client.spider(lambda c: _visitor(opts, c), max_depth=opts.depth)


def _visitor(opts: Namespace, client: MSSQLClient) -> None:
    if opts.sysinfo:
        _try_visitor(opts, client, sysinfo)
    if opts.xpcmd:
        _try_visitor(opts, client, xpcmdshell)
    if opts.olecmd:
        _try_visitor(opts, client, olecmd)
    if opts.xpdir:
        _try_visitor(opts, client, xpdirtree)


def _try_visitor(opts: Namespace, client: MSSQLClient, module) -> None:
    module_name = module.__name__.removeprefix(f'{module.__package__}.')
    try:
        result = module.visitor(opts, client)
        logging.info(f'{client.connection.server}:{client.connection.port}:{client.path} {module_name} {_format_result(result)}')
    except Exception as e:
        logging.error(f'{client.connection.server}:{client.connection.port}:{client.path} {module_name} {_format_result(dict(error=str(e)))}')
        if opts.debug:
            logging.exception(e)


def _format_result(data: dict[str, Any]) -> str:
    return ' '.join(f'{k}={v}' for k, v in data.items())


if __name__ == '__main__':
    main()
