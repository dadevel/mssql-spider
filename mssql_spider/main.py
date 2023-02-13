from __future__ import annotations
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
from typing import Any, Callable, Generator

import itertools
import logging
import os
import sys

from mssql_spider.client import MSSQLClient
from mssql_spider.modules import coerce, dump, exec, fs, query, reg, sysinfo

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
    entrypoint = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        epilog=(
            'notes:\n'
            '  crack database hashes:\n'
            '    hashcat -O -w 3 -a 0 -m 1731 --username ./hashes.txt ./rockyou.txt\n'
        ),
    )

    entrypoint.add_argument('--depth', type=int, default=10, metavar='UINT', help='default: 10')
    entrypoint.add_argument('--threads', type=int, default=min((os.cpu_count() or 1) * 4, 16), metavar='UINT', help='default: based on CPU cores')
    entrypoint.add_argument('--timeout', type=int, default=5, metavar='SECONDS', help='default: 5')
    entrypoint.add_argument('--debug', action='store_true')

    auth = entrypoint.add_argument_group('authentication')
    auth.add_argument('-d', '--domain', default='', metavar='DOMAIN', help='implies -w')
    auth.add_argument('-u', '--user', metavar='USERNAME')

    authsecret = auth.add_mutually_exclusive_group()
    authsecret.add_argument('-p', '--password', metavar='PASSWORD')
    authsecret.add_argument('-n', '--no-pass', action='store_true')
    authsecret.add_argument('-H', '--hashes', metavar='[LMHASH]:NTHASH')
    authsecret.add_argument('-a', '--aes-key', metavar='HEXKEY', help='implies -k')

    auth.add_argument('-w', '--windows-auth', action='store_true')
    auth.add_argument('-k', '--kerberos', action='store_true')
    auth.add_argument('-K', '--dc-ip', metavar='ADDRESS')
    auth.add_argument('-D', '--database', metavar='NAME')

    enumeration = entrypoint.add_argument_group('enumeration')
    enumeration.add_argument('-q', '--query', action='append', metavar='SQL', help='unprivileged')
    enumeration.add_argument('--sysinfo', action='store_true', help='unprivileged')
    #enumeration.add_argument('--databases', action='store_true', help='unprivileged')
    #enumeration.add_argument('--tables', action='store_true', help='unprivileged')
    #enumeration.add_argument('--columns', action='store_true', help='unprivileged')

    coercion = entrypoint.add_argument_group('coercion')
    coercion.add_argument('-c', '--coerce', '--coerce-dirtree', dest='coerce_dirtree', action='append', metavar='UNCPATH', help='coerce NTLM trough xp_dirtree(), unprivileged')
    coercion.add_argument('--coerce-fileexist', action='append', metavar='UNCPATH', help='coerce NTLM trough xp_fileexist(), unprivileged')
    coercion.add_argument('--coerce-openrowset', action='append', metavar='UNCPATH', help='coerce NTLM trough openrowset(), privileged')

    fs = entrypoint.add_argument_group('filesystem')
    fs.add_argument('--fs-read', action='append', metavar='REMOTE', help='read text file trough openrowset(), privileged')
    fs.add_argument('--fs-write', nargs=2, action='append', metavar=('LOCAL', 'REMOTE'), help='write file trough OLE automation, privileged')

    exec = entrypoint.add_argument_group('execution')
    exec.add_argument('-x', '--exec-cmdshell', action='append', metavar='COMMAND', help='execute command trough xp_cmdshell(), privileged')
    exec.add_argument('--exec-ole', action='append', metavar='COMMAND', help='execute blind command trough OLE automation, privileged')
    exec.add_argument('--exec-job', nargs=2, action='append', metavar=('COMMAND', 'cmd|powershell|jscript|vbscript'), help='execute blind command trough agent job, privileged, WARNING: further testing required')
    #exec.add_argument('--exec-dll', nargs='+', action='append', metavar=('ASSEMBLY FUNCTION', 'ARGS'), help='execute .NET DLL, privileged')

    reg = entrypoint.add_argument_group('registry')
    reg.add_argument('--reg-read', nargs=3, action='append', metavar=('HIVE', 'KEY', 'NAME'), help='read registry value, privileged')
    reg.add_argument('--reg-write', nargs=5, action='append', metavar=('HIVE', 'KEY', 'NAME', 'TYPE', 'VALUE'), help='write registry value, privileged')
    reg.add_argument('--reg-delete', nargs=3, action='append', metavar=('HIVE', 'KEY', 'NAME'), help='delete registry value, privileged')

    creds = entrypoint.add_argument_group('credentials')
    creds.add_argument('--dump-hashes', action='store_true', help='extract hashes of database logins, privileged')
    creds.add_argument('--dump-jobs', action='store_true', help='extract agent job scripts, privileged')
    creds.add_argument('--dump-autologon', action='store_true', help='extract autologon credentials from registry, privileged')

    entrypoint.add_argument('targets', nargs='+', metavar='HOST[:PORT]|FILE')

    opts = entrypoint.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(levelname)s:%(module)s:%(funcName)s:%(lineno)s:%(message)s')
        logging.getLogger('impacket').setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
        logging.getLogger('impacket').setLevel(logging.CRITICAL)

    if not opts.password and not opts.hashes and not opts.no_pass and not opts.aes_key:
        opts.password = getpass('Password: ')
    if opts.aes_key:
        opts.kerberos = True
    if opts.domain:
        opts.windows_auth = True

    logging.info(HEADER)

    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        for _ in pool.map(_process_target, itertools.repeat(opts), _load_targets(opts.targets)):
            continue


def _load_targets(targets: list[str]) -> Generator[tuple[str, int], None, None]:
    for item in targets:
        if os.path.isfile(item):
            with open(item) as file:
                for line in file:
                    yield _parse_target(line)
        else:
            yield _parse_target(item)


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
    if opts.query:
        _try_visitor(client, 'query', query.run, opts.query, debug=opts.debug)
    if opts.sysinfo:
        _try_visitor_single(client, 'sysinfo', sysinfo.run, [], debug=opts.debug)
    if opts.coerce_dirtree:
        _try_visitor(client, 'coerce-dirtee', coerce.dirtree, opts.coerce_dirtree, debug=opts.debug)
    if opts.coerce_fileexist:
        _try_visitor(client, 'coerce-fileexist', coerce.fileexist, opts.coerce_fileexist, debug=opts.debug)
    if opts.coerce_openrowset:
        _try_visitor(client, 'coerce-openrowset', coerce.openrowset, opts.coerce_openrowset, debug=opts.debug)
    if opts.fs_read:
        _try_visitor(client, 'fs-read', fs.read, opts.fs_read, debug=opts.debug)
    if opts.fs_write:
        _try_visitor(client, 'fs-write', fs.write, opts.fs_write, debug=opts.debug)
    if opts.exec_cmdshell:
        _try_visitor(client, 'exec-cmdshell', exec.cmdshell, opts.exec_cmdshell, debug=opts.debug)
    if opts.exec_ole:
        _try_visitor(client, 'exec-ole', exec.ole, opts.exec_ole, debug=opts.debug)
    if opts.exec_job:
        _try_visitor(client, 'exec-job', exec.job, opts.exec_job, debug=opts.debug)
    #if opts.exec_dll:
    #    _try_visitor(client, 'exec-dll', exec.rundll, opts.exec_dll, debug=opts.debug)
    if opts.reg_read:
        _try_visitor(client, 'reg-read', reg.read, opts.reg_read, debug=opts.debug)
    if opts.reg_write:
        _try_visitor(client, 'reg-write', reg.write, opts.reg_write, debug=opts.debug)
    if opts.reg_delete:
        _try_visitor(client, 'reg-delete', reg.delete, opts.reg_delete, debug=opts.debug)
    if opts.dump_hashes:
        _try_visitor_single(client, 'dump-hashes', dump.hashes, [], debug=opts.debug)
        logging.info('')
    if opts.dump_jobs:
        _try_visitor_single(client, 'dump-jobs', dump.jobs, [], debug=opts.debug)
    if opts.dump_autologon:
        _try_visitor_single(client, 'dump-autologon', dump.autologon, [], debug=opts.debug)


def _try_visitor(client: MSSQLClient, name: str, function: Callable, items: list[list[Any]], debug: bool = False) -> None:
    for args in items:
        _try_visitor_single(client, name, function, args, debug=debug)


def _try_visitor_single(client: MSSQLClient, name: str, function: Callable, args: str|list[str], debug: bool = False) -> None:
    try:
        if isinstance(args, list):
            result = function(client, *args)
        else:
            result = function(client, args)
        logging.info(f'{client.connection.server}:{client.connection.port}:{client.path} {name} {_format_result(result)}')
    except Exception as e:
        logging.error(f'{client.connection.server}:{client.connection.port}:{client.path} {name} {_format_result(dict(error=str(e)))}')
        if debug:
            logging.exception(e)


def _format_result(data: dict[str, Any]) -> str:
    return ' '.join(f'{k}={v}' for k, v in data.items())


if __name__ == '__main__':
    main()
