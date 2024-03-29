from __future__ import annotations
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from concurrent.futures import ThreadPoolExecutor
import functools
import logging
import os
import sys
import threading
import traceback

from mssqlmap.client import Client
from mssqlmap.connection import Connection
from mssqlmap import default
from mssqlmap import util

local = threading.local()


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=default.HELP_FORMATTER)
    entrypoint.add_argument('--threads', type=int, default=default.THREAD_COUNT, help=f'default: {default.THREAD_COUNT}')
    entrypoint.add_argument('--timeout', type=int, default=default.TIMEOUT, help=f'in seconds, default: {default.TIMEOUT}')
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False, help='write verbose logs to stderr')

    parsers = entrypoint.add_subparsers(dest='command', required=True)

    parser = parsers.add_parser('passwords')
    group = parser.add_argument_group('authentication')
    group.add_argument('-w', '--windows-auth', action=BooleanOptionalAction, default=False, help='use Windows instead of database login')
    group.add_argument('-d', '--domain', default='', metavar='DOMAINNAME', help='implies -w')
    group.add_argument('-u', '--user', nargs='+', default=[], metavar='USERNAME|FILE')
    group.add_argument('-p', '--password', nargs='+', default=[], metavar='PASSWORD|FILE')
    group.add_argument('-c', '--credential', nargs='+', default=[], metavar='USER:PASS|FILE')
    group.add_argument('-k', '--kerberos', action=BooleanOptionalAction, default=False, help='use Kerberos instead of NTLM')
    group.add_argument('-K', '--kdc', metavar='HOST', help='FQDN or IP of a domain controller, default: value of -d')
    group = parser.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]', help='default: read from stdin')

    parser = parsers.add_parser('hashes')
    group = parser.add_argument_group('authentication')
    group.add_argument('-d', '--domain', default='', metavar='DOMAINNAME')
    group.add_argument('-u', '--user', nargs='+', default=[], metavar='USERNAME|FILE')
    group.add_argument('-H', '--hashes', nargs='+', default=[], metavar='[LMHASH:]NTHASH|FILE', help='pass the hash')
    group = parser.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]', help='default: read from stdin')

    parser = parsers.add_parser('keys')
    group = parser.add_argument_group('authentication')
    group.add_argument('-d', '--domain', required=True, metavar='DOMAINNAME')
    group.add_argument('-u', '--user', nargs='+', default=[], metavar='USERNAME|FILE')
    group.add_argument('-H', '--hashes', nargs='*', default=[], metavar='[LMHASH:]NTHASH|FILE', help='Kerberos RC4, overpass the key')
    group.add_argument('-a', '--aes-key', nargs='*', default=[], metavar='HEXKEY', help='Kerberos AES128 or AES256, pass the key')
    group.add_argument('-K', '--kdc', metavar='HOST', help='FQDN or IP of a domain controller, default: value of -d')
    group = parser.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]', help='default: read from stdin')

    parser = parsers.add_parser('tickets')
    group = parser.add_argument_group('authentication')
    group.add_argument('-d', '--domain', required=True, metavar='DOMAINNAME')
    group.add_argument('-u', '--user', nargs='+', default=[], metavar='USERNAME|FILE')
    group.add_argument('-c', '--ticket', nargs='+', default=[], metavar='CCACHEFILE', help='pass the ticket')
    group.add_argument('-K', '--kdc', metavar='HOST', help='FQDN or IP of a domain controller, default: value of -d')
    group = parser.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]', help='default: read from stdin')

    opts = entrypoint.parse_args()

    logging.getLogger('impacket').setLevel(logging.FATAL)

    if opts.domain:
        opts.windows_auth = True

    try:
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            for _ in pool.map(functools.partial(process, opts=opts), util.load_targets(opts.targets, opts.json_input)):
                pass
    except KeyboardInterrupt:
        exit(1)


def process(target: Connection, opts: Namespace) -> None:
    local.log = functools.partial(util.log, host=target.host, port=target.port, domain=opts.domain)
    match opts.command:
        case 'passwords':
            for line in util.load_wordlists(opts.credential):
                username, password = line.split(':', maxsplit=1)
                client = Client(Connection(
                    host=target.host,
                    port=target.port or 1433,
                    domain=opts.domain,
                    username=username,
                    password=password,
                    windows_auth=opts.windows_auth,
                    kerberos=opts.kerberos,
                    kdc_host=opts.kdc,
                    timeout=opts.timeout,
                ))
                test_login(opts, client)
            for username in util.load_wordlists(opts.user):
                for password in util.load_wordlists(opts.password):
                    client = Client(Connection(
                        host=target.host,
                        port=target.port or 1433,
                        domain=opts.domain,
                        username=username,
                        password=password,
                        windows_auth=opts.windows_auth,
                        kerberos=opts.kerberos,
                        kdc_host=opts.kdc,
                        timeout=opts.timeout,
                    ))
                    test_login(opts, client)
        case 'hashes':
            for username in util.load_wordlists(opts.user):
                for hash in util.load_wordlists(opts.hashes):
                    client = Client(Connection(
                        host=target.host,
                        port=target.port or 1433,
                        domain=opts.domain,
                        username=username,
                        hashes=hash,
                        windows_auth=True,
                        kerberos=False,
                        timeout=opts.timeout,
                    ))
                    test_login(opts, client)
        case 'keys':
            for username in util.load_wordlists(opts.user):
                for hash in util.load_wordlists(opts.hashes):
                    client = Client(Connection(
                        host=target.host,
                        port=target.port or 1433,
                        domain=opts.domain,
                        username=username,
                        hashes=hash,
                        windows_auth=True,
                        kerberos=True,
                        kdc_host=opts.kdc,
                        timeout=opts.timeout,
                    ))
                    test_login(opts, client)
                for key in util.load_wordlists(opts.aes_key):
                    client = Client(Connection(
                        host=target.host,
                        port=target.port or 1433,
                        domain=opts.domain,
                        username=username,
                        aes_key=key,
                        windows_auth=True,
                        kerberos=True,
                        kdc_host=opts.kdc,
                        timeout=opts.timeout,
                    ))
                    test_login(opts, client)
        case 'tickets':
            for username in util.load_wordlists(opts.user):
                for ticket in opts.ticket:
                    client = Client(Connection(
                        host=target.host,
                        port=target.port or 1433,
                        domain=opts.domain,
                        username=username,
                        ticket=ticket,
                        windows_auth=True,
                        kerberos=True,
                        kdc_host=opts.kdc,
                        timeout=opts.timeout,
                    ))
                    test_login(opts, client)
        case _:
            raise RuntimeError('unreachable')


def test_login(opts: Namespace, client: Client) -> None:
    try:
        with client:
            local.log(**client.connection.model_dump(exclude_defaults=True), success=True, stdout=True)
    except OSError as e:
        local.log(**client.connection.model_dump(exclude_defaults=True), error=dict(message=str(e), type=e.__class__.__name__))
    except Exception as e:
        local.log(**client.connection.model_dump(exclude_defaults=True), error=dict(message=str(e), type=e.__class__.__name__))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)


if __name__ == '__main__':
    main()
