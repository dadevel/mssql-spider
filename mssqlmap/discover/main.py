from __future__ import annotations
from argparse import ArgumentParser, BooleanOptionalAction
from typing import Any
import json
import os
import sys

from mssqlmap import default


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=default.HELP_FORMATTER)
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False)

    parsers = entrypoint.add_subparsers(dest='command', required=True)
    parsers.add_parser(
        'bloodhound',
        epilog=(
            'env vars:\n'
            '  NEO4J_USERNAME\n'
            '  NEO4J_PASSWORD\n'
            '  NEO4J_URL\n'
        ),
    )

    parser = parsers.add_parser('ldap')
    auth = parser.add_argument_group('auth')
    auth.add_argument('-d', '--domain', default='', metavar='DOMAINNAME')
    auth.add_argument('-u', '--user', default='', metavar='USERNAME')
    authsecret = auth.add_mutually_exclusive_group()
    authsecret.add_argument('-p', '--password', default='', metavar='PASSWORD')
    authsecret.add_argument('-H', '--hashes', default='', metavar='[LMHASH:]NTHASH', help='authenticate via pass the hash')
    authsecret.add_argument('-a', '--aes-key', default='', metavar='HEXKEY', help='authenticate via pass the key')
    auth.add_argument('-k', '--kerberos', action=BooleanOptionalAction, default=False, help='use Kerberos instead of NTLM')
    auth.add_argument('-K', '--kdc', metavar='HOST', help='FQDN or IP of a domain controller, default: value of -d')

    opts = entrypoint.parse_args()

    match opts.command:
        case 'bloodhound':
            from mssqlmap.discover import bloodhound

            neo4j_username = os.environ.get('NEO4J_USERNAME') or 'neo4j'
            neo4j_password = os.environ.get('NEO4J_PASSWORD') or 'neo4j'
            neo4j_url = os.environ.get('NEO4J_URL') or 'http://localhost:7474'
            for spn in bloodhound.get_spns(neo4j_url, neo4j_username, neo4j_password):
                print(f'{spn.host}:{spn.port}', file=sys.stdout)
        case 'ldap':
            raise NotImplementedError()


def log(**kwargs: Any) -> None:
    print(json.dumps(kwargs, sort_keys=False), file=sys.stderr)


if __name__ == '__main__':
    main()
