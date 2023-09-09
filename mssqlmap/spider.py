from __future__ import annotations
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import functools
import json
import logging
import os
import sys

from rich.console import Console
from rich.highlighter import NullHighlighter
from rich.style import Style
from rich.text import Text

from mssqlmap.client import BaseModule, BrokenClient, Client
from mssqlmap.connection import Connection, SQLErrorException
from mssqlmap.modules.clrexec import ClrExecutor
from mssqlmap.modules.coerce import DirTreeCoercer, FileExistCoercer, OpenRowSetCoercer
from mssqlmap.modules.dump import HashDumper, JobDumper, AutoLogonDumper
from mssqlmap.modules.enum import DatabaseEnumerator, LoginEnumerator, UserEnumerator
from mssqlmap.modules.exec import CmdShellExecutor, OleExecutor, JobScheduler, JobDeleter, JobExecutor
from mssqlmap.modules.fs import FileReader, FileWrite
from mssqlmap.modules.query import QueryRunner
from mssqlmap.modules.reg import RegistryReader, RegistryWrite, RegistryDeleter
from mssqlmap.modules.sysinfo import SystemInformer
from mssqlmap import default, util
from mssqlmap.modules.impersonated_user import ImpersonationSpider
from mssqlmap.modules.linked_instance import LinkSpider

HEADER = '\n'.join((
    r'                              __                 _     __',
    r'   ____ ___  ______________ _/ /     _________  (_)___/ /__  _____',
    r'  / __ `__ \/ ___/ ___/ __ `/ /_____/ ___/ __ \/ / __  / _ \/ ___/',
    r' / / / / / (__  |__  ) /_/ / /_____(__  ) /_/ / / /_/ /  __/ /',
    r'/_/ /_/ /_/____/____/\__, /_/     /____/ .___/_/\__,_/\___/_/',
    r'                       /_/            /_/',
    r'',
    r'legend: => linked instance, -> impersonated user/login',
    r'',
))

# keep in sync with arguments below
SPIDER_MODULE_TABLE = dict(
    impersonation=ImpersonationSpider,
    links=LinkSpider,
)
VISITOR_MODULE_TABLE = dict(
    query=QueryRunner,
    sysinfo=SystemInformer,
    enum_dbs=DatabaseEnumerator,
    enum_logins=LoginEnumerator,
    enum_users=UserEnumerator,
    coerce_dirtree=DirTreeCoercer,
    coerce_fileexist=FileExistCoercer,
    coerce_openrowset=OpenRowSetCoercer,
    file_read=FileReader,
    file_write=FileWrite,
    exec_cmdshell=CmdShellExecutor,
    exec_clr=ClrExecutor,
    exec_ole=OleExecutor,
    exec_job=JobExecutor,
    schedule_job=JobScheduler,
    delete_job=JobDeleter,
    reg_read=RegistryReader,
    reg_write=RegistryWrite,
    reg_delete=RegistryDeleter,
    dump_hashes=HashDumper,
    dump_jobs=JobDumper,
    dump_autologon=AutoLogonDumper,
)

STDOUT = Console(highlighter=NullHighlighter(), soft_wrap=True, stderr=False)
STDERR = Console(highlighter=NullHighlighter(), soft_wrap=True, stderr=True)


def main() -> None:
    entrypoint = ArgumentParser(formatter_class=default.HELP_FORMATTER)

    entrypoint.add_argument('--threads', type=int, default=default.THREAD_COUNT, metavar='UINT', help='default: based on CPU cores')
    entrypoint.add_argument('--timeout', type=int, default=default.TIMEOUT, metavar='SECONDS', help=f'default: {default.TIMEOUT}')
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False, help='write verbose logs to stderr')

    auth = entrypoint.add_argument_group('authentication')
    auth.add_argument('-d', '--domain', default='', metavar='DOMAIN', help='implies -w')
    auth.add_argument('-u', '--user', metavar='USERNAME')

    authsecret = auth.add_mutually_exclusive_group()
    authsecret.add_argument('-p', '--password', metavar='PASSWORD', default='')
    authsecret.add_argument('-H', '--hashes', metavar='[LMHASH:]NTHASH', help='authenticate via pass the hash')
    authsecret.add_argument('-a', '--aes-key', metavar='HEXKEY', help='authenticate with Kerberos key in hex, implies -k')

    auth.add_argument('-w', '--windows-auth', action='store_true', help='use windows instead of local authentication, default: false')
    auth.add_argument('-k', '--kerberos', action='store_true', help='authenticate via Kerberos, implies -w, default: false')
    auth.add_argument('-K', '--kdc', metavar='ADDRESS', help='FQDN or IP address of a domain controller, default: value of -d')
    auth.add_argument('-D', '--database', metavar='NAME')

    spider = entrypoint.add_argument_group('spider')
    spider.add_argument('--links', action=BooleanOptionalAction, default=True, help='default: true')
    spider.add_argument('--impersonation', action=BooleanOptionalAction, default=True, help='default: true')
    spider.add_argument('--depth', type=int, default=10, metavar='UINT', help='default: 10')

    enumeration = entrypoint.add_argument_group('enumeration')
    enumeration.add_argument('-q', '--query', action='append', metavar='SQL', help='execute SQL statement, unprivileged, repeatable')
    enumeration.add_argument('--sysinfo', action='store_true', help='retrieve database and OS version, unprivileged')
    enumeration.add_argument('--enum-dbs', action='store_true', help='unprivileged')
    enumeration.add_argument('--enum-logins', action='store_true', help='unprivileged')
    enumeration.add_argument('--enum-users', action='store_true', help='unprivileged')
    #enumeration.add_argument('--grep', metavar='REGEX', help='list sample data from column names matching the pattern, unprivileged')

    coercion = entrypoint.add_argument_group('coercion')
    coercion.add_argument('-c', '--coerce-dirtree', dest='coerce_dirtree', action='append', metavar='UNCPATH', help='coerce NTLM trough xp_dirtree(), unprivileged, repeatable')
    coercion.add_argument('--coerce-fileexist', action='append', metavar='UNCPATH', help='coerce NTLM trough xp_fileexist(), unprivileged, repeatable')
    coercion.add_argument('--coerce-openrowset', action='append', metavar='UNCPATH', help='coerce NTLM trough openrowset(), privileged, repeatable')

    fs = entrypoint.add_argument_group('filesystem')
    fs.add_argument('--file-read', action='append', metavar='REMOTE', help='read file trough openrowset(), privileged, repeatable')
    fs.add_argument('--file-write', nargs=2, action='append', metavar=('LOCAL', 'REMOTE'), help='write file trough OLE automation, privileged, repeatable')

    exec = entrypoint.add_argument_group('execution')
    exec.add_argument('-x', '--exec-cmdshell', action='append', metavar='COMMAND', help='execute command trough xp_cmdshell(), privileged, repeatable')
    exec.add_argument('--exec-clr', nargs='+', action='append', metavar=('ASSEMBLY FUNCTION', 'ARGS'), help='execute .NET DLL, privileged, repeatable')
    exec.add_argument('--exec-ole', action='append', metavar='COMMAND', help='execute blind command trough OLE automation, privileged, repeatable')
    exec.add_argument('--exec-job', nargs=2, action='append', metavar=('|'.join(JobScheduler.SUBSYSTEMS), 'COMMAND'), help='execute blind command trough temporary agent job, privileged, repeatable')
    exec.add_argument('--schedule-job', nargs=4, action='append', metavar=('JOBNAME', '|'.join(JobScheduler.FREQUENCIES), '|'.join(JobScheduler.SUBSYSTEMS), 'COMMAND'), help='execute blind command in regular intervals trough permanent agent job, privileged, repeatable')
    exec.add_argument('--delete-job', action='append', metavar='JOBNAME', help='delete agent job, privileged, repeatable')

    reg = entrypoint.add_argument_group('registry')
    reg.add_argument('--reg-read', nargs=3, action='append', metavar=('HIVE', 'KEY', 'NAME'), help='read registry value, privileged, repeatable, experimental!')
    reg.add_argument('--reg-write', nargs=5, action='append', metavar=('HIVE', 'KEY', 'NAME', 'TYPE', 'VALUE'), help='write registry value, privileged, repeatable, experimental!')
    reg.add_argument('--reg-delete', nargs=3, action='append', metavar=('HIVE', 'KEY', 'NAME'), help='delete registry value, privileged, repeatable, experimental!')

    creds = entrypoint.add_argument_group('credentials')
    creds.add_argument('--dump-hashes', metavar='FILE', help='extract hashes of database logins and append them to a file, privileged')
    creds.add_argument('--dump-jobs', action='store_true', help='extract source code of agent jobs, privileged')
    creds.add_argument('--dump-autologon', action='store_true', help='extract autologon credentials from registry, privileged')

    group = entrypoint.add_argument_group('targets')
    group.add_argument('--json-input', action=BooleanOptionalAction, default=not os.isatty(sys.stdin.fileno()), help='expect JSONL input, default: if pipeline')
    group.add_argument('--json-output', action=BooleanOptionalAction, default=not os.isatty(sys.stdout.fileno()), help='produce JSONL output, default: if pipeline')
    group.add_argument('-t', '--targets', nargs='*', metavar='HOST[:PORT]')

    opts = entrypoint.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr, format='%(levelname)s:%(name)s:%(module)s:%(lineno)s:%(message)s')
        logging.getLogger('impacket').setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.ERROR, format='%(message)s')
        logging.getLogger('impacket').setLevel(logging.FATAL)

    if opts.exec_clr:
        if any(len(argset) < 2 for argset in opts.exec_clr):
            entrypoint.print_help()
            return

    opts.credentials = bool(opts.password or opts.hashes or opts.aes_key or opts.kerberos)

    if not opts.json_input and not opts.credentials:
        print('mssql-spider: error: no authentication material')
        entrypoint.print_usage()
        exit(1)

    if opts.aes_key:
        opts.kerberos = True
    if opts.domain:
        opts.windows_auth = True

    opts.spider_modules = translate_modules(opts, SPIDER_MODULE_TABLE)
    opts.visitor_modules = translate_modules(opts, VISITOR_MODULE_TABLE)

    try:
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            for _ in pool.map(functools.partial(process, opts=opts), util.load_targets(opts.targets, opts.json_input)):
                pass
    except KeyboardInterrupt:
        exit(1)


def translate_modules(opts: Namespace, table: dict[str, type]) -> list[Any]:
    modules = []
    for name, module_class in table.items():
        module_opts = getattr(opts, name)
        if module_opts:
            if module_opts is True:
                modules.append(module_class())
            elif isinstance(module_opts, list):
                for optset in module_opts:
                    if isinstance(optset, list):
                        modules.append(module_class(*optset))
                    else:
                        modules.append(module_class(optset))
            else:
                modules.append(module_class(module_opts))
    return modules


STYLE_TABLE = dict(
    pwned=Style(color='green', bold=True),
    accepted=Style(color='green'),
    repeated=Style(color='green'),
    denied=Style(color='yellow'),
    failed=Style(color='red'),
)


def format_status(status: str, error: Exception|None = None) -> Text:
    text = Text(status, style=STYLE_TABLE[status])
    if not error:
        return text
    text += Text('=', style='default')
    text += Text(str(error), style='default')
    return text


def format_result(data: dict[Any, Any]) -> Text:
    text = Text()
    for key, value in data.items():
        if value is None:
            continue
        if key == 'error':
            text += Text(key, style=STYLE_TABLE['failed'])
        elif isinstance(key, Text):
            text += key
        else:
            text += Text(str(key))
        text += '='
        if isinstance(value, Text):
            text += value
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            if len(value) == 1:
                text += value[0].rstrip()
            else:
                text += '\n' + '\n'.join(value)
        elif isinstance(value, str):
            lines = value.splitlines()
            if len(lines) == 1:
                text += lines[0].rstrip()
            else:
                text += '\n' + value
        else:
            text += value if isinstance(value, Text) else Text(str(value))
        text += ' '
    return text[:-1]


MINIFIED_JSON = dict(
    separators=(',', ':'),
    sort_keys=False,
)


def log_status_json(client: Client, module: BaseModule|None, status: str) -> None:
    STDOUT.print(
        json.dumps(
            dict(
                host=client.connection.host,
                port=client.connection.port,
                instance=client.instance,
                login=client.login,
                user=client.username,
                pwned=client.pwned,
                module=module.__class__.__name__ if module else 'Spider',
                status=status,
                error=dict(
                    type=client.error.__class__.__name__,
                    message=str(client.error)) if isinstance(client, BrokenClient) else None,
            ),
            **MINIFIED_JSON,  # type: ignore
        )
    )


def log_status_ascii(client: Client, module: BaseModule|None, status: str) -> None:
    prefix = Text(f'{client.connection.host}:{client.connection.port}', style=Style(color='blue'))
    STDOUT.print(
        prefix,
        client.path,
        module.__class__.__name__ if module else 'Spider',
        format_status(status, client.error if isinstance(client, BrokenClient) else None),
    )


def log_result_json(client: Client, module: BaseModule|None, result: dict[str, Any]) -> None:
    STDOUT.print(
        json.dumps(
            dict(
                host=client.connection.host,
                port=client.connection.port,
                instance=client.instance,
                login=client.login,
                user=client.username,
                pwned=client.pwned,
                module=module.__class__.__name__ if module else 'Spider',
                result=result,
            ),
            **MINIFIED_JSON,  # type: ignore
        )
    )


def log_result_ascii(client: Client, module: BaseModule|None, result: dict[str, Any]) -> None:
    prefix = Text(f'{client.connection.host}:{client.connection.port}', style=Style(color='blue'))
    STDOUT.print(prefix, client.path, module.__class__.__name__ if module else 'Spider', format_result(result))


def log_error_json(client: Client, error: Exception, **kwargs: str) -> None:
    STDOUT.print(
        json.dumps(
            dict(
                host=client.connection.host,
                port=client.connection.port,
                module='Connection',
                error=dict(type=error.__class__.__name__, message=str(error)),
                **kwargs,
            ),
            **MINIFIED_JSON,  # type: ignore
        )
    )


def log_error_ascii(client: Client, error: Exception, **kwargs: str) -> None:
    prefix = Text(f'{client.connection.host}:{client.connection.port}', style=Style(color='blue'))
    STDOUT.print(
        prefix,
        'Connection',
        format_result(dict(error=str(error), type=error.__class__.__name__, **kwargs)),
    )


def process(target: Connection, opts: Namespace) -> None:
    log_status = log_status_json if opts.json_output else log_status_ascii
    log_result = log_result_json if opts.json_output else log_result_ascii
    log_error = log_error_json if opts.json_output else log_error_ascii

    if isinstance(target, Connection):
        target = Connection(
            host=target.host,
            port=target.port,
            instance=None,
            domain=opts.domain if opts.credentials else target.domain,
            username=opts.user if opts.credentials else target.username,
            password=opts.password if opts.credentials else target.password,
            hashes=opts.hashes if opts.credentials else target.hashes,
            aes_key=opts.aes_key if opts.credentials else target.aes_key,
            windows_auth=opts.windows_auth if opts.credentials else target.windows_auth,
            kerberos=opts.kerberos if opts.credentials else target.kerberos,
            kdc_host=opts.kdc if opts.credentials else target.kdc_host,
            database=opts.database if opts.credentials else target.database,
            timeout=opts.timeout,
        )
    client = Client(target)
    try:
        with client:
            for child, module, status in client.spider(opts.spider_modules):
                log_status(child, module, status)
                if status in ('failed', 'denied', 'repeated'):
                    continue
                for module, result in child.invoke(opts.visitor_modules):
                    log_result(child, module, result)
    except TimeoutError as e:
        log_error(client, e, hint=f'retry with --timeout {opts.timeout * 3}')
    except OSError as e:
        log_error(client, e)
    except SQLErrorException as e:
        log_error(client, e)
    except Exception as e:
        STDERR.print_exception(show_locals=True)


if __name__ == '__main__':
    main()
