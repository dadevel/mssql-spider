from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    lines = xp_cmdshell(client, opts.xpcmd)
    if len(lines) == 0:
        return dict()
    elif len(lines) == 1:
        return dict(output=lines[0].rstrip())
    else:
        return dict(output='\n' + '\n'.join(lines))


def xp_cmdshell(client: MSSQLClient, command: str) -> list[str]:
    enabled = xp_cmdshell_enabled(client)
    if not enabled:
        enable_xp_cmdshell(client)
    rows = client.query(f"exec master..xp_cmdshell '{command}'")
    if not enabled:
        disable_xp_cmdshell(client)
    lines = [row['output'] for row in rows if row['output'] != 'NULL']
    return lines


def xp_cmdshell_enabled(client: MSSQLClient) -> bool:
    rows = client.query("SELECT CONVERT(INT, ISNULL(value, value_in_use)) as 'value' FROM sys.configurations WHERE name='xp_cmdshell'");
    assert len(rows) == 1
    return bool(rows[0]['value'])


def enable_xp_cmdshell(client: MSSQLClient) -> None:
    client.query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell',1;RECONFIGURE;")


def disable_xp_cmdshell(client: MSSQLClient) -> None:
    client.query("exec sp_configure 'xp_cmdshell',0;RECONFIGURE;exec sp_configure 'show advanced options',0;RECONFIGURE;")
