from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    hive, path, key = opts.regread
    value = regread(client, hive, path, key)
    return dict(value=value)


def regread(client: MSSQLClient, hive: str, path: str, key: str) -> str:
    rows = client.query(
        'DECLARE @value SYSNAME '
        f"EXECUTE master.dbo.xp_regread N'{hive}', N'{path}', N'{key}', @value OUTPUT "
        'SELECT @value AS [value]'
    )
    assert len(rows) == 1 and len(rows[0]) == 1
    return rows[0]['value']
