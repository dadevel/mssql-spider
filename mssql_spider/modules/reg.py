from typing import Any

from mssql_spider.client import MSSQLClient

HIVES = {
    'HKLM': 'HKEY_LOCAL_MACHINE',
    'HKCU': 'HKEY_LOCAL_USER',
}


def read(client: MSSQLClient, hive: str, key: str, name: str) -> dict[str, Any]:
    value = regread(client, hive, key, name)
    return dict(value=value)


def regread(client: MSSQLClient, hive: str, key: str, name: str) -> str:
    rows = client.query(
        'DECLARE @value SYSNAME '
        f'EXECUTE master.dbo.xp_regread {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}, @value OUTPUT '
        'SELECT @value AS [value]'
    )
    assert len(rows) == 1 and len(rows[0]) == 1
    return rows[0]['value']


def delete(client: MSSQLClient, hive: str, key: str, name: str) -> dict[str, Any]:
    regdeletevalue(client, hive, key, name)
    return {}


def regdeletevalue(client: MSSQLClient, hive: str, key: str, name: str) -> None:
    client.query(f'EXECUTE master.dbo.xp_regdeletevalue {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}')


def regdelete(client: MSSQLClient, hive: str, key: str) -> None:
    client.query(f'EXECUTE master.dbo.xp_regdelete {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}')


def write(client: MSSQLClient, hive: str, key: str, name: str, type: str, value: str) -> dict[str, Any]:
    regwrite(client, hive, key, name, type, value)
    return {}


def regwrite(client: MSSQLClient, hive: str, key: str, name: str, type: str, value: str) -> None:
    client.query(f'EXECUTE master.dbo.xp_regwrite {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}, {client.escape_string(type)}, {client.escape_string(value)}')
