from typing import Any

from mssql_spider.client import MSSQLClient


def read(client: MSSQLClient, hive: str, key: str, name: str) -> dict[str, Any]:
    value = regread(client, hive, key, name)
    return dict(value=value)


def regread(client: MSSQLClient, hive: str, key: str, name: str) -> str:
    assert "'" not in hive
    assert "'" not in key
    assert "'" not in name
    rows = client.query(
        'DECLARE @value SYSNAME '
        f"EXECUTE master.dbo.xp_regread N'{hive}', N'{key}', N'{name}', @value OUTPUT "
        'SELECT @value AS [value]'
    )
    assert len(rows) == 1 and len(rows[0]) == 1
    return rows[0]['value']


def delete(client: MSSQLClient, hive: str, key: str, name: str) -> dict[str, Any]:
    regdeletevalue(client, hive, key, name)
    return {}


def regdeletevalue(client: MSSQLClient, hive: str, key: str, name: str) -> None:
    assert "'" not in hive
    assert "'" not in key
    assert "'" not in name
    client.query(f"EXECUTE master.dbo.xp_regdeletevalue N'{hive}', N'{key}', N'{name}'")


def regdelete(client: MSSQLClient, hive: str, key: str) -> None:
    assert "'" not in hive
    assert "'" not in key
    client.query(f"EXECUTE master.dbo.xp_regdelete N'{hive}', N'{key}'")


def write(client: MSSQLClient, hive: str, key: str, name: str, type: str, value: str) -> dict[str, Any]:
    regwrite(client, hive, key, name, type, value)
    return {}


def regwrite(client: MSSQLClient, hive: str, key: str, name: str, type: str, value: str) -> None:
    assert "'" not in hive
    assert "'" not in key
    assert "'" not in name
    assert "'" not in type
    assert "'" not in value
    client.query(f"EXECUTE master.dbo.xp_regwrite N'{hive}', N'{key}', N'{name}', N'{type}', {value}")
