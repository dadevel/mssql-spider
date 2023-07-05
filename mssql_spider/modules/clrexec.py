from typing import Any
import hashlib

from mssql_spider.client import MSSQLClient
from mssql_spider.util import random_string


def filehash(path: str, algorithm: str) -> str:
    hash = hashlib.new(algorithm)
    with open(path, 'rb') as file:
        while True:
            bindata = file.read(4096)
            if not bindata:
                break
            hash.update(bindata)
    return hash.hexdigest()


def hexencode(path: str) -> str:
    result = []
    with open(path, 'rb') as file:
        while True:
            bindata = file.read(4096)
            if not bindata:
                break
            result.append(bindata.hex())
    return ''.join(result)


def clrexec(client: MSSQLClient, assembly_path :str, function_name: str, *function_args: str) -> dict[str, Any]:
    hash = filehash(assembly_path, 'sha512')
    hexdata = hexencode(assembly_path)
    name = filehash(assembly_path, 'md5')
    enabled = clr_enabled(client)
    trusted = assembly_trusted(client, hash)
    try:
        if not enabled:
            enable_clr(client)
        if not trusted:
            trust_assembly(client, hash, name)
        remove_assembly(client, name)
        add_assembly(client, name, hexdata, function_name, len(function_args))
        escaped_args = ','.join(client.escape_string(arg) for arg in function_args)
        rows = client.query(f'EXEC "dbo".{client.escape_identifier(name)} {escaped_args}')
        if len(rows) == 1:
            _, value = rows[0].popitem()
            value = value.rstrip()
            value = '\n' + value if '\n' in value else value
            return dict(output=value)
        else:
            return dict(rows=rows)
    finally:
        remove_assembly(client, name)
        if not trusted:
            distrust_assembly(client, hash)
        if not enabled:
            disable_clr(client)


def clr_enabled(client: MSSQLClient) -> bool:
    rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='clr enabled'");
    assert len(rows) == 1
    return bool(rows[0]['value'])


def enable_clr(client: MSSQLClient) -> None:
    client.configure('show advanced options', True)
    client.configure('clr enabled', True)


def disable_clr(client: MSSQLClient) -> None:
    client.configure('clr enabled', False)
    client.configure('show advanced options', False)


def assembly_trusted(client: MSSQLClient, hash: str) -> bool:
    rows = client.query(f'SELECT hash FROM sys.trusted_assemblies WHERE hash=0x{hash}')
    return len(rows) > 0


def trust_assembly(client: MSSQLClient, hash: str, name: str) -> None:
    client.query(f"EXEC sys.sp_add_trusted_assembly 0x{hash},N'{name},version=0.0.0.0,culture=neutral,publickeytoken=null,processorarchitecture=msil'")


def distrust_assembly(client: MSSQLClient, hash: str) -> None:
    client.query(f'EXEC sys.sp_drop_trusted_assembly 0x{hash}')


def remove_assembly(client: MSSQLClient, name: str) -> None:
    client.query(f'DROP PROCEDURE IF EXISTS {client.escape_identifier(name)} DROP ASSEMBLY IF EXISTS {client.escape_identifier(name)}')


def add_assembly(client: MSSQLClient, name: str, content: str, function: str, argc: int) -> None:
    client.query(f'CREATE ASSEMBLY {client.escape_identifier(name)} FROM 0x{content} WITH PERMISSION_SET=UNSAFE')
    # procedure must be created in separate batch
    escaped_args = ','.join(f'@{random_string(4)} nvarchar(max)' for _ in range(argc))
    client.query(f'CREATE PROCEDURE "dbo".{client.escape_identifier(name)} {escaped_args} AS EXTERNAL NAME {client.escape_identifier(name)}."StoredProcedures".{client.escape_identifier(function)}')
