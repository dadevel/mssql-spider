from typing import Any
import hashlib

from mssqlmap.client import Client, VisitorModule
from mssqlmap.util import random_string


class ClrExecutor(VisitorModule):
    def __init__(self, assembly_path: str, function_name: str, *function_args: str) -> None:
        self.assembly_path = assembly_path
        self.function_name = function_name
        self.function_args = function_args

    def invoke(self, client: Client) -> dict[str, list[dict[str, Any]]]:
        hash = self.filehash(self.assembly_path, 'sha512')
        hexdata = self.hexencode(self.assembly_path)
        name = self.filehash(self.assembly_path, 'md5')
        enabled = self.clr_enabled(client)
        trusted = self.assembly_trusted(client, hash)
        try:
            if not enabled:
                self.enable_clr(client)
            if not trusted:
                self.trust_assembly(client, hash, name)
            self.remove_assembly(client, name)
            self.add_assembly(client, name, hexdata, self.function_name, len(self.function_args))
            escaped_args = ','.join(client.escape_string(arg) for arg in self.function_args)
            rows = client.query(f'EXEC "dbo".{client.escape_identifier(name)} {escaped_args}')
            return dict(rows=rows)
        finally:
            self.remove_assembly(client, name)
            if not trusted:
                self.distrust_assembly(client, hash)
            if not enabled:
                self.disable_clr(client)

    @staticmethod
    def clr_enabled(client: Client) -> bool:
        rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='clr enabled'");
        assert len(rows) == 1
        return bool(rows[0]['value'])

    @staticmethod
    def enable_clr(client: Client) -> None:
        client.configure('show advanced options', True)
        client.configure('clr enabled', True)

    @staticmethod
    def disable_clr(client: Client) -> None:
        client.configure('clr enabled', False)
        client.configure('show advanced options', False)

    @staticmethod
    def assembly_trusted(client: Client, hash: str) -> bool:
        rows = client.query(f'SELECT hash FROM sys.trusted_assemblies WHERE hash=0x{hash}')
        return len(rows) > 0

    @staticmethod
    def trust_assembly(client: Client, hash: str, name: str) -> None:
        client.query(f"EXEC sys.sp_add_trusted_assembly 0x{hash},N'{name},version=0.0.0.0,culture=neutral,publickeytoken=null,processorarchitecture=msil'")

    @staticmethod
    def distrust_assembly(client: Client, hash: str) -> None:
        client.query(f'EXEC sys.sp_drop_trusted_assembly 0x{hash}')

    @staticmethod
    def remove_assembly(client: Client, name: str) -> None:
        client.query(f'DROP PROCEDURE IF EXISTS {client.escape_identifier(name)} DROP ASSEMBLY IF EXISTS {client.escape_identifier(name)}')

    @staticmethod
    def add_assembly(client: Client, name: str, content: str, function: str, argc: int) -> None:
        client.query(f'CREATE ASSEMBLY {client.escape_identifier(name)} FROM 0x{content} WITH PERMISSION_SET=UNSAFE')
        # procedure must be created in separate batch
        escaped_args = ','.join(f'@{random_string(4)} nvarchar(max)' for _ in range(argc))
        client.query(f'CREATE PROCEDURE "dbo".{client.escape_identifier(name)} {escaped_args} AS EXTERNAL NAME {client.escape_identifier(name)}."StoredProcedures".{client.escape_identifier(function)}')

    @staticmethod
    def filehash(path: str, algorithm: str) -> str:
        hash = hashlib.new(algorithm)
        with open(path, 'rb') as file:
            while True:
                bindata = file.read(4096)
                if not bindata:
                    break
                hash.update(bindata)
        return hash.hexdigest()

    @staticmethod
    def hexencode(path: str) -> str:
        result = []
        with open(path, 'rb') as file:
            while True:
                bindata = file.read(4096)
                if not bindata:
                    break
                result.append(bindata.hex())
        return ''.join(result)
