from typing import Any

from mssqlmap.client import Client, VisitorModule

HIVES = {
    'HKLM': 'HKEY_LOCAL_MACHINE',
    'HKCU': 'HKEY_LOCAL_USER',
}


class RegistryReader(VisitorModule):
    def __init__(self, hive: str, key: str, name: str) -> None:
        self.hive = hive
        self.key = key
        self.name = name

    def invoke(self, client: Client) -> dict[str, Any]:
        value = self.regread(client, self.hive, self.key, self.name)
        return dict(value=value)

    @staticmethod
    def regread(client: Client, hive: str, key: str, name: str) -> str:
        # TODO: support recursive reading
        rows = client.query(
            'DECLARE @value SYSNAME '
            f'EXECUTE master.dbo.xp_regread {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}, @value OUTPUT '
            'SELECT @value AS [value]'
        )
        assert len(rows) == 1 and len(rows[0]) == 1
        return rows[0]['value']


class RegistryDeleter(VisitorModule):
    def __init__(self, hive: str, key: str, name: str) -> None:
        self.hive = hive
        self.key = key
        self.name = name

    def invoke(self, client: Client) -> dict[str, bool]:
        # TODO: support recursive deletion
        self.regdeletevalue(client, self.hive, self.key, self.name)
        return dict(ok=True)

    @staticmethod
    def regdeletevalue(client: Client, hive: str, key: str, name: str) -> None:
        client.query(f'EXECUTE master.dbo.xp_regdeletevalue {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}')

    @staticmethod
    def regdelete(client: Client, hive: str, key: str) -> None:
        client.query(f'EXECUTE master.dbo.xp_regdelete {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}')


class RegistryWrite(VisitorModule):
    def __init__(self, hive: str, key: str, name: str, type: str, value: str) -> None:
        self.hive = hive
        self.key = key
        self.name = name
        self.type = type
        self.value = value

    def invoke(self, client: Client) -> dict[str, bool]:
        # TODO: create parent keys if necessary
        self.regwrite(client, self.hive, self.key, self.name, self.type, self.value)
        return dict(ok=True)

    @staticmethod
    def regwrite(client: Client, hive: str, key: str, name: str, type: str, value: str) -> None:
        client.query(f'EXECUTE master.dbo.xp_regwrite {client.escape_string(HIVES.get(hive, hive))}, {client.escape_string(key)}, {client.escape_string(name)}, {client.escape_string(type)}, {client.escape_string(value)}')
