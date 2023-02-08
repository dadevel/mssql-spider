from typing import Any

from mssql_spider.client import MSSQLClient


class ImpersonatedUser(MSSQLClient):
    def __init__(self, parent: MSSQLClient, name: str, database: str) -> None:
        super().__init__(parent.connection)
        self.parent = parent
        self.name = name
        self.database = database

    def query(self, statement: str) -> list[dict[str, Any]]:
        statement = f"EXECUTE AS user='{self.name}';{statement};REVERT"
        return self.parent.query(statement)

    def disconnect(self) -> None:
        self.parent.disconnect()

    @property
    def path(self) -> str:
        return f'{self.parent.path}~>{super().path}'
