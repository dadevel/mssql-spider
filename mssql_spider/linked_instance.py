from typing import Any

from mssql_spider.client import MSSQLClient


class LinkedInstance(MSSQLClient):
    def __init__(self, parent: MSSQLClient, name: str, seen: set[str]) -> None:
        super().__init__(parent.connection, seen)
        self.parent = parent
        self.name = name

    def query(self, statement: str, decode: bool = True) -> list[dict[str, Any]]:
        assert '[' not in self.name and ']' not in self.name
        statement = f'EXEC ({self.escape_string(statement)}) AT {self.escape_identifier(self.name)}'
        return self.parent.query(statement, decode=decode)

    def disconnect(self) -> None:
        self.parent.disconnect()

    @property
    def path(self) -> str:
        return f'{self.parent.path}=>{super().path}'
