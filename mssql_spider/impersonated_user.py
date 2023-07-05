from typing import Any

from mssql_spider.client import MSSQLClient


class ImpersonatedUser(MSSQLClient):
    def __init__(self, parent: MSSQLClient, name: str, mode: str, seen: set[str]) -> None:
        super().__init__(parent.connection, seen)
        assert mode in ('login', 'user')
        self.parent = parent
        self.mode = mode
        self.name = name

    def query(self, statement: str, decode: bool = True) -> list[dict[str, Any]]:
        statement = f'EXECUTE AS {self.mode}={self.escape_string(self.name)};{statement};REVERT'
        return self.parent.query(statement, decode=decode)

    def disconnect(self) -> None:
        self.parent.disconnect()

    @property
    def path(self) -> str:
        return f'{self.parent.path}->{super().path}'
