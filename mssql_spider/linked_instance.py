from typing import Any

from mssql_spider.client import MSSQLClient


class LinkedInstance(MSSQLClient):
    def __init__(self, parent: MSSQLClient, name: str) -> None:
        super().__init__(parent.connection)
        self.parent = parent
        self.name = name

    def query(self, statement: str) -> list[dict[str, Any]]:
        assert '[' not in self.name and ']' not in self.name
        statement = statement.replace("'", "''")
        statement = f"EXEC ('{statement}') AT [{self.name}]"
        return self.parent.query(statement)

    def disconnect(self) -> None:
        self.parent.disconnect()

    @property
    def path(self) -> str:
        return f'{self.parent.path}=>{super().path}'
