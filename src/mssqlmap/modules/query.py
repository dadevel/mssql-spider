from typing import Any

from mssqlmap.client import Client, VisitorModule


class QueryRunner(VisitorModule):
    def __init__(self, statement: str) -> None:
        self.statement = statement

    def invoke(self, client: Client) -> dict[str, list[dict[str, Any]]]:
        rows = client.query(self.statement)
        return dict(rows=rows)
