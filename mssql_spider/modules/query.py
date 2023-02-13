from typing import Any

from mssql_spider.client import MSSQLClient


def run(client: MSSQLClient, statement: str) -> dict[str, Any]:
    rows = client.query(statement)
    if len(rows) == 0:
        return dict()
    elif len(rows) == 1:
        return rows[0]
    else:
        return dict(rows=rows)
