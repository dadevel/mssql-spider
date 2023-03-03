from typing import Any

from mssql_spider.client import MSSQLClient


def run(client: MSSQLClient, statement: str) -> dict[str, Any]:
    rows = client.query(statement)
    if len(rows) == 0:
        return dict()
    elif len(rows) == 1:
        first_key = next(iter(rows[0].keys()))
        if not first_key:
            return dict(value=rows[0][first_key])
        else:
            return rows[0]
    else:
        return dict(rows=rows)
