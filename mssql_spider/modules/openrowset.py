from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    bindata = openrowset(client, opts.openrowset).decode(errors='surrogate-escape')
    if bindata.count('\n') < 2:
        return dict(content=bindata.rstrip())
    else:
        return dict(content='\n' + bindata)


def openrowset(client: MSSQLClient, path: str) -> bytes:
    # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql
    rows = client.query(f"SELECT bulkcolumn FROM openrowset(BULK '{path}', SINGLE_BLOB) AS x", decode=False)
    assert len(rows) == 1 and len(rows[0]) == 1
    bindata = bytes.fromhex(rows[0]['bulkcolumn'].decode('ascii'))
    return bindata
