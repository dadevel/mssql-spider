from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visitor(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    xp_fileexist(client, opts.fileexist)
    return {}


def xp_fileexist(client: MSSQLClient, uncpath: str) -> None:
    assert "'" not in uncpath
    client.query(f"EXEC master.sys.xp_fileexist '{uncpath}',1,1")
