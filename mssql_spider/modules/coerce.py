from typing import Any

from mssql_spider.client import MSSQLClient
from mssql_spider.modules import fs


def dirtree(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    client.query(f"EXEC master.sys.xp_dirtree {client.escape_string(uncpath)},1,1")
    return {}


def fileexist(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    client.query(f"EXEC master.sys.xp_fileexist {client.escape_string(uncpath)},1,1")
    return {}


def openrowset(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    fs.openrowset(client, uncpath)
    return {}
