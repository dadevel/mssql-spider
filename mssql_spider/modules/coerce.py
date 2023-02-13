from typing import Any

from mssql_spider.client import MSSQLClient
from mssql_spider.modules import fs


def dirtree(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    assert "'" not in uncpath
    client.query(f"EXEC master.sys.xp_dirtree '{uncpath}',1,1")
    return {}


def fileexist(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    assert "'" not in uncpath
    client.query(f"EXEC master.sys.xp_fileexist '{uncpath}',1,1")
    return {}


def openrowset(client: MSSQLClient, uncpath: str) -> dict[str, Any]:
    fs.openrowset(client, uncpath)
    return {}
