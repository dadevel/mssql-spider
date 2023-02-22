from typing import Any

from mssql_spider.client import MSSQLClient
from mssql_spider.modules import exec


def read(client: MSSQLClient, path: str) -> dict[str, Any]:
    bindata = openrowset(client, path).decode(errors='surrogate-escape')
    if bindata.count('\n') < 2:
        return dict(content=bindata.rstrip())
    else:
        return dict(content='\n' + bindata)


def openrowset(client: MSSQLClient, path: str) -> bytes:
    # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql
    rows = client.query(f'SELECT bulkcolumn FROM openrowset(BULK {client.escape_string(path)}, SINGLE_BLOB) AS x', decode=False)
    assert len(rows) == 1 and len(rows[0]) == 1
    bindata = bytes.fromhex(rows[0]['bulkcolumn'].decode('ascii'))
    return bindata


def write(client: MSSQLClient, local: str, remote: str) -> dict[str, Any]:
    with open(local, 'rb') as file:
        data = file.read()
    enabled = exec.ole_automation_enabled(client)
    if not enabled:
        exec.enable_ole_automation(client)
    try:
        client.query(
            "DECLARE @ob INT "
            "EXEC sp_oacreate 'ADODB.Stream', @ob OUTPUT "
            "EXEC sp_oasetproperty @ob, 'Type', 1 "
            "EXEC sp_oamethod @ob, 'Open' "
            f"EXEC sp_oamethod @ob, 'Write', NULL, 0x{data.hex()} "
            f"EXEC sp_oamethod @ob, 'SaveToFile', NULL, {client.escape_string(remote)}, 2 "
            "EXEC sp_oamethod @ob, 'Close' "
            "EXEC sp_oadestroy @ob"
        )
    finally:
        if not enabled:
            exec.disable_ole_automation(client)
    return {}
