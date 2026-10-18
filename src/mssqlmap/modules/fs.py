from mssqlmap.client import Client, VisitorModule
from mssqlmap.modules.exec import OleExecutor


class FileReader(VisitorModule):
    def __init__(self, path: str) -> None:
        self.path = path

    def invoke(self, client: Client) -> dict[str, str]:
        bindata = self.openrowset(client, self.path).decode(errors='surrogate-escape')
        return dict(content=bindata)

    @staticmethod
    def openrowset(client: Client, path: str) -> bytes:
        # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/openrowset-transact-sql
        rows = client.query(f'SELECT bulkcolumn FROM openrowset(BULK {client.escape_string(path)}, SINGLE_BLOB) AS x', decode=False)
        assert len(rows) == 1 and len(rows[0]) == 1
        bindata = bytes.fromhex(rows[0]['bulkcolumn'].decode('ascii'))
        return bindata


class FileWrite(VisitorModule):
    def __init__(self, local: str, remote: str) -> None:
        self.local = local
        self.remote = remote

    def invoke(self, client: Client) -> dict[str, bool]:
        with open(self.local, 'rb') as file:
            data = file.read()
        enabled = OleExecutor.ole_automation_enabled(client)
        if not enabled:
            OleExecutor.enable_ole_automation(client)
        try:
            client.query(
                "DECLARE @ob INT "
                "EXEC sp_oacreate 'ADODB.Stream', @ob OUTPUT "
                "EXEC sp_oasetproperty @ob, 'Type', 1 "
                "EXEC sp_oamethod @ob, 'Open' "
                f"EXEC sp_oamethod @ob, 'Write', NULL, 0x{data.hex()} "
                f"EXEC sp_oamethod @ob, 'SaveToFile', NULL, {client.escape_string(self.remote)}, 2 "
                "EXEC sp_oamethod @ob, 'Close' "
                "EXEC sp_oadestroy @ob"
            )
        finally:
            if not enabled:
                OleExecutor.disable_ole_automation(client)
        return dict(ok=True)
