from typing import Any, Generator, TypedDict

from mssqlmap.client import BrokenClient, Client, SpiderModule
from mssqlmap.connection import SQLErrorException


class ImpersonatedUser(Client):
    SIGN = '->'

    def __init__(self, name: str, mode: str, parent: Client, children: list[Client]|None = None, seen: set[str]|None = None) -> None:
        super().__init__(parent.connection, parent, children, seen)
        self.parent: Client  # make type checker happy
        assert mode in ('login', 'user')
        self.name = name
        self.mode = mode

    def query(self, statement: str, decode: bool = True, ignore_errors: bool = False) -> list[dict[str, Any]]:
        self.parent.query(f'EXECUTE AS {self.mode}={self.escape_string(self.name)}')
        try:
            return self.parent.query(statement, decode=decode, ignore_errors=ignore_errors)
        finally:
            self.parent.query('REVERT')

    def disconnect(self) -> None:
        for child in self.children:
            child.disconnect()

    @property
    def path(self) -> str:
        match self.mode:
            case 'login':
                return f'{self.parent.path}{self.SIGN}{self.login}:{self.username}'
            case 'user':
                return f'{self.parent.path}{self.SIGN}{self.login}:{self.username}'
            case _:
                raise RuntimeError('unreachable')


class BrokenImpersonatedUser(BrokenClient):
    @property
    def path(self) -> str:
        return f'{self.parent.path if self.parent else ""}{ImpersonatedUser.SIGN}{super().path}'


class ImpersonationInfo(TypedDict):
    mode: str
    database: str
    grantee: str
    grantor: str


class ImpersonationSpider(SpiderModule):
    def spider(self, client: Client) -> Generator[Client, None, None]:
        for row in self.enum_impersonation(client):
            child = ImpersonatedUser(row['grantor'], row['mode'], client, None, client.seen)
            try:
                child.test()
                yield child
            except SQLErrorException as e:
                attrs = {row['mode']: row['grantor']}
                yield BrokenImpersonatedUser(client, e, **attrs)

    def enum_impersonation(self, client: Client) -> list[ImpersonationInfo]:
        results = []

        if client.whoami()['user'] == 'dbo':
            results.append(dict(mode='login', database='', grantee='sa', grantor='sa'))

        results += self.enum_logins(client)
        results += self.enum_users(client)
        return results

    @staticmethod
    def enum_logins(client: Client) -> list[ImpersonationInfo]:
        result = client.query("SELECT 'login' as [mode], '' AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.server_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
        return result  # type: ignore

    @staticmethod
    def enum_users(client: Client) -> list[ImpersonationInfo]:
        results = []
        for database in client.enum_databases():
            try:
                results += client.query_database(database, f"SELECT 'user' as [mode], db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.database_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
            except SQLErrorException:
                # current user is not allowed to access the database
                pass
        return results
