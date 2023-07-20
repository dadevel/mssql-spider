from __future__ import annotations
from typing import Any, Generator, TypedDict

import logging

from mssqlmap.connection import Connection


class BaseModule:
    def __repr__(self) -> str:
        attrs = ', '.join(f'{k}={v!r}' for k, v in self.__dict__.items())
        return f'{self.__class__.__name__}({attrs})'


class SpiderModule(BaseModule):
    def spider(self, client: Client) -> Generator[Client, None, None]:
        raise NotImplementedError()


class VisitorModule(BaseModule):
    def invoke(self, client: Client) -> dict[str, Any]|None:
        raise NotImplementedError()


class UserInfo(TypedDict):
    computer: str
    instance: str
    login: str
    user: str
    roles: list[str]
    pwned: bool


class DatabaseInfo(TypedDict):
    name: str
    owner: str
    trusted: bool
    encrypted: bool
    accessible: bool


class Client:
    def __init__(self, connection: Connection, parent: Client|None = None, children: list[Client]|None = None, seen: set[str]|None = None) -> None:
        self.connection = connection
        self.parent = parent
        self.seen = seen or set()
        self.children = children or []

    def __enter__(self) -> Client:
        self.connect()
        return self

    def __exit__(self, type, value, traceback) -> None:
        self.disconnect()

    def connect(self) -> Client:
        self.connection.connect()
        self.connection.login()
        return self

    def disconnect(self) -> None:
        for child in self.children:
            child.disconnect()
        self.connection.disconnect()

    def reconnect(self) -> Client:
        self.disconnect()
        self.connection = self.connection.duplicate()
        self.connect()
        return self

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.path})'

    @property
    def id(self) -> str:
        # multiple logins that map to the same user are not always equal, for example the login matters for the login mapping of linked instances
        return f'{self.login}:{self.username}@{self.hostname}:{self.instance}'

    @property
    def path(self) -> str:
        return self.id

    @property
    def login(self) -> str:
        return self.whoami()['login']

    @property
    def username(self) -> str:
        return self.whoami()['user']

    @property
    def hostname(self) -> str:
        return self.whoami()['computer']

    @property
    def instance(self) -> str:
        return self.whoami()['instance']

    @property
    def pwned(self) -> bool:
        return self.whoami()['pwned']

    def whoami(self) -> UserInfo:
        try:
            return self._userinfo
        except Exception:
            pass
        row = self.query_single("SELECT system_user AS [login], user_name() AS [user], convert(varchar(max), serverproperty('ComputerNamePhysicalNetBIOS')) AS [computer], convert(varchar(max), serverproperty('InstanceName')) AS [instance]")
        assert len(row) == 4
        roles = self.roles()
        self._userinfo: UserInfo = {
            'computer': row['computer'].lower(),
            'instance': row['instance'].lower(),
            'login': row['login'].lower(),
            'user': row['user'].lower(),
            'roles': list(roles),
            'pwned': 'sysadmin' in roles,
        }
        return self._userinfo

    def roles(self) -> set[str]:
        #roles = {row['name'] for row in self.query("SELECT name FROM sys.database_principals WHERE type IN ('R','G') AND type_desc='DATABASE_ROLE' AND is_member(name)=1")}
        builtin_roles = 'sysadmin setupadmin serveradmin securityadmin processadmin diskadmin dbcreator bulkadmin'.split(' ')
        custom_roles = [row['name'] for row in self.query("SELECT name FROM sysusers WHERE issqlrole=1")]
        statement = ','.join(f"is_srvrolemember({self.escape_string(role)}) AS {self.escape_identifier(role)}" for role in builtin_roles + custom_roles)
        row = self.query_single(f'SELECT {statement}')
        assert len(row) == len(builtin_roles) + len(custom_roles)
        return {key.lower() for key, value in row.items() if value}

    def query(self, statement: str, decode: bool = True, ignore_errors: bool = False) -> list[dict[str, Any]]:
        statement = statement.strip(' ;')
        logging.debug(f'{self.connection.host}:{self.connection.port}:sql:query:{statement}')
        # sets wrapped._connection.replies and returns results
        rows = self.connection.wrapped.sql_query(statement)
        assert isinstance(rows, list)
        if decode:
            rows = [
                {
                    key: value.decode(errors='surrogate-escape') if isinstance(value, bytes) else value
                    for key, value in row.items()
                }
                for row in rows
            ]
        self.connection.wrapped.printReplies()  # gets wrapped._connection.replies and sets wrapped._connection.lastError
        error = self.connection.last_error()
        if error:
            logging.debug(f'{self.connection.host}:{self.connection.port}:sql:error:{error}')
            if not ignore_errors:
                raise error
        logging.debug(f'{self.connection.host}:{self.connection.port}:sql:result:{rows}')
        return rows

    def query_single(self, statement: str, decode: bool = True, ignore_errors: bool = False) -> dict[str, Any]:
        rows = self.query(statement, decode=decode, ignore_errors=ignore_errors)
        assert len(rows) == 1
        return rows[0]

    def query_database(self, database: str, statement: str, decode: bool = True, ignore_errors: bool = False) -> list[dict[str, Any]]:
        row = self.query_single('SELECT db_name() AS [db]')
        assert len(row) == 1
        prev = row['db']
        rows = self.query(f'USE {self.escape_identifier(database)};{statement};USE {self.escape_identifier(prev)}', decode=decode, ignore_errors=ignore_errors)
        return rows

    def invoke(self, modules: list[VisitorModule]) -> Generator[tuple[VisitorModule, dict[str, Any]], None, None]:
        for module in modules:
            try:
                result = module.invoke(self)
                if result is not None:
                    yield module, result
            except Exception as e:
                yield module, dict(error=str(e), type=e.__class__.__name__)

    def spider(self, modules: list[SpiderModule], max_depth: int = 10, depth: int = 0) -> Generator[tuple[Client, SpiderModule|None, str], None, None]:
        if depth == 0:
            self.seen.clear()
            self.seen.add(self.id)
            yield self, None, 'pwned' if self.pwned else 'accepted'

        for module in modules:
            for client in module.spider(self):
                if isinstance(client, BrokenClient):
                    yield client, module, 'denied'
                elif client.id in self.seen:
                    yield client, module, 'repeated'
                else:
                    self.seen.add(client.id)
                    self.children.append(client)
                    yield client, module, 'pwned' if self.pwned else 'accepted'
                    if depth >= max_depth:
                        raise RecursionError('maximum recursion depth exceeded')
                    yield from client.spider(modules, max_depth, depth + 1)

    def test(self) -> bool:
        self.query_single('SELECT 1')
        return True

    def configure(self, option: str, enabled: bool) -> None:
        value = 1 if enabled else 0
        self.query(f"EXEC master.dbo.sp_configure {self.escape_string(option)},{value};RECONFIGURE;")

    def enum_databases(self) -> dict[str, DatabaseInfo]:
        rows = self.query('SELECT name, suser_sname(owner_sid) AS [owner], is_trustworthy_on AS [trusted], is_encrypted AS [encrypted], has_dbaccess(name) AS [accessible] FROM sys.databases')
        databases = {row['name']: row for row in rows}
        return databases  # type: ignore

    def enum_columns(self, pattern: str = '%') -> list[dict[str, Any]]:
        results = []
        for database in self.enum_databases():
            rows = self.query_database(database, f"SELECT {self.escape_string(database)} AS [database], table_name AS [table], column_name AS [column], data_type AS [type] FROM information_schema.columns WHERE column_name LIKE {self.escape_string(pattern)}")
            results.extend(rows)
        return results

    @staticmethod
    def escape_identifier(value: str) -> str:
        """
        Escapes a string for use as database identifier.
        """
        value = value.replace('"', '""')
        return f'"{value}"'

    @staticmethod
    def escape_string(value: str) -> str:
        """
        Escapes a string for use as string literal.
        """
        value = value.replace("'", "''")
        return f"'{value}'"


class BrokenClient(Client):
    def __init__(self, parent: Client, error: Exception, login: str|None = None, user: str|None = None, hostname: str|None = None, instance: str|None = None) -> None:
        super().__init__(parent.connection, parent)
        self.error = error
        self._login = login or parent.login
        self._username = user or parent.username
        self._hostname = hostname or parent.hostname
        self._instance = instance or parent.instance

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.path}, error={self.error})'

    @property
    def login(self) -> str:
        return self._login

    @property
    def username(self) -> str:
        return self._username

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def instance(self) -> str:
        return self._instance

    @property
    def pwned(self) -> bool:
        return False

    def roles(self) -> set[str]:
        return set()

    def whoami(self) -> UserInfo:
        return {
            'computer': self.hostname,
            'instance': self.instance,
            'login': self.login,
            'user': self.username,
            'roles': [],
            'pwned': self.pwned,
        }

    def query(self, *args, **kwargs) -> Any:
        raise RuntimeError('can not query broken client')
