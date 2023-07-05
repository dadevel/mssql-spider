from __future__ import annotations
from typing import Any, Callable, TypedDict, TYPE_CHECKING

import logging
import socket

from impacket.tds import MSSQL, SQLErrorException

from mssql_spider import log

if TYPE_CHECKING:
    from mssql_spider.linked_instance import LinkedInstance
    from mssql_spider.impersonated_user import ImpersonatedUser


class UserInfo(TypedDict):
    host: str
    login: str
    user: str
    roles: set[str]


class ImpersonationInfo(TypedDict):
    mode: str
    database: str
    grantee: str
    grantor: str


class InstanceInfo(TypedDict):
    local_login: str
    remote_login: str


class DatabaseInfo(TypedDict):
    name: str
    owner: str
    trusted: bool
    encrypted: bool
    accessible: bool


class MSSQLClient:
    def __init__(self, connection: MSSQL, seen: set[str]|None = None) -> None:
        self.connection = connection
        self.seen = seen if seen else set()

    @classmethod
    def connect(cls, address: str, port: int, timeout: int = 10) -> MSSQLClient:
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(address, port, family=0, type=socket.SOCK_STREAM)[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        connection = MSSQL(address, port)
        connection.socket = sock
        return cls(connection)

    def login(self, domain: str = '', username: str = '', password: str = '', hashes: str|None = None, aes_key: str = '', windows_auth: bool = False, kerberos: bool = False, kdc_host: str|None = None, database: str|None = None) -> MSSQLClient:
        if kerberos:
            ok = self.connection.kerberosLogin(database, username, password, domain, hashes, aes_key, kdcHost=kdc_host)
        else:
            ok = self.connection.login(database, username, password, domain, hashes, windows_auth)
        self.connection.printReplies()  # sets _connection.lastError
        if not ok:
            error = self.connection.lastError if isinstance(self.connection.lastError, Exception) else SQLErrorException(self.connection.lastError) if self.connection.lastError else SQLErrorException('authentication failed for unknown reason')
            raise error
        return self

    def disconnect(self) -> None:
        self.connection.disconnect()

    def query(self, statement: str, decode: bool = True) -> list[dict[str, Any]]:
        statement.strip(' ;')
        logging.debug(f'{self.connection.server}:{self.connection.port}:sql:query:{statement}')
        # sets _connection.replies and returns results
        rows: list[dict[str, Any]] = self.connection.sql_query(statement)  # type: ignore
        if decode:
            rows = [
                {
                    key: value.decode(errors='surrogate-escape') if isinstance(value, bytes) else value
                    for key, value in row.items()
                }
                for row in rows
            ]
        self.connection.printReplies()  # gets _connection.replies and sets _connection.lastError
        if self.connection.lastError:
            error = self.connection.lastError if isinstance(self.connection.lastError, Exception) else SQLErrorException(self.connection.lastError) if self.connection.lastError else SQLErrorException('query failed for unknown reason')
            logging.debug(f'{self.connection.server}:{self.connection.port}:sql:error:{error}')
            raise error
        logging.debug(f'{self.connection.server}:{self.connection.port}:sql:result:{rows}')
        return rows

    def query_single(self, statement: str, decode: bool = True) -> dict[str, Any]:
        rows = self.query(statement, decode=decode)
        assert len(rows) == 1
        return rows[0]

    def query_database(self, database: str, statement: str, decode: bool = True) -> list[dict[str, Any]]:
        rows = self.query('SELECT db_name() AS [db]')
        assert len(rows) == 1 and len(rows[0]) == 1
        prev = rows[0]['db']
        rows = self.query(f'USE {self.escape_identifier(database)};{statement};USE {self.escape_identifier(prev)}', decode=decode)
        return rows

    def ping(self) -> MSSQLClient:
        self.query('SELECT 1')
        return self

    @property
    def hostname(self) -> str:
        return self.whoami()['host']

    @property
    def username(self) -> str:
        return self.whoami()['user']

    def whoami(self) -> UserInfo:
        try:
            return self._userinfo  # type: ignore
        except Exception:
            pass
        rows = self.query("SELECT system_user AS [login], user_name() AS [user], convert(varchar(max), serverproperty('MachineName')) AS [host]")
        assert len(rows) == 1 and len(rows[0]) == 3
        self._userinfo = dict(
            host=rows[0]['host'].lower(),
            login=rows[0]['login'].lower(),
            user=rows[0]['user'].lower(),
            roles=self.roles(),
        )
        return self._userinfo  # type: ignore

    def roles(self) -> set[str]:
        #roles = {row['name'] for row in self.query("SELECT name FROM sys.database_principals WHERE type IN ('R','G') AND type_desc='DATABASE_ROLE' AND is_member(name)=1")}
        builtin_roles = 'sysadmin setupadmin serveradmin securityadmin processadmin diskadmin dbcreator bulkadmin'.split(' ')
        custom_roles = [row['name'] for row in self.query("SELECT name FROM sysusers WHERE issqlrole=1")]
        statement = ','.join(f"is_srvrolemember({self.escape_string(role)}) AS {self.escape_identifier(role)}" for role in builtin_roles + custom_roles)
        rows = self.query(f'SELECT {statement}')
        assert len(rows) == 1 and len(rows[0]) == len(builtin_roles) + len(custom_roles)
        return {key for key, value in rows[0].items() if value}

    def databases(self) -> dict[str, DatabaseInfo]:
        rows = self.query('SELECT name, suser_sname(owner_sid) AS [owner], is_trustworthy_on AS [trusted], is_encrypted AS [encrypted], has_dbaccess(name) AS [accessible] FROM sys.databases')
        databases = {row['name']: row for row in rows}
        return databases  # type: ignore

    def columns(self, pattern: str = '%passw%') -> list[dict[str, Any]]:
        results = []
        for database in self.databases():
            rows = self.query_database(database, f"SELECT {self.escape_string(database)} AS [database], table_name AS [table], column_name AS [column], data_type AS [type] FROM information_schema.columns WHERE column_name LIKE {self.escape_string(pattern)}")
            results.extend(rows)
        return results

    def spider(self, visitor: Callable[[MSSQLClient], Any]|None = None, max_depth: int = 10, depth: int = 0) -> MSSQLClient:
        if depth >= max_depth:
            raise RecursionError('maximum recursion depth exceeded')

        # FIXME in rare cases the whoami query fails for a unknown reason
        try:
            if self.id in self.seen:
                log.spider_status(self, 'repeated')
                return self
        except (SQLErrorException) as e:
            log.general_error((self.connection.server, self.connection.port), 'spider', e)
            logging.error(f'{self.connection.server}:{self.connection.port}: {e}')
            return self
        self.seen.add(self.id)

        log.spider_status(self, 'pwned' if 'sysadmin' in self.whoami()['roles'] else 'allowed')

        if visitor:
            visitor(self)

        self.spider_impersonations(visitor, max_depth, depth)
        self.spider_links(visitor, max_depth, depth)

        return self

    def spider_impersonations(self, visitor: Callable[[MSSQLClient], Any]|None, max_depth: int, depth: int) -> None:
        for login in self.enum_impersonation():
            try:
                child = self.impersonate(login['mode'], login['grantor'])
            except (SQLErrorException) as e:
                log.spider_status(self, 'denied', path=f'->{login["grantor"]}', message=str(e).removeprefix('ERROR: Line 1: '))
                logging.warning(f'{self.connection.server}:{self.connection.port}:could not impersonate {login["mode"]} {login["grantor"]} on {self.id}: {e}')
            else:
                child.spider(visitor, max_depth=max_depth, depth=depth + 1)

    def spider_links(self, visitor: Callable[[MSSQLClient], Any]|None, max_depth: int, depth: int) -> None:
        for instance_name in self.enum_links():
            child = None

            try:
                child = self.use_rpc_link(instance_name)
            except (SQLErrorException) as e:
                log.spider_status(self, 'denied', path=f'=>{instance_name}', message=str(e).removeprefix('ERROR: Line 1: '))
                logging.warning(f'{self.connection.server}:{self.connection.port}:could not use link from {self.id} to {instance_name} via rpc: {e}')
            if child:
                child.spider(visitor, max_depth=max_depth, depth=depth + 1)
                continue

            # when link fails due to rpc error try again with openquery
            try:
                child = self.use_query_link(instance_name)
            except (SQLErrorException) as e:
                log.spider_status(self, 'denied', path=f'=>{instance_name}', message=str(e).removeprefix('ERROR: Line 1: '))
                logging.warning(f'{self.connection.server}:{self.connection.port}:could not use link from {self.id} to {instance_name} via query: {e}')
            if child:
                child.spider(visitor, max_depth=max_depth, depth=depth + 1)
                continue

    def enum_links(self) -> dict[str, InstanceInfo]:
        # TODO: implement "SELECT srvname, srvproduct, rpcout FROM master.sys.sysservers"
        # sometimes sp_helplinkedsrvlogin does not return results but sp_linkedservers does
        try:
            a = {
                row['SRV_NAME']: dict(local_login='NULL', remote_login='NULL')
                for row in self.query('EXEC sp_linkedservers')
            }
            b = {
                row['Linked Server']: dict(local_login=row['Local Login'], remote_login=row['Remote Login'])
                for row in self.query('EXEC sp_helplinkedsrvlogin')
            }
            return a | b  # type: ignore
        except (SQLErrorException):
            return {}

    def use_rpc_link(self, link: str) -> LinkedInstance:
        from mssql_spider.linked_instance import LinkedRpcInstance
        client = LinkedRpcInstance(self, link, seen=self.seen)
        client.ping()
        return client

    def use_query_link(self, link: str) -> LinkedInstance:
        from mssql_spider.linked_instance import LinkedQueryInstance
        client = LinkedQueryInstance(self, link, seen=self.seen)
        client.ping()
        return client

    def enum_impersonation(self) -> list[ImpersonationInfo]:
        results = []
        if self.whoami()['user'] == 'dbo' and self.whoami()['login'] != 'sa':
            results.append(dict(mode='login', database='master', grantee='NULL', grantor='sa'))
        try:
            for database in self.databases():
                try:
                    results += self.query_database(database, "SELECT 'login' as [mode], db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.server_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
                    results += self.query_database(database, f"SELECT 'user' as [mode], db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.database_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
                except (SQLErrorException):
                    pass
            return results  # type: ignore
        except (SQLErrorException):
            return []

    def impersonate(self, mode: str, name: str) -> ImpersonatedUser:
        from mssql_spider.impersonated_user import ImpersonatedUser
        client = ImpersonatedUser(self, name, mode=mode, seen=self.seen)
        client.ping()
        return client

    @property
    def id(self) -> str:
        return f'{self.username}@{self.hostname}'

    @property
    def path(self) -> str:
        return self.id

    def configure(self, option: str, enabled: bool) -> None:
        value = 1 if enabled else 0
        self.query(f"EXEC master.dbo.sp_configure {self.escape_string(option)},{value};RECONFIGURE;")

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
