from __future__ import annotations
from typing import Any, Callable, TypedDict, TYPE_CHECKING

import logging
import re
import socket

from impacket.tds import MSSQL, SQLErrorException

from mssql_spider import log

if TYPE_CHECKING:
    from mssql_spider.linked_instance import LinkedInstance
    from mssql_spider.impersonated_user import ImpersonatedUser


class SQLPermissionError(SQLErrorException):
    def __init__(self, message: str) -> None:
        super().__init__(message)


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
    instance: str
    local_login: str
    remote_login: str


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

    def login(self, database: str|None, username: str, password: str, domain: str, hashes: str|None, aes_key: str, kdc_host: str|None, windows_auth: bool, kerberos: bool) -> MSSQLClient:
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

    def query_database(self, database: str, statement: str, decode: bool = True) -> list[dict[str, Any]]:
        rows = self.query('SELECT db_name() AS [db]')
        assert len(rows) == 1 and len(rows[0]) == 1
        prev = rows[0]['db']
        try:
            rows = self.query(f'USE {self.escape_identifier(database)};{statement};USE {self.escape_identifier(prev)}', decode=decode)
        except SQLErrorException as e:
            if re.search(r'The server principal .+? is not able to access the database .+? under the current security context', e.args[0]):
                raise SQLPermissionError(e.args[0]) from e
            else:
                raise e
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

    def databases(self) -> set[str]:
        rows = self.query('SELECT name FROM sys.databases')
        databases = {row['name'] for row in rows}
        return databases

    def spider(self, visitor: Callable[[MSSQLClient], Any]|None = None, max_depth: int = 10, depth: int = 0) -> MSSQLClient:
        if depth >= max_depth:
            raise RecursionError('maximum recursion depth exceeded')

        # FIXME in rare cases the whoami query fails for a unknown reason
        try:
            if self.id in self.seen:
                log.spider_status(self, 'repeated')
                return self
        except SQLErrorException as e:
            log.general_error((self.connection.server, self.connection.port), 'spider', e)
            logging.exception(e)
            return self
        self.seen.add(self.id)

        log.spider_status(self, 'pwned' if 'sysadmin' in self.whoami()['roles'] else 'allowed')

        if visitor:
            visitor(self)

        for login in self.enum_impersonation():
            try:
                child = self.impersonate(login['mode'], login['grantor'])
            except (TimeoutError, SQLErrorException) as e:
                log.spider_status(self, 'denied', path=f'->{login["grantor"]}')
                logging.warning(f'{self.connection.server}:{self.connection.port}:could not impersonate {login["mode"]} {login["grantor"]} on {self.id}: {e}')
            else:
                child.spider(visitor, max_depth=max_depth, depth=depth + 1)

        for link in self.enum_links():
            try:
                child = self.use_link(link['instance'])
            except (TimeoutError, SQLErrorException) as e:
                log.spider_status(self, 'denied', path=f'=>{link["instance"]}')
                logging.warning(f'{self.connection.server}:{self.connection.port}:could not use link from {self.id} to {link["instance"]}: {e}')
            else:
                child.spider(visitor, max_depth=max_depth, depth=depth + 1)

        return self

    def enum_links(self) -> list[InstanceInfo]:
        # sometimes sp_helplinkedsrvlogin does not return results but sp_linkedservers does
        rows = self.query('EXEC sp_linkedservers')
        results = [dict(instance=row['SRV_NAME']) for row in rows]
        rows = self.query('EXEC sp_helplinkedsrvlogin')
        results += [dict(instance=row['Linked Server'], local_login=row['Local Login'], remote_login=row['Remote Login']) for row in rows if row['Local Login'] != 'NULL']
        return results  # type: ignore

    def use_link(self, link: str) -> LinkedInstance:
        from mssql_spider.linked_instance import LinkedInstance
        client = LinkedInstance(self, link, seen=self.seen)
        client.ping()
        return client

    def enum_impersonation(self) -> list[ImpersonationInfo]:
        results = []
        for database in self.databases():
            try:
                results += self.query_database(database, "SELECT 'login' as [mode], db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.server_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
                results += self.query_database(database, f"SELECT 'user' as [mode], db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.database_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
            except SQLPermissionError:
                pass
        return results  # type: ignore

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
