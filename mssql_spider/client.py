from __future__ import annotations
from typing import Any, Callable, TypedDict, TYPE_CHECKING

import logging
import re
import socket

from impacket.tds import MSSQL, SQLErrorException

if TYPE_CHECKING:
    from mssql_spider.linked_instance import LinkedInstance
    from mssql_spider.impersonated_login import ImpersonatedLogin
    from mssql_spider.impersonated_user import ImpersonatedUser

class MSSQLError(RuntimeError):
    pass


class SQLPermissionError(SQLErrorException):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class UserInfo(TypedDict):
    host: str
    login: str
    user: str
    roles: set[str]


class ImpersonationInfo(TypedDict):
    database: str
    grantee: str
    grantor: str


class InstanceInfo(TypedDict):
    instance: str
    local_login: str
    remote_login: str


class LinkError(MSSQLError):
    pass


class MSSQLClient:
    seen = set()

    def __init__(self, connection: MSSQL) -> None:
        self.connection = connection

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
            if isinstance(self.connection.lastError, Exception):
                raise self.connection.lastError
            else:
                raise SQLErrorException('authentication failed for unknown reason')
        return self

    def disconnect(self) -> None:
        self.connection.disconnect()

    def query(self, statement: str) -> list[dict[str, Any]]:
        statement.strip(' ;')
        logging.debug(f'{self.connection.server}:{self.connection.port}:sql:{statement}')
        rows = self.connection.sql_query(statement)  # sets _connection.replies and returns results
        self.connection.printReplies()  # gets _connection.replies and sets _connection.lastError
        if self.connection.lastError:
            if isinstance(self.connection.lastError, Exception):
                raise self.connection.lastError
            else:
                raise SQLErrorException(self.connection.lastError)
        logging.debug(f'{self.connection.server}:{self.connection.port}:sql:{rows}')
        return rows  # type: ignore

    def query_database(self, database: str, statement: str) -> list[dict[str, Any]]:
        rows = self.query('SELECT db_name() AS [db]')
        assert len(rows) == 1 and len(rows[0]) == 1
        prev = rows[0]['db']
        try:
            rows = self.query(f'USE {database};{statement};USE {prev}')
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
            host=rows[0]['host'].decode(errors='surrogate-escape').lower(),
            login=rows[0]['login'].lower(),
            user=rows[0]['user'].lower(),
            roles=self.roles(),
        )
        return self._userinfo  # type: ignore

    def pwned(self) -> bool:
        info = self.whoami()
        return 'serveradmin' in info['roles']

    def roles(self) -> set[str]:
        #roles = {row['name'] for row in self.query("SELECT name FROM sys.database_principals WHERE type IN ('R','G') AND type_desc='DATABASE_ROLE' AND is_member(name)=1")}
        builtin_roles = 'sysadmin setupadmin serveradmin securityadmin processadmin diskadmin dbcreator bulkadmin'.split(' ')
        custom_roles = [row['name'] for row in self.query("SELECT name FROM sysusers WHERE issqlrole=1")]
        statement = ','.join(f"is_srvrolemember('{role}') AS [{role}]" for role in builtin_roles + custom_roles)
        rows = self.query(f'SELECT {statement}')
        assert len(rows) == 1 and len(rows[0]) == len(builtin_roles) + len(custom_roles)
        return {key for key, value in rows[0].items() if value}

    def databases(self) -> set[str]:
        rows = self.query('select name from sys.databases')
        databases = {row['name'] for row in rows}
        return databases

    def spider(self, visitor: Callable[[MSSQLClient], Any]|None = None, depth: int = 0) -> MSSQLClient:
        if depth >= 10:
            raise RecursionError('maximum recursion depth exceeded')

        if self.id in self.seen:
            logging.info(f'{self.connection.server}:{self.connection.port}:{self.path} ok, already visited')
            return self
        self.seen.add(self.id)

        logging.info(f'{self.connection.server}:{self.connection.port}:{self.path} ok')

        if visitor:
            visitor(self)

        for login in self.enum_login_impersonation():
            try:
                child = self.impersonate_login(login['grantor'], login['database'])
            except SQLErrorException as e:
                logging.info(f'{self.connection.server}:{self.connection.port}:{self.path}->{login["grantor"]} not ok')
                logging.debug(f'{self.connection.server}:{self.connection.port}:could not impersonate login {login["grantor"]} on {self.id}: {e}')
            else:
                child.spider(visitor, depth=depth + 1)

        for user in self.enum_user_impersonation():
            try:
                child = self.impersonate_user(user['grantor'], user['database'])
            except SQLErrorException as e:
                logging.info(f'{self.connection.server}:{self.connection.port}:{self.path}~>{user["grantor"]} not ok')
                logging.debug(f'{self.connection.server}:{self.connection.port}:could not impersonate user {user["grantor"]} on {self.id}: {e}')
            else:
                child.spider(visitor, depth=depth + 1)

        for link in self.enum_links():
            try:
                child = self.use_link(link['instance'])
            except SQLErrorException as e:
                logging.info(f'{self.connection.server}:{self.connection.port}:{self.path}=>{link["instance"]} not ok')
                logging.debug(f'{self.connection.server}:{self.connection.port}:could not use link from {self.id} to {link["instance"]}: {e}')
            else:
                child.spider(visitor, depth=depth + 1)

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
        client = LinkedInstance(self, link)
        client.ping()
        return client

    def enum_login_impersonation(self) -> list[ImpersonationInfo]:
        results = []
        for database in self.databases():
            try:
                results += self.query_database(database, "SELECT db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.server_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
            except SQLPermissionError:
                pass
            except SQLErrorException as e:
                logging.exception(e)
        results = [
            {
                key: value.decode(errors='surrogate-escape') if isinstance(value, bytes) else value
                for key, value in row.items()
            }
            for row in results
        ]
        return results  # type: ignore

    def impersonate_login(self, name: str, database: str) -> ImpersonatedLogin:
        from mssql_spider.impersonated_login import ImpersonatedLogin
        client = ImpersonatedLogin(self, name, database)
        client.ping()
        return client

    def enum_user_impersonation(self) -> list[ImpersonationInfo]:
        results = []
        for database in self.databases():
            try:
                results += self.query_database(database, f"SELECT db_name() AS [database], pr.name AS [grantee], pr2.name AS [grantor] FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.database_principals pr2 ON pe.grantor_principal_id=pr2.principal_id WHERE pe.type='IM' AND (pe.state='G' OR pe.state='W')")
            except SQLPermissionError:
                pass
            except SQLErrorException as e:
                logging.exception(e)
        results = [
            {
                key: value.decode(errors='surrogate-escape') if isinstance(value, bytes) else value
                for key, value in row.items()
            }
            for row in results
        ]
        return results  # type: ignore

    def impersonate_user(self, name: str, database: str) -> ImpersonatedUser:
        from mssql_spider.impersonated_user import ImpersonatedUser
        client = ImpersonatedUser(self, name, database)
        client.ping()
        return client

    @property
    def id(self) -> str:
        return f'{self.username}@{self.hostname}'

    @property
    def path(self) -> str:
        return self.id
