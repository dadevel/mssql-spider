from typing import Any, TypedDict

from mssqlmap.client import BaseModule, Client, DatabaseInfo
from mssqlmap.connection import SQLErrorException


class DatabaseEnumerator(BaseModule):
    def invoke(self, client: Client) -> dict[str, DatabaseInfo]:
        return client.enum_databases()


class LoginInfo(TypedDict):
    name: str
    login_type: str
    roles: list[str]


class LoginEnumerator(BaseModule):
    def invoke(self, client: Client) -> dict[str, LoginInfo]:
        # legacy table: master.sys.syslogins
        # docs: https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql
        return {
            row['name']: {
                'name': row['name'],
                'login_type': row['login_type'],
                'roles': row['roles'].split(','),
            }
            for row in client.query("SELECT members.name, members.type_desc AS login_type, string_agg(roles.name, ',') AS roles FROM sys.server_role_members AS server_role_members JOIN sys.server_principals AS roles ON server_role_members.role_principal_id=roles.principal_id JOIN sys.server_principals AS members ON server_role_members.member_principal_id=members.principal_id WHERE members.is_disabled=0 AND NOT members.type IN ('A','R') GROUP BY members.name, members.type_desc")
        }


class UserInfo(TypedDict):
    name: str
    user_type: str
    auth_type: str
    roles: list[str]


class UserEnumerator(BaseModule):
    def invoke(self, client: Client) -> dict[str, UserInfo]:
        # legacy table: master.sys.sysusers
        # docs: https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-principals-transact-sql
        return {
            row['name']: {
                'name': row['name'],
                'user_type': row['user_type'],
                'auth_type': row['auth_type'],
                'roles': row['roles'].split(','),
            }
            for row in client.query("SELECT members.name, members.type_desc AS user_type, members.authentication_type_desc AS auth_type, string_agg(roles.name, ',') AS roles FROM sys.database_role_members AS server_role_members JOIN sys.database_principals AS roles ON server_role_members.role_principal_id=roles.principal_id JOIN sys.database_principals AS members ON server_role_members.member_principal_id=members.principal_id WHERE NOT members.type IN ('A','R') GROUP BY members.name, members.type_desc, members.authentication_type_desc")
        }
