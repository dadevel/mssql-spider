from typing import Any, Generator, TypedDict
import logging

from mssqlmap.client import BrokenClient, Client, SpiderModule
from mssqlmap.connection import SQLErrorException


class LinkedInstance(Client):
    SIGN = '=>'

    def __init__(self, name: str, parent: Client, children: list[Client]|None = None, seen: set[str]|None = None) -> None:
        super().__init__(parent.connection, parent, children, seen)
        self.parent: Client  # make type checker happy
        self.name = name

    def disconnect(self) -> None:
        for child in self.children:
            child.disconnect()


class LinkedRpcInstance(LinkedInstance):
    def __init__(self, name: str, disable_rpc: bool, parent: Client, children: list[Client]|None = None, seen: set[str]|None = None) -> None:
        super().__init__(name, parent, children, seen)
        self.disable_rpc = disable_rpc

    def query(self, statement: str, decode: bool = True, ignore_errors: bool = False) -> list[dict[str, Any]]:
        assert '[' not in self.name and ']' not in self.name, f'unsupported name {self.name!r}'
        statement = f'EXEC ({self.escape_string(statement)}) AT {self.escape_identifier(self.name)}'
        return self.parent.query(statement, decode=decode, ignore_errors=ignore_errors)

    @property
    def path(self) -> str:
        return f'{self.parent.path}{self.SIGN}{super().path}'

    def disconnect(self) -> None:
        if self.disable_rpc:
            logging.debug(f'disabling rpc on {self.parent.path} for {self.name}')
            self.parent.query(f"EXEC sp_serveroption {self.escape_string(self.name)},'rpc out','false'")


class LinkedQueryInstance(LinkedInstance):
    def query(self, statement: str, decode: bool = True, ignore_errors: bool = False) -> list[dict[str, Any]]:
        assert '[' not in self.name and ']' not in self.name, f'unsupported name {self.name!r}'
        statement = f'SELECT * FROM openquery({self.escape_identifier(self.name)}, {self.escape_string(statement)})'
        return self.parent.query(statement, decode=decode, ignore_errors=ignore_errors)

    @property
    def path(self) -> str:
        return f'{self.parent.path}{self.SIGN}{super().path}'


class BrokenLinkedInstance(BrokenClient):
    @property
    def path(self) -> str:
        return f'{self.parent.path if self.parent else ""}{LinkedRpcInstance.SIGN}{super().path}'


class UnsupportedLinkedInstance(BrokenLinkedInstance):
    pass


class InstanceInfo(TypedDict):
    name: str
    product: str
    provider: str
    datasource: str
    rpc_enabled: bool|None
    data_enabled: bool|None
    local_login: str|None
    remote_login: str|None


class UnsupportedInstance(Exception):
    def __init__(self, info: InstanceInfo) -> None:
        self.info = info

    def __str__(self) -> str:
        return f'unsupported provider {self.info["provider"]} for {self.info["product"] or "NULL"} at {self.info["datasource"]}'


class LinkSpider(SpiderModule):
    def spider(self, client: Client) -> Generator[Client, None, None]:
        for name, info in self.enum_links(client).items():
            if info['provider'] != 'SQLNCLI':
                yield UnsupportedLinkedInstance(client, UnsupportedInstance(info), hostname=name, instance=info['name'])
                continue

            child = LinkedRpcInstance(name, not info['rpc_enabled'], client, None, client.seen)
            try:
                if not info['rpc_enabled']:
                    logging.debug(f'enabling rpc on {client.path} for {name}')
                    client.query(f"EXEC sp_serveroption {client.escape_string(name)},'rpc out','true'")
                child.test()
                yield child
                continue
            except TimeoutError as e:
                client.reconnect()
                yield BrokenLinkedInstance(client, e, hostname=name, instance='')
            except SQLErrorException as e:
                yield BrokenLinkedInstance(client, e, hostname=name, instance='')

            # when link fails due to rpc error try again with openquery
            child = LinkedQueryInstance(name, client, None, client.seen)
            try:
                child.test()
                yield child
                continue
            except TimeoutError as e:
                client.reconnect()
                yield BrokenLinkedInstance(client, e, hostname=name, instance='')
            except SQLErrorException as e:
                yield BrokenLinkedInstance(client, e, hostname=name, instance='')

    def enum_links(self, client: Client) -> dict[str, InstanceInfo]:
        result = {}

        try:
            result |= {
                row['SRV_NAME']: dict(
                    name=row['SRV_NAME'],
                    product=row['SRV_PRODUCT'],
                    provider=row['SRV_PROVIDERNAME'],
                    datasource=row['SRV_DATASOURCE'],
                    rpc_enabled=None,
                    data_enabled=None,
                    local_login='',
                    remote_login='',
                )
                for row in client.query('EXEC sp_linkedservers')
            }
        except SQLErrorException:
            pass

        # sys.sysservers is the legacy version of sys.servers, see https://learn.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql
        try:
            result |= {
                row['name']: row
                for row in client.query("SELECT name, product, provider, data_source AS datasource, '' AS local_login, '' AS remote_login, is_rpc_out_enabled AS rpc_enabled, is_data_access_enabled AS data_enabled FROM master.sys.servers WHERE NOT server_id=0")  # filter by is_data_access_enabled?
            }
        except SQLErrorException:
            pass

        # another method to list instances and rpc state from https://github.com/skahwah/SQLRecon/pull/8/files
        # EXEC sp_helpserver

        try:
            logins = {
                row['Linked Server']: dict(
                    local_login=row['Local Login'],
                    remote_login=row['Remote Login'],
                )
                for row in client.query('EXEC sp_helplinkedsrvlogin')
                if not row['Is Self Mapping']
            }
            for server in result:
                try:
                    result[server]['local_login'] = logins[server]['local_login']
                    result[server]['remote_login'] = logins[server]['remote_login']
                except KeyError:
                    pass
        except SQLErrorException:
            pass

        return result
