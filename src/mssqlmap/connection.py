from __future__ import annotations
from typing import Any
import os
import socket
import unittest.mock

from impacket.krb5.ccache import CCache
from impacket.tds import MSSQL, SQLErrorException
import pydantic

from mssqlmap.model import BaseModel

# source: https://sqlserverbuilds.blogspot.com/
# TODO: improve granularity to SP/CU level plus unsupported/outdated/patched status
VERSION_TABLE = {
    '16.': '2022',
    '15.': '2019',
    '14.': '2017',
    '13.': '2016',
    '12.': '2014',
    '11.': '2012',
    '10.50.': '2008 R2',
    '10.0.': '2008',
    '9.': '2005',
    '8.': '2000',
}


def lookup_buildnumber(build: str) -> str:
    for key in VERSION_TABLE:
        if build.startswith(key):
            return f'SQL Server {VERSION_TABLE[key]}'
    return f'Unknown {build}'


class Connection(BaseModel):
    host: str
    port: int = 1433
    instance: str|None = None
    domain: str|None = None
    username: str|None = None
    password: str|None = None
    hashes: str|None = None
    aes_key: str|None = None
    ticket: str|None = None
    windows_auth: bool = False
    kerberos: bool = False
    kdc_host: str|None = None
    database: str|None = None
    timeout: int = 10
    loginname: str|None = None
    pwned: bool = False
    computername: str|None = None
    build: str = ''
    version: str = ''
    clustered: bool = False
    wrapped: MSSQL = pydantic.Field(default_factory=lambda: MSSQL(None), exclude=True)

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_ping(cls, host: str, servername: str, instancename: str, isclustered: str, version: str, tcp: str = '', np: str = '') -> Connection:
        return cls(
            host=host,
            port=int(tcp) if tcp else 1433,
            instance=instancename.upper(),
            computername=servername.upper(),
            build=version,
            version=lookup_buildnumber(version),
            clustered=isclustered.lower() == 'yes',
        )

    def __enter__(self) -> Connection:
        self.connect()
        self.login()
        return self

    def __exit__(self, type, value, traceback) -> None:
        self.disconnect()

    def connect(self) -> Connection:
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(self.host, self.port, family=0, type=socket.SOCK_STREAM)[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        sock.connect(sockaddr)
        self.wrapped.server = self.host
        self.wrapped.port = self.port
        self.wrapped.socket = sock
        return self

    def login(self) -> Connection:
        domain, username = self.domain or '', self.username or ''
        tgt, st = None, None
        if self.ticket:
            # this is ugly, but impacket doesn't provide a proper API
            with unittest.mock.patch('os.getenv', side_effect=self._inject_ccache):
                domain, username, tgt, st = CCache.parseFile(domain, username, f'MSSQLSvc/{self.host}')
                if not st:
                    domain, username, tgt, st = CCache.parseFile(domain, username, f'MSSQLSvc/{self.host}:{self.port}')
                if not st and self.instance:
                    domain, username, tgt, st = CCache.parseFile(domain, username, f'MSSQLSvc/{self.host}:{self.instance}')
            assert tgt or st, f'no ticket could be loaded from ccache {self.ticket}'

        # ensure impacket hash format
        if self.hashes and ':' not in self.hashes:
            hashes = f':{self.hashes}'
        else:
            hashes = self.hashes

        if self.kerberos:
            ok = self.wrapped.kerberosLogin(self.database, self.username, self.password or '', self.domain or '', hashes, self.aes_key or '', self.kdc_host, tgt, st, useCache=False if self.ticket else True)
        else:
            ok = self.wrapped.login(self.database, self.username, self.password or '', self.domain or '', hashes, self.windows_auth)
        self.wrapped.printReplies()  # gets wrapped._connection.replies and sets wrapped._connection.lastError
        error = self.last_error()
        assert (ok and not error) or (not ok and error), f'contradicting state, ok={ok!r} error={error!r}'
        if not ok and error:
            raise error
        return self

    def disconnect(self) -> None:
        # closes wrapped.socket
        self.wrapped.disconnect()

    def duplicate(self) -> Connection:
        return Connection(**self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != 'wrapped'}

    def last_error(self) -> SQLErrorException|None:
        if not self.wrapped.lastError:
            return None
        elif isinstance(self.wrapped.lastError, SQLErrorException):
            return SQLErrorException(self.wrapped.lastError.args[0].removeprefix('ERROR: Line 1: '))
        elif isinstance(self.wrapped.lastError, Exception):
            return SQLErrorException(self.wrapped.lastError)
        elif isinstance(self.wrapped.lastError, str):
            return SQLErrorException(self.wrapped.lastError.removeprefix('ERROR: Line 1: '))
        else:
            return SQLErrorException(f'unknown failure: {self.wrapped.lastError!r}')

    def _inject_ccache(self, name: str) -> str|None:
        return self.ticket if name == 'KRB5CCNAME' else os.getenv(name)
