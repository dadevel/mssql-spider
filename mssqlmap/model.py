from __future__ import annotations
import functools

import pydantic

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
    return ''


class BaseModel(pydantic.BaseModel):
    class Config:
        extra = pydantic.Extra.forbid
        frozen = True
        # work around pydantic incompatibility with cached properties, see https://github.com/pydantic/pydantic/issues/1241#issuecomment-587896750
        ignored_types = (functools.cached_property,)


class DatabaseServicePrincipal(BaseModel):
    host: str
    port: int


class DatabaseInstance(BaseModel):
    host: str
    port: int
    computer: str = ''
    instance: str = ''
    build: str = ''
    version: str = ''
    clustered: bool = False
    pipe: str = ''

    @classmethod
    def from_ping(cls, host: str, servername: str, instancename: str, isclustered: str, version: str, tcp: str = '', np: str = '') -> DatabaseInstance:
        return cls(
            host=host,
            port=int(tcp) if tcp else 1433,
            computer=servername.upper(),
            instance=instancename.upper(),
            build=version,
            version=lookup_buildnumber(version),
            clustered=isclustered.lower() == 'yes',
            pipe=np,
        )
