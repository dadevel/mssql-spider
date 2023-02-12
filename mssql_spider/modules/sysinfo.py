from argparse import Namespace
from typing import Any
import re

from mssql_spider.client import MSSQLClient


def visitor(_: Namespace, client: MSSQLClient) -> dict[str, Any]:
    info = sysinfo(client)
    return dict(version=info['versionstring'])


def sysinfo(client: MSSQLClient) -> dict[str, Any]:
    # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql?view=sql-server-ver16
    # convert() is needed because impacket does not support the variant type
    rows = client.query(
        "SELECT convert(varchar(max), serverproperty('ComputerNamePhysicalNetBIOS')) AS [hostname],"  # DB01
        "convert(varchar(max), serverproperty('InstanceName')) AS [instance],"  # b'SQLEXPRESS'
        "convert(varchar(max), serverproperty('MachineName')) AS [clustername],"  # DB01, equal to hostname if not clustered
        "convert(int, serverproperty('IsClustered')) AS [clustered],"  # 0/1
        "@@version AS version,"  # Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) ...
        "convert(varchar(max), serverproperty('ProductLevel')) AS [servicepack],"  # b'RTM', b'SP1'
        "convert(varchar(max), serverproperty('ProductUpdateLevel')) AS [updatelevel],"  # b'CU21'
        "convert(varchar(max), serverproperty('ProductVersion')) AS [buildnumber],"  # b'15.0.2000.5'
        "convert(varchar(max), serverproperty('Edition')) AS [edition]"  # b'Express Edition (64-bit)'
    )
    assert len(rows) == 1
    row = rows[0]

    if match := re.fullmatch(r'^Microsoft SQL Server (.+?) ', row['version']):
        row['release'] = match.group()

    row['clustered'] = bool(row['clustered'])
    row['versionstring'] = row['version'].split('\n', maxsplit=1)[0].strip()

    return row
