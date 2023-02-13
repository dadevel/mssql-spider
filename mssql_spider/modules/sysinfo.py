from typing import Any
import re

from mssql_spider.client import MSSQLClient

OS_VERSION_PATTERN = re.compile(' on Windows (.+?) <')


def run(client: MSSQLClient) -> dict[str, Any]:
    # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql?view=sql-server-ver16
    # convert() is needed because impacket does not support the variant type
    # partly stolen from https://github.com/NetSPI/PowerUpSQL/blob/54d73c340611a00e1a2c683c96e7057f7dc35e49/PowerUpSQL.ps1#L4
    rows = client.query(
        'DECLARE @regpath varchar(250) '
        'DECLARE @servicename varchar(250) '
        "IF @@servicename = 'MSSQLSERVER' "
        r"BEGIN SET @regpath = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER' SET @servicename = 'MSSQLSERVER' END "
        'ELSE '
        r"BEGIN SET @regpath = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@servicename as varchar(250)) SET @servicename = 'MSSQL$'+cast(@@SERVICENAME as varchar(250)) END "
        'DECLARE @serviceaccount varchar(250) '
        "EXECUTE master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', @regpath, N'ObjectName', @serviceaccount OUTPUT, N'no_output' "
        'SELECT '
          "convert(varchar(max), serverproperty('ComputerNamePhysicalNetBIOS')) AS [hostname],"  # DB01
          "convert(varchar(max), serverproperty('InstanceName')) AS [instance],"  # SQLEXPRESS
          "convert(varchar(max), serverproperty('MachineName')) AS [clustername],"  # DB01, equal to hostname if not clustered
          "convert(int, serverproperty('IsClustered')) AS [clustered],"  # 0/1
          "@servicename AS [servicename],"
          "@serviceaccount AS [serviceaccount],"
          "default_domain() AS [domain],"
          "@@version AS version,"  # Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) ...
          "convert(varchar(max), serverproperty('ProductLevel')) AS [servicepack],"  # RTM, SP1
          "convert(varchar(max), serverproperty('ProductUpdateLevel')) AS [updatelevel],"  # CU21
          "convert(varchar(max), serverproperty('ProductVersion')) AS [buildnumber],"  # 15.0.2000.5
          "convert(varchar(max), serverproperty('Edition')) AS [edition]"  # Express Edition (64-bit)
    )
    assert len(rows) == 1
    row = rows[0]

    if match := re.fullmatch(r'^Microsoft SQL Server (.+?) ', row['version']):
        row['release'] = match.group()

    row['clustered'] = bool(row['clustered'])

    lines = row['version'].splitlines()
    row['version'] = lines[0].strip()
    if match := OS_VERSION_PATTERN.search(lines[-1].strip()):
        row['osversion'] = match.group(1)

    return {k: v for k, v in row.items() if k in {'version', 'osversion', 'servicename', 'serviceaccount', 'domain'} and v}
