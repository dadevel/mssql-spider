from typing import TypedDict
import re

from mssqlmap.client import Client, VisitorModule

OS_VERSION_PATTERN = re.compile(' on Windows (.+?) <')
DB_RELEASE_PATTERN = re.compile(r'^Microsoft SQL Server (.+?) ')


class SystemInfo(TypedDict):
    hostname: str
    instance: str
    clustername: str
    servicename: str
    serviceaccount: str
    domain: str
    longversion: str
    servicepack: str
    updatelevel: str
    buildnumber: str
    edition: str
    clustered: bool
    dbversion: str|None
    osversion: str|None
    release: str|None


class SystemInformer(VisitorModule):
    def invoke(self, client: Client) -> SystemInfo:
        # docs: https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql?view=sql-server-ver16
        # convert() is needed because impacket does not support the variant type
        # partly stolen from https://github.com/NetSPI/PowerUpSQL/blob/54d73c340611a00e1a2c683c96e7057f7dc35e49/PowerUpSQL.ps1#L4
        row = client.query_single(
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
            "@@version AS longversion,"  # Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) ...
            "convert(varchar(max), serverproperty('ProductLevel')) AS [servicepack],"  # RTM, SP1
            "convert(varchar(max), serverproperty('ProductUpdateLevel')) AS [updatelevel],"  # CU21
            "convert(varchar(max), serverproperty('ProductVersion')) AS [buildnumber],"  # 15.0.2000.5
            "convert(varchar(max), serverproperty('Edition')) AS [edition]"  # Express Edition (64-bit)
        )

        row['clustered'] = bool(row['clustered'])
        row['dbversion'], row['osversion'] = self.extract_versions(row['longversion'])
        row['release'] = self.extract_release(row['longversion'])
        del row['longversion']

        return row  # type: ignore

    @staticmethod
    def extract_versions(text: str) -> tuple[str, str|None]:
        lines = text.splitlines()
        version = lines[0].strip()
        if match := OS_VERSION_PATTERN.search(lines[-1].strip()):
            osversion = match.group(1)
        else:
            osversion = None
        return version, osversion

    @staticmethod
    def extract_release(text: str) -> str|None:
        if match := re.fullmatch(DB_RELEASE_PATTERN, text):
            return match.group()
        else:
            return None
