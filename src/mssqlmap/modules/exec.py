from mssqlmap.client import Client, VisitorModule
from mssqlmap.connection import SQLErrorException
from mssqlmap.util import random_string


class CmdShellExecutor(VisitorModule):
    def __init__(self, command: str) -> None:
        self.command = command

    def invoke(self, client: Client) -> dict[str, list[str]]:
        lines = self.xp_cmdshell(client, self.command)
        return dict(lines=lines)

    def xp_cmdshell(self, client: Client, command: str) -> list[str]:
        enabled = self.xp_cmdshell_enabled(client)
        if not enabled:
            self.enable_xp_cmdshell(client)
        rows = client.query(f'EXEC master.dbo.xp_cmdshell {client.escape_string(command)}')
        if not enabled:
            self.disable_xp_cmdshell(client)
        lines = [row['output'] for row in rows if row['output'] != 'NULL']
        return lines

    @staticmethod
    def xp_cmdshell_enabled(client: Client) -> bool:
        rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='xp_cmdshell'");
        assert len(rows) == 1
        return bool(rows[0]['value'])

    @staticmethod
    def enable_xp_cmdshell(client: Client) -> None:
        client.configure('show advanced options', True)
        client.configure('xp_cmdshell', True)

    @staticmethod
    def disable_xp_cmdshell(client: Client) -> None:
        client.configure('xp_cmdshell', False)
        client.configure('show advanced options', False)


class OleExecutor(VisitorModule):
    def __init__(self, command: str) -> None:
        self.command = command

    def invoke(self, client: Client) -> dict[str, bool]:
        # FIXME: figure out proper escaping rules here
        assert '"' not in self.command, 'double quotes are not supported'
        command = f'Run("{self.command}")'

        enabled = self.ole_automation_enabled(client)
        if not enabled:
            self.enable_ole_automation(client)
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
                self.disable_ole_automation(client)
        return dict(ok=True)

    @staticmethod
    def enable_ole_automation(client: Client) -> None:
        client.configure('show advanced options', True)
        client.configure('Ole Automation Procedures', True)

    @staticmethod
    def disable_ole_automation(client: Client) -> None:
        client.configure('Ole Automation Procedures', False)
        client.configure('show advanced options', False)

    @staticmethod
    def ole_automation_enabled(client: Client) -> bool:
        rows = client.query("SELECT convert(int, isnull(value, value_in_use)) AS [value] FROM sys.configurations WHERE name='Ole Automation Procedures'");
        assert len(rows) == 1
        return bool(rows[0]['value'])


class JobScheduler(VisitorModule):
    # see https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-add-jobstep-transact-sql
    SUBSYSTEMS = dict(
        sql='TSQL',
        cmd='CmdExec',
        powershell='PowerShell',
    )
    # see https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-add-jobschedule-transact-sql
    FREQUENCIES = dict(
        once=1,
        daily=4,
        weekly=8,
        monthly=16,
    )

    def __init__(self, name: str, interval: str|None, language: str, command: str) -> None:
        self.jobname = name
        try:
            self.interval = self.FREQUENCIES[interval] if interval else None
        except KeyError as e:
            raise ValueError(f'invalid interval {self.interval!r}') from e
        try:
            self.language = self.SUBSYSTEMS[language]
        except KeyError as e:
            raise ValueError(f'invalid language {self.language!r}') from e
        self.command = command

    def invoke(self, client: Client) -> dict[str, bool|str]:
        if client.instance == 'sqlexpress':
            raise RuntimeError('SQL Express does not support agent jobs')

        step_name, schedule_name  = random_string(), random_string()

        started = self.sql_server_agent_started(client)
        if not started:
            self.start_sql_server_agent(client)
        try:
            # delete level 3 means that the job deletes itself after execution, see https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-add-job-transact-sql
            statements = [
                f"EXEC msdb.dbo.sp_add_job @job_name={client.escape_string(self.jobname)},@delete_level={0 if self.interval else 3}",
                f"EXEC msdb.dbo.sp_add_jobstep @job_name={client.escape_string(self.jobname)},@step_name={client.escape_string(step_name)},@subsystem={client.escape_string(self.language)},@command={client.escape_string(self.command)}",
                f"EXEC msdb.dbo.sp_add_jobschedule @job_name={client.escape_string(self.jobname)},@name={client.escape_string(schedule_name)},@freq_type={self.interval} " if self.interval else '',
                f"EXEC msdb.dbo.sp_add_jobserver @job_name={client.escape_string(self.jobname)}",
                f"EXEC msdb.dbo.sp_start_job @job_name={client.escape_string(self.jobname)} " if not self.interval else '',
            ]
            client.query(' '.join(x for x in statements if x))
            return dict(ok=True)
        except SQLErrorException as e:
            client.query(f"EXEC msdb.dbo.sp_delete_job @job_name={client.escape_string(self.jobname)}", ignore_errors=True)
            return dict(ok=False, error=str(e))
        finally:
            if not started and not self.interval:
                self.stop_sql_server_agent(client)
            pass

    @staticmethod
    def sql_server_agent_started(client: Client) -> bool:
        #row = client.query_single("EXEC master.dbo.xp_servicecontrol 'Querystate','SQLServerAgent'")
        #row['Current Service State'].lower().removesuffix('.') == 'started'

        # docs: https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-server-services-transact-sql
        assert "'" not in client.instance, 'instance name contains unsupported character'
        rows = client.query(f"SELECT servicename AS name, startup_type_desc AS startup, status_desc AS status FROM sys.dm_server_services WHERE servicename in ('SQL Server Agent ({client.instance})', 'SQL Server Agent')")
        assert len(rows) == 1, 'more than one matching SQL Server Agent found'
        row = rows[0]
        if row['status'].lower() == 'running':
            return True
        if row['startup'].lower() != 'automatic':
            raise RuntimeError(f'agent service is not running and not configured to start automatically')
        return False

    @staticmethod
    def start_sql_server_agent(client: Client) -> None:
        client.query("EXEC master.dbo.xp_servicecontrol 'Start','SQLServerAgent'")

    @staticmethod
    def stop_sql_server_agent(client: Client) -> None:
        client.query("EXEC master.dbo.xp_servicecontrol 'Stop','SQLServerAgent'")


class JobDeleter(VisitorModule):
    def __init__(self, job: str) -> None:
        self.job = job

    def invoke(self, client: Client) -> dict[str, bool]:
        client.query(f'EXEC msdb.dbo.sp_delete_job @job_name={client.escape_string(self.job)}')
        return dict(ok=True)


class JobExecutor(JobScheduler):
    def __init__(self, language: str, command: str) -> None:
        super().__init__(random_string(), None, language, command)
