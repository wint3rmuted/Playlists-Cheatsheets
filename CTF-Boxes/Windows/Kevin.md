# PG Kevin
## HP Power Manager, MSF
## nmap
```
PORT      STATE SERVICE            VERSION
80/tcp    open  http               GoAhead WebServer
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows
```
## 80
```
80/tcp    open  http               GoAhead WebServer
Takes us to a login screen for HP Power Manager.
A quick Google search reveals the default credentials are admin:admin.
Searchsploit reveals HP Power Manager is vulnerable to a remote buffer overflow given CVE-2009-3999.
https://www.exploit-db.com/exploits/18015
```
## MSF
```
exploit/windows/http/hp_power_manager_filename.
```
