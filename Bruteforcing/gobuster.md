## Gobuster
```
GoBuster:
Gobuster gobuster dir -u http://ip-address -w wordlists -x extensions -o output.txt  -t 90
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt -x php,html,txt -t 80  -o gobuster/RaftFilesLarge.txt
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt -t 80  -o gobuster/RaftFilesDirectories.txt
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt -x php,html,txt -t 80  -o gobuster/RaftFilesExtensions.txt

Master Filetype List:
-x php,html,txt
-x php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

gobuster dir -u http://192.168.70.53:4443/ -w /usr/share/dirb/wordlists/common.txt -t 40
gobuster dir -u http://10.10.10.175/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root -t 40
gobuster -u http://10.10.10.103/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x asp,aspx,txt,html 
gobuster dir -u http://192.168.196.155 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,git -t 90
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 80
gobuster dir -u http://192.168.155.145/openemr/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 80
gobuster dir -u http://192.168.174.56:8295 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 80                                                                                
gobuster dir -u http://192.168.170.110 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 90
gobuster dir -u http://192.168.195.117:50000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 90        
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.239.63/ -x "aspx" 
gobuster dir -u http://192.168.137.145/openemr/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 80
gobuster dir -u http://192.168.188.23 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -x php,txt
gobuster dir -u http://192.168.150.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 200 -x txt,zip,php
gobuster dir -u https://192.168.150.57:8081 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 200 -x txt,zip,php -k
gobuster dir -u http://192.168.136.69:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,zip,git,js,php,html,txt -t 90
gobuster -u http://10.10.10.68 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

Having noticed that the links on the page were to php files, we’ll search for php and txt extensions:
root@kali# gobuster -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -x php,txt

root@kali# gobuster dir -k -u https://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o scans/gobuster-https-root-medium -t 20
root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -u http://10.10.10.88 -o gobuster/port80root.txt
root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -u http://10.10.10.88/webservices -o gobuster/port80webservices -t 30

Gobuster gobuster dir -u http://ip-address -w wordlists -x extentions -o output.txt
```
