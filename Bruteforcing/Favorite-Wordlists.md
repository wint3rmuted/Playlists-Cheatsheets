## Directory Bruteforce
```
Master filetype list: php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

-x php,html,txt 

Feroxbuster:
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt --filter-status 403,404
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt
feroxbuster -u http://192.168.x.x -x pdf -x js,html -x php txt json,docx –no-recursion -vv -o, --output <FILE>
-x php,txt,json,docx,js,html,
-x php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old
-x php,html,htm,js,json,xml,txt,pdf,zip,tar,gz,ini,bak,old,md,doc,docx,xls,xlsx,jpg,jpeg,png,gif,mpg,mp3,

WFUZZ: export URL="http://192.168.x.x:80/FUZZ/"
wfuzz -c -z file,/usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt --hc 404 “$URL”  ←  FIRST FOR FILES -c for color, -z file,/usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt, --hc 404 exclude 404s
wfuzz -c -z file,/usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt --hc 404 “$URL” ← THEN FOR DIRECTORIES
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt--hc 404 “$URL” ← THEN FOR EXTENSIONS  f <OUTPUT FILE>
wfuzz -w ${wordlist} -z list,txt-php --hc 404 https://10.10.10.60/FUZZ.FUZ2Z
Encoders options wfuzz -e encoders #Prints the available encoders #Examples: urlencode, md5, base64, hexlify, uri_hex, double urlencode
In order to use an encoder, you have to indicate it in the "-w" or "-z" option.
Path Parameters BF: wfuzz -c -w ~/git/Arjun/db/params.txt --hw 11 'http://example.com/path%3BFUZZ=FUZZ'
DNS ←   wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

GoBuster:
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt -x php,html,txt -t 80  -o gobuster/RaftFilesLarge.txt
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt -t 80  -o gobuster/RaftFilesDirectories.txt
gobuster dir -u http://192.168.155.145 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt -x php,html,txt -t 80  -o gobuster/RaftFilesExtensions.txt
Gobuster gobuster dir -u http://ip-address -w wordlists -x extensions -o output.txt  -t 90
kali@kali:~$ gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern ← API fuzzing
kali@kali:~$ gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt ← Smaller wordlist for admin user

-x php,html,txt
-x php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

Dirsearch:
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY with 80 threads filtering out 403,404
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-extensions.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY
Using Threads:
 python3 dirsearch.py -e php,htm,js,bak,zip,tgz,txt -u https://geeksforgeeks.org -t 30

-e php,html,js
-e php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

My Common Wordlists:
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt 
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt
/usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/wordlists/seclists/Usernames/Names/names.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

/usr/share/dirb/wordlists/common.txt 
/usr/share/seclists/Passwords/Default-Credentials <-- Decent default credentials list, try pass-station too. 

IIS 
/usr/share/wordlists/seclists/Discovery/Web-Content/IIS.fuzz.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/iis-systemweb.txt

APACHE
/usr/share/wordlists/seclists/Discovery/Web-Content/Apache.fuzz.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/ApacheTomcat.fuzz.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/apache.txt



target=10.0.0.1; gobuster -u http://$target -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee $target-gobuster
target=10.0.0.1; nikto -h http://$target:80 | tee $target-nikto
target=10.0.0.1; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
```
