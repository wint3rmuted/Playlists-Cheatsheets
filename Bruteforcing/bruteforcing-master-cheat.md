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

## Cewl
```
cewl http://192.168.233.x:8081/ | grep -v CeWL > custom-wordlist.txt
cewl --lowercase http://192.168.233.x:8081/ | grep -v CeWL  >> custom-wordlist.txt

root@kali# cewl -w cewl-forum.txt -e -a http://forum.site.internal

HTTP
cewl www.megacorp.com -m 6 -w mega-cewl.txt

Mangle:
john --wordlist=mega-cewl.txt --rules --stdout > mega-mangled

# To spider a site and write all found words to a file
cewl -w <file> <url>

# To spider a site and follow links to other sites
cewl -o <url>

# To spider a site using a given user-agent 
cewl -u <user-agent> <url>

# To spider a site for a given depth and minimum word length
cewl -d <depth> -m <min word length> <url>

# To spider a site and include a count for each word
cewl -c <url>

# To spider a site inluding meta data and separate the meta_data words
cewl -a -meta_file <file> <url>

# To spider a site and store email adresses in a separate file
cewl -e -email_file <file> <url>
```

## Crunch
```
Generating a wordlist for a bruteforce attack
kali@kali:~$ crunch 6 6 -t Lab%%% > wordlist

We can then verify the content of the generated wordlist:
kali@kali:~$ cat wordlist
Lab000
Lab001
Lab002
Lab003
```

## Dirsearch
```
Dirsearch:
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY with 80 threads filtering out 403,404
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-extensions.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY

Master Filetype List:
-e php,html,js
-e php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

python3 dirsearch.py -e php,html,js -u https://site.org -r    <---- Recursive option

Using Wordlist:
python3 dirsearch.py -e php,html,js -u https://example.com -w /usr/share/wordlists/dirb/common.txt

Max Recursion Depth:
python3 dirsearch.py -e php,html,js -u https://site.org -r -R 3

Using Threads:
 python3 dirsearch.py -e php,htm,js,bak,zip,tgz,txt -u https://site.org -t 30
 
Prefixes:
python3 dirsearch.py -e php -u https://site.org –prefixes .,admin,_,~

Excluding Extensions:
 python3 dirsearch.py -e asp,aspx,htm,js -u https://site.org -X php,jsp,jspx
 
 Example 6: Filters
python3 dirsearch.py -e php,html,js -u https://site.org -i 200,204,400,403 -x 500,502,429

Example 7: Scan sub-directories
python3 dirsearch.py -e php,html,js -u https://geeksforgeeks.org –subdirs admin/,folder/,/


Example 8:  Using Proxy Server.
python3 dirsearch.py -e php,html,js -u https://geeksforgeeks.org –proxy 127.0.0.1:8080

Example 9: Saving Results
python3 dirsearch.py -e php -u https://geeksforgeeks.org -o report.txt



root@kali# python3 /opt/dirsearch/dirsearch.py -u http://10.10.10.x/ -e php -x 403,404 -t 50
```

## Feroxbuster
```
Feroxbuster:
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt --filter-status 403,404
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt
feroxbuster -u http://192.168.x.x -x pdf -x js,html -x php txt json,docx –no-recursion -vv -o, --output <FILE>

Master Filetype List:
-x php,txt,json,docx,js,html,
-x php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old
-x php,html,htm,js,json,xml,txt,pdf,zip,tar,gz,ini,bak,old,md,doc,docx,xls,xlsx,jpg,jpeg,png,gif,mpg,mp3,

feroxbuster -u http://site.org 

Example 1: Multiple Values
    sudo feroxbuster -u http://site.org -x pdf -x js,html -x php txt json,docx
    
Example 6: Proxy traffic through a SOCKS proxy (including DNS lookups)
    feroxbuster -u http://site.org –proxy socks5h://127.0.0.1:80    
    
    The Feroxbuster has a number of useful filters to modify or customize the scanning results. The tool supports all major web status codes for scanning purposes. We can drop certain status codes using the filter-status argument.

feroxbuster -u http://site.com --filter-status 301

The Feroxbuster allows the use of multiple filters in a single command. In particular, we can filter certain response codes (-C), page size (-S), lines (-N), and words (-W) to exclude from the scanning process. For example, we can drop the content with the following defined values from the final results.

Status Code (-C)= 302
Number of Lines (-N)= 50
Number of Words (-W)= 200
Byte Size (-S)= 2000

We run feroxbuster scan [feroxbuster -u http://192.168.65.x:50080 -C 401 403 405] and find the directory “/cloud”

./feroxbuster -u http://192.168.106.x:<port> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

feroxbuster -u https://10.10.10.60/ -x php,html,txt -w /usr/share/wordlists/d
feroxbuster -u http://10.10.10.34 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

Example 5: Proxy traffic through Burp
    feroxbuster -u http://geeksforgeeks.org –insecure –proxy http://127.0.0.1:80

Example 6: Proxy traffic through a SOCKS proxy (including DNS lookups)
    feroxbuster -u http://geeksforgeeks.org –proxy socks5h://127.0.0.1:80

Example 7: Pass auth token via a query parameter
    feroxbuster -u http://geeksforgeeks.org –query token=0123456789ABCDEF

Include Headers:
./feroxbuster -u http://127.1 -H Accept:application/json "Authorization: Bearer {token}"

Write to outfile:
-o, --output <FILE>
```

## FFUF
```
Recursion (super dodgy I like to use dirsearch to search recursively, good for speed tho)
ffuf -u https://site.io/FUZZ -w ./wordlist -recursion <--Does not work, I like to use dirsearch for recursion

Extensions
ffuf -u https://site.io/FUZZ -w ./wordlist -recursion -e .bak

Typical commands & Usage 

# Directory discovery
ffuf -w /path/to/wordlist -u https://target/FUZZ

# Adding classical header (some WAF bypass)
ffuf -c -w "/opt/host/main.txt:FILE" -H "X-Originating-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Remote-IP: 127.0.0.1, X-Remote-Addr: 127.0.0.1, X-Client-IP: 127.0.0.1" -fs 5682,0 -u https://target/FUZZ

# match all responses but filter out those with content-size 42
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

# Fuzz Host-header, match HTTP 200 responses.
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

# Virtual host discovery (without DNS records)
ffuf -w /path/to/vhost/wordlist -u https://target -H "Host: FUZZ" -fs 4242


# Playing with threads and wait
./ffuf -u https://target/FUZZ -w /home/mdayber/Documents/Tools/Wordlists/WebContent_Discovery/content_discovery_4500.txt -c -p 0.1 -t 10


# GET param fuzzing, filtering for invalid response size (or whatever)
ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242

# GET parameter fuzzing if the param is known (fuzzing values) and filtering 401
ffuf -w /path/to/values.txt -u https://target/script.php?valid_name=FUZZ -fc 401


# POST parameter fuzzing
ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401

# Fuzz POST JSON data. Match all responses not containing text "error".
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"
```

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

## wfuzz
```
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'

Write to File
wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404

Custom Scan with limited output
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20

Fuzzing two paramters at once
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c

Domain
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/

Subdomain
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>

Git
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404

Login
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --hc 200 -c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --ss "Invalid login"

SQL
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http

The following command tests for SQL injection using the wordlist sqli.txt. You can specify POST body data with the -d flag:
$ wfuzz -w sqli.txt -d "user_id=FUZZ" http://example.com/get_user

DNS
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100

Numbering Files
wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip

WPS
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u
target=<RHOST>; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```
