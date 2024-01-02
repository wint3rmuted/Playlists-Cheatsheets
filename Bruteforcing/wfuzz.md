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





