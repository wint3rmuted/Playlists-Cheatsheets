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


Example 8:  Using Proxy Server.
python3 dirsearch.py -e php,html,js -u https://geeksforgeeks.org –proxy 127.0.0.1:8080

Example 9: Saving Results
python3 dirsearch.py -e php -u https://geeksforgeeks.org -o report.txt



root@kali# python3 /opt/dirsearch/dirsearch.py -u http://10.10.10.x/ -e php -x 403,404 -t 50
```
