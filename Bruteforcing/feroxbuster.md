## Feroxbuster
```
Feroxbuster:
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt --filter-status 403,404
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt
feroxbuster -u http://192.168.106.101:<port> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-extensions.txt
feroxbuster -u http://192.168.x.x -x pdf -x js,html -x php txt json,docx –no-recursion -vv -o, --output <FILE>
feroxbuster --url http://example.com --recursive


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
