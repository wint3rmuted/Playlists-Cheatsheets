## HTTP Enumeration with Nmap
```
While Nmap is not a vulnerability scanner in the traditional sense, it can be very useful for similar tasks. 
Use --script vuln to run all scripts in the "vuln" category against a target:
kali@kali:~$ sudo nmap --script vuln 10.11.1.10

HTTP Recon ( http-enum.nse)
Nmap comes with a wide range of NSE scripts for testing web servers and web applications.
An advantage of using the NSE scripts for your HTTP reconnaissance is that you are able to test aspects of a web server against large subnets.
This can quickly provide a picture of the types of servers and applications in use within the subnet.
http-enum.nse

One of the more aggressive tests, this script effectively brute forces a web server path in order to discover web applications in use. Attempts will be made to find valid paths on the web server that match a list of known paths for common web applications. The standard test includes testing of over 2000 paths, meaning that the web server log will have over 2000 entries that are HTTP 404 not found, not a stealthy testing option! This is very similar to the famous Nikto web server testing tool (that performs 6000+ tests).

nmap --script http-enum 192.168.10.55

Nmap scan report for ubuntu-test (192.168.10.55)
Host is up (0.024s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
| http-enum: 
|   /robots.txt: Robots file
|   /readme.html: WordPress version 3.9.2
|   /css/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'

Additional options:
Specify base path, for example you could specify a base path of /pub/.

nmap --script -http-enum --script-args http-enum.basepath='pub/' 192.168.10.55

Nmap scan report for xbmc (192.168.1.5)
Host is up (0.0012s latency).
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /pub/: Root directory w/ listing on 'apache/2.2.22 (ubuntu)'
|   /pub/images/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /pub/js/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 1.03 seconds
```
