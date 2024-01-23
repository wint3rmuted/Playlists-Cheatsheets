## Nmap Enumeration
```
Information Gathering
1. DNS Brute Force ( dns-brute.nse)
Find sub-domains with this script. Detecting sub-domains associated with an organization's domain can reveal new targets when performing a security assessment.
The discovered hosts may be virtual web hosts on a single web server or distinct hosts on IP addresses spread across the world in different data centres.
The dns-brute.nse script will find valid DNS A records by trying a list of common sub-domains and finding those that successfully resolve.

nmap -p 80 --script dns-brute.nse vulnweb.com

Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-24 19:58 EST
Nmap scan report for vulnweb.com (176.28.50.165)
Host is up (0.34s latency).
rDNS record for 176.28.50.165: rs202995.rs.hosteurope.de
PORT   STATE SERVICE
80/tcp open  http

Host script results:
| dns-brute: 
|   DNS Brute-force hostnames: 
|     admin.vulnweb.com - 176.28.50.165
|     firewall.vulnweb.com - 176.28.50.165
|_    dev.vulnweb.com - 176.28.50.165

Nmap done: 1 IP address (1 host up) scanned in 28.41 seconds

2. Find Hosts on IP
Another tactic for expanding an attack surface is to find virtual hosts on an IP address that you are attempting to compromise (or assess).
This can be done by using the hostmap-* scripts in the NSE collection. The hostmap-bfk.nse seems to work reasonably well providing a good starting point for your recon (IP to Host services do vary in accuracy).

nmap -p 80 --script hostmap-bfk.nse nmap.org

Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-24 19:47 EST
Nmap scan report for nmap.org (173.255.243.189)
Host is up (0.19s latency).
PORT   STATE SERVICE
80/tcp open  http

Host script results:
| hostmap-bfk: 
|   hosts: 
|     www.nmap.org
|     173.255.243.189
|     seclists.org
|     sectools.org
|     svn.nmap.org
|     nmap.org
|     hb.insecure.org
|     insecure.org
|     images.insecure.org
|     189.243.255.173.in-addr.arpa
|_    www.insecure.org

Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds

3. Traceroute Geolocation
Perform a traceroute to your target IP address and have geolocation data plotted for each hop along the way. Makes correlating the reverse dns names of routers in your path with locations much easier.

sudo nmap --traceroute --script traceroute-geolocation.nse -p 80 hackertarget.com

Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-24 21:03 EST
Nmap scan report for hackertarget.com (178.79.163.23)
Host is up (0.31s latency).
PORT   STATE SERVICE
80/tcp open  http

Host script results:
| traceroute-geolocation: 
|   HOP  RTT     ADDRESS                                                GEOLOCATION
|   1    2.09    192.168.1.1                                            - ,- 
|   2    25.55   core-xxxxx.grapevine.net.au (203.xxx.32.20)            -27,133 Australia (Unknown)
|   3    31.61   core-xxxxx.grapevine.net.au (203.xxx.32.25)            -27,133 Australia (Unknown)
|   4    25.02   xe0-0-0-icr1.cbr2.transact.net.au (202.55.144.117)     -27,133 Australia (Unknown)
|   5    23.48   xe11-3-0.cr1.cbr2.on.ii.net (150.101.33.62)            -27,133 Australia (Unknown)
|   6    43.45   ae2.br1.syd4.on.ii.net (150.101.33.22)                 -27,133 Australia (Unknown)
|   7    175.24  te0-0-0-1.br1.lax1.on.ii.net (203.16.213.69)           -27,133 Australia (Unknown)
|   8    181.29  TenGE13-2.br02.lax04.pccwbtn.net (206.223.123.93)      38,-97 United States (Unknown)
|   9    310.46  telecity.ge9-9.br02.ldn01.pccwbtn.net (63.218.13.222)  51,0 United Kingdom (London)
|   10   309.63  212.111.33.238                                         51,0 United Kingdom (Unknown)
|_  11   338.95  hackertarget.com (178.79.163.23)                       51,0 United Kingdom (Unknown)

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   2.09 ms   192.168.1.1
2   25.55 ms  core-xxxxx.grapevine.net.au (203.xxx.32.20)
3   31.61 ms  core-xxxxx.grapevine.net.au (203.xxx.32.25)
4   25.02 ms  xe0-0-0-icr1.cbr2.transact.net.au (202.55.144.117)
5   23.48 ms  xe11-3-0.cr1.cbr2.on.ii.net (150.101.33.62)
6   43.45 ms  ae2.br1.syd4.on.ii.net (150.101.33.22)
7   175.24 ms te0-0-0-1.br1.lax1.on.ii.net (203.16.213.69)
8   181.29 ms TenGE13-2.br02.lax04.pccwbtn.net (206.223.123.93)
9   310.46 ms telecity.ge9-9.br02.ldn01.pccwbtn.net (63.218.13.222)
10  309.63 ms 212.111.33.238
11  338.95 ms hackertarget.com (178.79.163.23)

HTTP Recon
Nmap comes with a wide range of NSE scripts for testing web servers and web applications.
An advantage of using the NSE scripts for your HTTP reconnaissance is that you are able to test aspects of a web server against large subnets.
This can quickly provide a picture of the types of servers and applications in use within the subnet.
4. http-enum.nse

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
