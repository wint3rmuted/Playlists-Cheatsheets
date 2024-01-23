## DNS Subdomain Bruteforcing with Nmap
```
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
```
