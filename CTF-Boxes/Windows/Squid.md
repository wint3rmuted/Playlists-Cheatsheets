# PG Squid
## Squid Proxy
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
