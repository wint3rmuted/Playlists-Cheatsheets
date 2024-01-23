## 10 Useful NSE Scripts for Network Enumeration
```
http-enum
Command: nmap [port] --script=http-enum [target]
The http-enum script is used to enumerate directories, files, and other details from web servers. It sends requests to the target server and analyzes the responses to identify potential vulnerabilities and misconfigurations. This script is particularly useful when assessing the security of web applications.
This command will run the http-enum script against the example.com domain, attempting to enumerate directories and files on the web server.
Example Usage: nmap --script=http-enum testhtml5.vulnweb.com

smb-os-discovery
Command: nmap --script smb-os-discovery.nse [target]
The smb-os-discovery script is a valuable tool in your pentesting arsenal. It uses the Server Message Block (SMB) protocol to identify the operating system of remote hosts.
This information is crucial as it allows you to tailor your approach based on the specific vulnerabilities of the detected operating system.
This command instructs Nmap to run the smb-os-discovery script against the target IP address 192.168.1.1. The script will attempt to reveal the operating system and other key details about the server.
Example Usage: nmap --script smb-os-discovery.nse example.com

dns-brute
Command: nmap --script=dns-brute [target]
The dns-brute script is a reconnaissance tool that performs DNS brute force enumeration. It attempts to discover subdomains and hostnames associated with a target domain. This can be helpful in identifying potential entry points into a network or system.
This command instructs Nmap to run the dns-brute script against the example.com domain. The script will attempt to uncover subdomains and hostnames, providing a more comprehensive view of the target's DNS infrastructure.
Example Usage: nmap --script=dns-brute example.com

dns-zone-transfer
Command: nmap --script dns-zone-transfer.nse [args] [target]
The dns-zone-transfer script is designed to attempt a DNS zone transfer with the target domain's DNS servers. A successful zone transfer can reveal a treasure trove of information about the target domain's DNS infrastructure, including hostnames, IP addresses, and other DNS records.
In this command, we're instructing Nmap to run the dns-zone-transfer script against the example.com domain. The script will attempt to perform a DNS zone transfer, which could reveal valuable information if the DNS servers are misconfigured to allow such transfers.
Example Usage: nmap --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=example.com

ftp-anon
Command: nmap --script=ftp-anon [target]
The ftp-anon script is a handy tool for identifying misconfigured FTP servers. It checks if anonymous FTP login is enabled, which could allow unauthorized access to the server's files and directories.
In this command, we're instructing Nmap to run the ftp-anon script against the target IP address 192.168.1.1. The script will attempt to log in to the FTP server anonymously, revealing whether such access is possible.
Example Usage: nmap --script=ftp-anon 192.168.1.1

smtp-enum-users
Command: nmap --script=smtp-enum-users [args] [target]
The smtp-enum-users script is a reconnaissance tool that enumerates email addresses of users on SMTP servers. This can be useful for gathering information about a target's email system, which can be valuable for further analysis or potential exploitation.
In this command, we're instructing Nmap to run the smtp-enum-users script against the mail.example.com domain. The script will attempt to enumerate email addresses, providing a list of potential targets for further investigation or phishing attempts.
Example Usage: nmap --script=smtp-enum-users --script-args smtp.domain=mail.example.com

vulners
Command: nmap --script=vulners [args] [target]
The vulners category in Nmap includes multiple scripts that are designed to detect specific vulnerabilities in target systems.
These scripts are invaluable for vulnerability assessment and penetration testing, as they can help identify potential weaknesses that could be exploited.
In this command, we're instructing Nmap to run all scripts within the vulners category against the example.com domain. The scripts will attempt to identify known vulnerabilities, providing a detailed report of potential security issues.
Example Usage: nmap --script=vulners --script-args mincvss=5.0 example.com

snmp-brute
Command: nmap --script=snmp-brute [target]
The snmp-brute script is a powerful tool for identifying weak community strings or credentials in SNMP (Simple Network Management Protocol) services. It performs brute force authentication attacks, which can reveal vulnerabilities that could be exploited.
In this command, we're instructing Nmap to run the snmp-brute script against the target IP address 192.168.1.1. The script will attempt to perform a brute force authentication attack, potentially revealing weak community strings or credentials.
Example Usage: nmap --script=snmp-brute 192.168.1.1

http-vuln-
Command: nmap --script=http-vuln-* [target]
The http-vuln- scripts are a set of scripts that detect specific vulnerabilities in web applications and web servers. They can identify common vulnerabilities like SQL injection, cross-site scripting (XSS), and more, making them invaluable tools for web application security assessments. You can run the script against a vulnerability by specifying it in the script such --script http-vuln-cve2017-8917, or use the wildcard symbol * to check against all.
In this command, we're instructing Nmap to run all scripts within the http-vuln- category against the example.com domain. The scripts will attempt to identify known web vulnerabilities, providing a detailed report of potential security issues.
Example Usage: nmap --script=http-vuln-cve2017-8917 example.com

smb-enum-shares
Command: nmap --script=smb-enum-shares [target]
The smb-enum-shares script is a reconnaissance tool that enumerates shares available on SMB (Server Message Block) services. It helps in discovering accessible file shares and understanding the file-sharing configurations of target systems.
In this command, we're instructing Nmap to run the smb-enum-shares script against the target IP address 192.168.1.1. The script will attempt to enumerate file shares, providing a list of potential access points into the system.
Example Usage: nmap --script=smb-enum-shares 192.168.1.1


