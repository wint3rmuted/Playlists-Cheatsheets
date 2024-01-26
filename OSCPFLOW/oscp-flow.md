## OSCPFLOW 
```
A high level view of my web application enumeration flow for the OSCP exam. 

1. Scan and find the web application. 
		- rustscan -a 192.168.45.220 --ulimit 10000  --no-nmap   // I like to use rustscan to find initial open ports then feed them into nmap.
		- nmap -v -Pn -sV -sC -p- 192.168.237.120 -T4 -oN nmapfullscripts.txt 
		    -Refer to NSE scripts for further modular scanning based on the protocol.
		
2. Create Application Profile. Look at web stack, databases and technology using Wappalyzer, whatweb, nse scripts, etc. 

3. Inspect Source Code. Curl the page and get the html or right click and inspect source. 
		- While inspecting html on a splash or any page, be on the lookout for hardcoded credentials and references to  interesting URLs, files, and directories.
		- Follow general guidelines for analyzing sourcecode.

4. Fully test the application. Create a user account, test links, test features and functionality across the site entirely.  "Walk the application" fully. 
		- You may choose to have burpsuite proxy intercept open and running while you test site functionality to capture all requests sent so you can further inspect them. You can use the burp browser for this. 

5. Fully Bruteforce Directories and Subdirectories.
		- Ffuf, Dirsearch, Gobuster, feroxbuster, you have options. I like to use dirsearch recursively.
		- Brute for files, directories,  and extensions.  Use modular seclists for servers when possible such as apache and IIS. 
		- Filetypes: php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old
		
Dirsearch:
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-files.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY with 90 threads filtering out 403, 404 responses
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-directories.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY
dirsearch -u http://192.168.237.120/ -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-large-extensions.txt -r -t 90 -x 403,404 ← SEARCH RECUSIVELY
Using Threads:
 dirsearch -e php,html,js,bak,zip,pdf,git,txt,ini,old -u https://site.org -t 90 -r -x 403,404

Now you have walked the app, inspected pages, clicked links, identified the web server for exploits, bruteforced directories. You may also want to brutforce DNS subdomains. 
Try default credentials for any CMS login portals such as phpmyadmin, jenkins, wordpress.
Login Pages, hydra bruteforce dictionary attack
SSH, hydra bruteforce
SQLi
file upload
directory traversal
LFI/RFI
Research Server for exploit
Wordpress

		
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Source Code Analysis:

1. Important functions first.
	When reading source code, focus on important functions such as authentication, password reset, state-changing actions and sensitive info reads. (What is the most important would depend on the application.) Then, review how these components interact with other functionality. Finally, audit other less sensitive parts of the application.
	
2.Follow user input
	Another approach is to follow the code that processes user input. User input such as HTTP request parameters, HTTP headers, HTTP request paths, database entries, file reads, and file uploads provide the entry points for attackers to exploit the application’s vulnerabilities.This may also help us to find some critical vulnerabilities like xxe,xxs,sql injection
	
3.Hardcoded secrets and credentials
	Hardcoded secrets such as API keys, encryption keys and database passwords can be easily discovered during a source code review. You can grep for keywords such as “key”, “secret”, “password”, “encrypt” or regex search for hex or base64 strings (depending on the key format in use).
	
4.Use of dangerous functions and outdated dependencies.
	Unchecked use of dangerous functions and outdated dependencies are a huge source of bugs. Grep for specific functions for the language you are using and search through the dependency versions list to see if they are outdated.

5.Developer comments, hidden debug functionalities, configuration files, and the .git directory:
These are things that developers often forget about and they leave the application in a dangerous state. Developer comments can point out obvious programming mistakes, hidden debug functionalities often lead to privilege escalation, config files allow attackers to gather more information about your infrastructure and finally, an exposed .git directory allows attackers to reconstruct your source code.

6.Hidden paths, deprecated endpoints, and endpoints in development:
These are endpoints that users might not encounter when using the application normally. But if they work and they are discovered by an attacker, it can lead to vulnerabilities such as authentication bypass and sensitive information leak, depending on the exposed endpoint.

7.Weak cryptography or hashing algorithms:
This is an issue that is hard to find during a black-box test, but easy to spot when reviewing source code. Look for issues such as weak encryption keys, breakable encryption algorithms, and weak hashing algorithms. Grep for terms like ECB, MD4, and MD5.

8.Missing security checks on user input and regex strength:
Reviewing source code is a great way to find out what kind of security checks are missing. Read through the application’s documentation and test all the edge cases that you can think of. A great resource for what kind of edge cases that you should consider is PayloadsAllTheThings.(github)

9.Missing cookie flags:
Look out for missing cookie flags such as httpOnly and secure.

10.Unexpected behavior, conditionals, unnecessarily complex and verbose functions:
Additionally, pay special attention to the application’s unexpected behavior, conditionals, and complex functions. These locations are where obscure bugs are often discovered.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


