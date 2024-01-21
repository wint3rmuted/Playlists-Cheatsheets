## Recon Resources
```
Domain Name Information Lookup:

    https://bgp.he.net/ : Hurricane Electric, an internet altyapısı monitoring and analysis service. It provides information about IP addresses, networks, and connections, and uses the BGP protocol. It is used for internet traffic routing and security analysis.
    https://whois.arin.net : Sometimes, you can use Hurricane Electric to confirm IP range intervals that you couldn’t find on your own. It’s a powerful tool on its own as well.
    https://linux.die.net/man/1/nslookup: nslookup, a tool that provides you with IP addresses, DNS records, and other details and information about the target domain, helping you understand the target’s infrastructure.
    www.yougetsignal.com : It’s a service that allows you to conduct various network and IP address research over the internet. It assists you in areas such as Port Scanning, IP Address Detection, DNS Records Examination, Email Server Check, Website Location Detection, SSL Certificate Verification, and many more.
    https://dnsdumpster.com/ : It’s a web-based service that allows users to search and analyze historical DNS records, subdomains, DNS changes, and provides insights into potential security issues.
    https://searchdns.netcraft.com/ : This online tool allows users to query and obtain DNS information such as DNS records, IP addresses, and domain registration details for a specific domain name or hostname.
```

## Service Enumeration
```
Service Enumeration:

    https://nmap.org/: It is a commonly used tool to scan open ports and running services on a network. It also discovers service versions and other network information.
```

## Subdomain Enumeration
```
Sub-domain enumeration (and sub-domain of sub-domains):

    gobuster: https://github.com/OJ/gobuster
    sublist3r: https://github.com/aboul3la/Sublist3r
    Amass: https://github.com/owasp-amass/amass/
    dnsrecon: https://github.com/darkoperator/dnsrecon
    Knockpy: https://github.com/guelfoweb/knock
    SubBrute: https://github.com/TheRook/subbrute
    altdns: https://github.com/infosec-au/altdns
    EyeWitness: https://github.com/ChrisTruncer/EyeWitness
```

## Check Certificates
```
Check Certificates:

    https://crt.sh/: It’s an important resource for cybersecurity experts and web administrators. It is used to monitor website security, understand certificate processes, and discover critical network information such as subdomains.
    https://github.com/drwetter/testssl.sh: It is a command-line tool used to test the SSL/TLS security and certificates of a web server.
    https://github.com/nabla-c0d3/sslyze: It is a free and open-source tool used to analyze and assess the SSL/TLS security configurations of computer systems and servers. This tool scans server SSL/TLS certificates, supported encryption protocols, certificate chains, security vulnerabilities, and other critical security settings, providing security experts and system administrators with detailed information about server security.
```

## OSINT
```
OSINT (Open Source Intelligence):

    https://archive.org/web/: It is an online archive service that preserves and makes accessible the history of the internet. This service is used to capture the history and content of websites. Users can explore the past of websites, access old content, recover lost web pages, and conduct research. Additionally, they can use past websites for educational purposes and leverage this resource to preserve the evolution of the internet. Archive.org/web is an important source for documenting the history of the internet and providing access to web content over time.
    https://www.exploit-db.com/: Users can find information here about security vulnerabilities available for current and older software and systems. They can access Metasploit modules and proof-of-concept (PoC) codes that guide how vulnerabilities can be exploited. This resource is an important tool that supports security research within the cybersecurity community and is used with the aim of enhancing the security of the digital world.
    https://github.com/lanmaster53/recon-ng: Recon-ng provides the ability to gather information from different sources, perform target analysis, utilize open-source intelligence (OSINT) data, and automate information gathering processes for security testing. Thanks to its modular structure, Recon-ng allows users to create customizable and expandable workflows.
    https://www.shodan.io/: This platform provides cybersecurity experts and researchers with a valuable resource for detecting potential security vulnerabilities, weaknesses, and cyber threats. Shodan offers valuable information about the overall state of the internet and contributes to raising awareness about cybersecurity and the development of security measures.
    https://github.com/laramies/theHarvester: theHarvester simplifies the process of gathering information from different sources and performing target analysis, serving as a valuable starting point for cybersecurity testing. Additionally, its modular structure allows users to create customizable and expandable workflows. This aids in gaining a better understanding of targets and conducting cybersecurity tests more effectively.
    https://inteltechniques.com/tools/index.html: Let’s talk about one of my favorite websites. Intel Techniques is a website and resource center created by OSINT expert Michael Bazzell, providing information, tools, and techniques for conducting OSINT investigations.
```

## Github Search
```
Github search automation tools:

    Gitrob: https://github.com/michenriksen/gitrob
    Git-all-secrets: https://github.com/anshumanbh/git-all-secrets
    truffleHog: https://github.com/dxa4481/truffleHog.git
    Git-secrets: https://github.com/awslabs/git-secrets
    Repo-supervisor: https://github.com/auth0/repo-supervisor
```

## Amazon S3 Buckets
```
Amazon S3 bucket finder:

    https://digi.ninja/projects/bucket_finder.php: identify and enumerate misconfigured Amazon S3 buckets, aiding in the discovery of potentially exposed data or sensitive information.
    Google Dork: It’s the finest way to perform fast and accurate searches on the internet. By using exploit-db, you can quickly gather new information about your target on Google.
    https://portswigger.net/burp: As many cybersecurity professionals would describe it, Burp is like a Swiss Army Knife and one of the biggest helpers for many bug bounty hunters. You can gather a wealth of information about Amazon S3 buckets using Burp. https://securityonline.info/aws-extender-burpsuite-extension-identify-test-s3-buckets-google-storage/
```

## Technology Lookup
```
Technology lookup:

    Netcraft: https://sitereport.netcraft.com/
    BuiltWith: https://builtwith.com/
    Wappalyzer: https://www.wappalyzer.com/
    Rescan: https://rescan.io/
    PageXRay: https://pagexray.com/
    WhatRuns: https://www.whatruns.com/
```

## Get URLs
```
Get URLs:

    GAU (Get All Urls): https://github.com/lc/gau
    Crawley: https://github.com/s0rg/crawley
    GoSpider: https://github.com/jaeles-project/gospider
    Zscanner: https://github.com/zseano/InputScanner
```

## Endpoints
```
Endpoints:

    Burp-Suite: https://portswigger.net/burp
    Katana: https://github.com/projectdiscovery/katana
```

## Find JS Files
```
Find JS files:

    JSScanner: https://github.com/tampe125/jscanner
    JS-Scan: https://github.com/zseano/JS-Scan
    hakrawler: https://github.com/hakluke/hakrawler
    gf: https://github.com/tomnomnom/gf
    LinkFinder: https://github.com/GerbenJavado/LinkFinder
```

## Find APEX Domain:
```
Find APEX Domain:

This part actually varies depending on the defined target. One of the things you need to determine for a thorough analysis is the apex domains. These could be companies that the company has acquired or has a high level of partnership with. The reason for identifying them is that a company can’t instantly detect and secure all the security measures of a newly acquired company. For this reason, discovering apex domains that are affiliated with the company and could be within the scope is crucial for a penetration test. The websites I’ll provide as examples here may vary, but they are all websites from which you can passively gather information about the company.

    Crunchbase: https://www.crunchbase.com/
    Dealroom: https://dealroom.co/
    ExplodingTopics: https://explodingtopics.com/
    Techcrunch: https://techcrunch.com/
```
