## HTTP Enumeration with Nmap
```
Don't be afraid to read through the list of NSE scripts.
Using additional NSE scripts for whatever protocol you are looking at can be a big help in gathering those extra little details during enumeration. 

HTTP Service Information
Gather page titles from HTTP services 	nmap --script=http-title 192.168.1.0/24
Get HTTP headers of web services 	nmap --script=http-headers 192.168.1.0/24
Find web apps from known paths 	nmap --script=http-enum 192.168.1.0/24

While Nmap is not a vulnerability scanner in the traditional sense, it can be very useful for similar tasks. 
Use --script vuln to run all scripts in the "vuln" category against a target:
kali@kali:~$ sudo nmap --script vuln 10.11.1.10

HTTP Recon ( http-enum.nse)
Nmap comes with a wide range of NSE scripts for testing web servers and web applications.
An advantage of using the NSE scripts for your HTTP reconnaissance is that you are able to test aspects of a web server against large subnets.
This can quickly provide a picture of the types of servers and applications in use within the subnet.
http-enum.nse

One of the more aggressive tests, this script effectively brute forces a web server path in order to discover web applications in use. Attempts will be made to find valid paths on the web server that match a list of known paths for common web applications.
The standard test includes testing of over 2000 paths, meaning that the web server log will have over 2000 entries that are HTTP 404 not found, not a stealthy testing option! This is very similar to the Nikto web server testing tool.

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

http-adobe-coldfusion-apsa1301.nse
http-affiliate-id.nse
http-apache-negotiation.nse
http-apache-server-status.nse
http-aspnet-debug.nse
http-auth-finder.nse
http-auth.nse
http-avaya-ipoffice-users.nse
http-awstatstotals-exec.nse
http-axis2-dir-traversal.nse
http-backup-finder.nse
http-barracuda-dir-traversal.nse
http-bigip-cookie.nse
http-brute.nse
http-cakephp-version.nse
http-chrono.nse
http-cisco-anyconnect.nse
http-coldfusion-subzero.nse
http-comments-displayer.nse
http-config-backup.nse
http-cookie-flags.nse
http-cors.nse
http-cross-domain-policy.nse
http-csrf.nse
http-date.nse
http-default-accounts.nse
http-devframework.nse
http-dlink-backdoor.nse
http-dombased-xss.nse
http-domino-enum-passwords.nse
http-drupal-enum.nse
http-drupal-enum-users.nse
http-enum.nse
http-errors.nse
http-exif-spider.nse
http-favicon.nse
http-feed.nse
http-fetch.nse
http-fileupload-exploiter.nse
http-form-brute.nse
http-form-fuzzer.nse
http-frontpage-login.nse
http-generator.nse
http-git.nse
http-gitweb-projects-enum.nse
http-google-malware.nse
http-grep.nse
http-headers.nse
http-hp-ilo-info.nse
http-huawei-hg5xx-vuln.nse
http-icloud-findmyiphone.nse
http-icloud-sendmsg.nse
http-iis-short-name-brute.nse
http-iis-webdav-vuln.nse
http-internal-ip-disclosure.nse
http-joomla-brute.nse
http-jsonp-detection.nse
http-litespeed-sourcecode-download.nse
http-ls.nse
http-majordomo2-dir-traversal.nse
http-malware-host.nse
http-mcmp.nse
http-methods.nse
http-method-tamper.nse
http-mobileversion-checker.nse
http-ntlm-info.nse
http-open-proxy.nse
http-open-redirect.nse
http-passwd.nse
http-phpmyadmin-dir-traversal.nse
http-phpself-xss.nse
http-php-version.nse
http-proxy-brute.nse
http-put.nse
http-qnap-nas-info.nse
http-referer-checker.nse
http-rfi-spider.nse
http-robots.txt.nse
http-robtex-reverse-ip.nse
http-robtex-shared-ns.nse
http-sap-netweaver-leak.nse
http-security-headers.nse
http-server-header.nse
http-shellshock.nse
http-sitemap-generator.nse
http-slowloris-check.nse
http-slowloris.nse
http-sql-injection.nse
https-redirect.nse
http-stored-xss.nse
http-svn-enum.nse
http-svn-info.nse
http-title.nse
http-tplink-dir-traversal.nse
http-trace.nse
http-traceroute.nse
http-trane-info.nse
http-unsafe-output-escaping.nse
http-useragent-tester.nse
http-userdir-enum.nse
http-vhosts.nse
http-virustotal.nse
http-vlcstreamer-ls.nse
http-vmware-path-vuln.nse
http-vuln-cve2006-3392.nse
http-vuln-cve2009-3960.nse
http-vuln-cve2010-0738.nse
http-vuln-cve2010-2861.nse
http-vuln-cve2011-3192.nse
http-vuln-cve2011-3368.nse
http-vuln-cve2012-1823.nse
http-vuln-cve2013-0156.nse
http-vuln-cve2013-6786.nse
http-vuln-cve2013-7091.nse
http-vuln-cve2014-2126.nse
http-vuln-cve2014-2127.nse
http-vuln-cve2014-2128.nse
http-vuln-cve2014-2129.nse
http-vuln-cve2014-3704.nse
http-vuln-cve2014-8877.nse
http-vuln-cve2015-1427.nse
http-vuln-cve2015-1635.nse
http-vuln-cve2017-1001000.nse
http-vuln-cve2017-5638.nse
http-vuln-cve2017-5689.nse
http-vuln-cve2017-8917.nse
http-vuln-misfortune-cookie.nse
http-vuln-wnr1000-creds.nse
http-waf-detect.nse
http-waf-fingerprint.nse
http-webdav-scan.nse
http-wordpress-brute.nse
http-wordpress-enum.nse
http-wordpress-users.nse
http-xssed.nse

```
