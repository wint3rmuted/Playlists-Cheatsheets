## Wordpress WPScan
```
wordpress, wpscan -u http://10.10.10.88/webservices/wp/ --enumerate p,t,u | tee wpscan.log 
	wpscan --url $URL --disable-tls-checks -U users.txt -P /usr/share/wordlists/rockyou.txt
	wpscan --url https://brainfuck.htb --disable-tls-checks --api-token $WPSCAN_API
```


