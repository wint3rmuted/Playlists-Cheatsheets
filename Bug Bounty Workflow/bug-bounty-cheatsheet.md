## Methodology
```

So here's my general concept for how I plan to do most of my bug hunting for now:

    monitor / list all subs with sublist3r and cert.sh
    hook into discord webhook api so I can get notifications about new domains etc
    when a new sub is found 
        enumerate with limited rate using feroxbuster running through burp for visual hierarchy and file access
        API fuzz with kiterunner / wfuzz if allowed
        enumerate archive.org with hakrawler for hidden old API assets / enpoints / etc
        take interesting files and source and feed to AI and snyk for initial analysis
        manual code review
        start looking for various exploits like xss
            for XSS enumeration use payload list with limited rate using burp intruder or similar tool
            check XSS using manual enumeration and custom payloads not in lists
            use XSStrike
        nikto cause why not?
        look for open panels with nuclei
        use other custom nuclei templates and ones that make sense to use that others may be using as well
