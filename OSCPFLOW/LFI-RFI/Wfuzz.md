## wfuzz
```
Some of the benefits of using wfuzz include:

    Automating the fuzzing process and saving time and effort
    Customizing payloads to identify specific vulnerabilities
    Identifying potential security issues before they can be exploited
    Integrating with other tools like Burp Suite to streamline the testing process

Basic usage:

wfuzz -c [OPTIONS] URL

OPTIONS:

    -c : colorize the output
    -z : set the payload type (list, num, etc.)
    -d : set the data to be sent with the request
    -H : set the headers to be sent with the request
    -e : set the encoding for the payload (urlencode, hex, etc.)
    -w : set the wordlist to be used for fuzzing
    -p : set the number of concurrent connections
    -t : set the timeout for each request
    -s : set the delay between each request
    -L : follow redirects

Payload types:

    list : use a wordlist to fuzz the target
    num : use a range of numbers to fuzz the target
    alpha : use the alphabet to fuzz the target
    alphanum : use a combination of numbers and letters to fuzz the target
    hex : use hexadecimal values to fuzz the target

wfuzz -c -z list,common.txt https://example.com/FUZZ
wfuzz -c -z num,1-10 https://example.com/FUZZ
wfuzz -c -z alpha https://example.com/FUZZ
wfuzz -c -z alphanum https://example.com/FUZZ
wfuzz -c -z hex https://example.com/FUZZ
wfuzz -c -o json https://example.com/FUZZ
wfuzz --hh 3  -b 'PHPSESSID=ck29o8sviahdj7jec63dgt3' -w /usr/share/wordlists/Seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://10.10.10.66/secret/download.php?FUZZ=/etc/passwd

wfuzz -c -w -d "password=FUZZ" -u "http://IP_ADDRESS" --hh 474 -t 42-c Output text with colors nice feature.
-w wordlist
-d Post-Data request
-u url
--hh hide response chars length
-t threads 

wfuzz -c -b 'PHPSESSID=RepLAceME' -w '/the dictionary' -d 'http://Subscribe/to/ippsec.php?FUZZ=/etc/passwd'-d post-data
--hh hide responses with a n(1,2,4,22) character length
-b Cookie or the php session id
-w Dictionary WordList what have you https://github.com/danielmiessler/SecLists
by defaul the last part is always the url or target you can uses the -u url
-H header FUZZ.hackthebox.htb used to enumerate subdomains /Seclist/Discovery/DNS/subdomains-top1mil-5000.txt

wfuzz -c -b 'PHPSESSID=RepLAceME' -w '/the dictionary' -u 'http://Subscribe/to/ippsec.php?action=FUZZ'
This method is different than the above. This uses get request or a standard request.
-d is for post. For this one action is replaceable with any php action info file action.
-c add colour 
-b session id you mgiht need it
-w word dictionary
-u url
```

## Advanced wfuzz Usage
## Specify headers
```
You can use the “-H” option followed by the header value. For example:
wfuzz -c -H "Authorization: Bearer token" https://example.com/FUZZ
```

## Specify cookies
```
You can use the “ — cookie” option followed by the cookie value. For example:
wfuzz -c --cookie "name=value" https://example.com/FUZZ
```

## Specify multiple headers or cookies
```
Sseparate them with a semicolon (;). For example:
wfuzz -c -H "Authorization: Bearer token; Content-Type: application/json" --cookie "name=value; session=1234" https://example.com/FUZZ
```

## Fuzzing Authentication systems
```
To fuzz authentication systems using wfuzz, you can use the “-d” option to specify the login credentials and the “-b” option to specify any necessary cookies. For example:
wfuzz -c -d "username=admin&password=FUZZ" -b "session=12345" https://example.com/login.php
```

## Combine authentication fuzzing with other fuzzing techniques
```
Such as brute force or injection, to test for a wider range of vulnerabilities. For example:
wfuzz -c -z brute-force -d "username=admin&password=FUZZ" -b "session=12345" https://example.com/login.php
```

## wfuzz with Burp Suite
```
wfuzz can be integrated with Burp Suite to automate the fuzzing process and identify vulnerabilities in web applications. By using wfuzz with Burp Suite, you can leverage the power of both tools and streamline your testing process.
To run wfuzz from Burp Suite, follow these steps:

    Install the wfuzz extension for Burp Suite.
    Launch Burp Suite and navigate to the “Extender” tab.
    Click on the “Extensions” tab and select “Add”.
    Locate the wfuzz extension file and click “Next” to install it.
    Navigate to the “Proxy” tab and send a request to the endpoint you want to fuzz.
    Right-click on the request in the “Proxy” history and select “Send to wfuzz”.
    In the wfuzz interface, specify the payload you want to use and any other options you want to configure.
    Click “Start Fuzzer” to begin the fuzzing process.

Interpreting results in Burp Suite can be done in several ways. One way is to view the results in the “Proxy” history and look for unusual responses or error messages. Another way is to use the Burp Suite “Scanner” to automatically scan the target for vulnerabilities and generate a report.

By using wfuzz with Burp Suite, you can automate the fuzzing process and identify vulnerabilities in web applications more quickly and accurately. This approach allows you to save time and effort while ensuring the security of your web applications.
```







