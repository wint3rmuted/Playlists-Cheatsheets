# Login Pages
## Try Default Credentials First
```
I've come to like pass-station for getting default creds from the cli:
https://github.com/sec-it/pass-station

$ pass-station search Weblogic

Other sources:
https://cirt.net/passwords
www.virus.org/default-password
Research application documentation to enumerate default users

```

## Hydra Dictionary Attack 
```
## HTTP POST Login Form
Attacking an HTTP POST login form with Hydra is not as straightforward as attacking SSH or RDP. 
We must first gather two different pieces of information. 
The first is the POST data itself, which contains the request body specifying the username and password. 
Second, we must capture a failed login attempt to help Hydra differentiate between a successful and a failed login.

We'll use Burp to intercept a login attempt so we can grab the request body in the POST data. 
Next, we need to identify a failed login attempt aka condition string
The simplest way to do this is to forward the request or turn intercept off and check the login form in the browser. 
In more complex applications, you may need to dig deeper into the request and response or even inspect the source code of the login form to isolate a failed login indicator.

Now we can assemble the pieces to start our Hydra attack. 
As before, we'll specify -l for the user, -P for the wordlist, the target IP without any protocol, and a new http-post-form argument, which accepts three colon-delimited fields.

The first field indicates the location of the login form. 
In this demonstration, the login form is located on the index.php web page. 
The second field specifies the request body used for providing a username and password to the login form, which we retrieved with Burp. 
Finally we must provide the failed login identifier, also known as a condition string.

Reduce False positives!
To reduce false positives, we should always try to avoid keywords such as password or username. To do so, shorten the condition string appropriately.
The complete command with the shortened condition string is shown below. 


kali@kali:~$ sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.x http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

As with any dictionary attack, this generates a lot of noise and many events. 
If installed, a Web Application Firewall (WAF) would block this activity quickly. 
Other brute force protection applications could also block this, such as fail2ban, which locks a user out after a set number of failed login attempts. 
However, web services aren't often afforded this type of protection, making this is a highly effective vector against those targets.
```


##  Hydra Get request login form
```
$ sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 80 -f 192.168.156.201 http-get -V

```
