## Hashcat
```
# Search for correct hashcat number
hashcat --example-hashes | grep -B5 {HASH IDENTIFIER}
hashcat -h | grep -i "ntlmv2" 

# Crack Hash
hashcat -m {HASH NUMBER} {HASH} /usr/share/wordlists/rockyou.txt -O --force

Attack Modes
-a 0 # Straight : hash dict
-a 1 # Combination : hash dict dict
-a 3 # Bruteforce : hash mask
-a 6 # Hybrid wordlist + mask : hash dict mask
-a 7 # Hybrid mask + wordlist : hash mask dict

Example Hashes - If you are struggling to match a hash, consult the index and try to visually match it and ctrl+f it.
https://hashcat.net/wiki/doku.php?id=example_hashes  

Rules
/usr/share/hashcat/rules
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule

Fav Rules:
OneRuleToRuleThemAll.rule
OneRuleToRuleThemStill.rule
/usr/share/hashcat/rules/rockyou-30000.rule
/usr/share/hashcat/rules/best64.rule

Generate Word List
Hashcat has a nice rules syntax for generating wordlists. In the help for hashcat it defines the different character sets:
- [ Built-in Charsets ] -

  ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz [a-z]
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
  d | 0123456789                 [0-9]
  h | 0123456789abcdef           [0-9a-f]
  H | 0123456789ABCDEF           [0-9A-F]
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  a | ?l?u?d?s
  b | 0x00 - 0xff

Generate a list using Morris?d?d?d?d?s:
$ /opt/hashcat-6.2.5/hashcat.bin --stdout -a 3 Morris?d?d?d?d?s > mute-passwords

Responder hashes
hashcat -h | grep -i "ntlmv2" 
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol\

Group Policy XML files
Crack XML cpassword string
gpp-decrypt {HASH}


Kerberoast Rubeus Crack:
TGS-REP Hash
PS C:\> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol

13100 is the correct mode to crack TGS-REP hashes.
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

AS-REP-Roast Crack:
PS C:\> .\Rubeus.exe asreproast /nowrap  <-- Using Rubeus to kerberoast locally.
impacket-GetNPUsers -dc-ip 192.168.x.x  -request -outputfile hashes.asreproast corp.com/mute <-- Using GetNPUsers to perform AS-REP roasting remotely.

Check correct mode for an AS-REP hash by grepping for "Kerberos" in hashcat help:
kali@kali:~$ hashcat --help | grep -i "Kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol

The correct mode for AS-REP is 18200.
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Hashcat Rules
```
New password policy passwords need 3 numbers, a capital letter and a special character
We can begin to create our rule file. We must include three numbers, at least one capital letter, and at least one special character.

For our first attempt, we'll just use the most common special characters "!", "@", and "#", since they are the first three special characters when typing them from the left side of many keyboard layouts.

Based on the analysis, we'll create our rules. We'll use c for the capitalization of the first letter and $1 $3 $7 for the numerical values. 
To address the special characters, we'll create rules to append the different special characters $!, $@, and $#.

$ cat ssh.rule
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

Next, we'll create a wordlist file containing the passwords from note.txt and save the output to ssh.passwords.

kali@kali:~/passwordattacks$ cat ssh.passwords
Window
mute
supermute
megamute
umbrellas

Now we can use Hashcat to perform the cracking by specifying the rules file, the wordlist, and the mode.

kali@kali:~/passwordattacks$ hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat (v6.2.5) starting

Hashfile 'ssh.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception
No hashes loaded.

Unfortunately, we receive an error indicating that our hash caused a "Token length exception". Several posts suggest that modern private keys and their corresponding passphrases are created with the aes-256-ctr cipher, which Hashcat's mode 22921 does not support.

This reinforces the benefit of using multiple tools since John the Ripper (JtR) can handle this cipher.

john.conf
To be able to use the previously created rules in JtR, we need to add a name for the rules and append them to the /etc/john/john.conf configuration file. For this demonstration, we'll name the rule sshRules with a "List.Rules" rule naming syntax (as shown in Listing 34). We'll use sudo and sh -c to append the contents of our rule file into /etc/john/john.conf.

kali@kali:~/passwordattacks$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
 Adding the named rules to the JtR configuration file

Now that we've successfully added our sshRules to the JtR configuration file, we can use john to crack the passphrase in the final step 
We'll define our wordlist with --wordlist=ssh.passwords, select the previously created rule with --rules=sshRules, and provide the hash of the private key as the final argument, ssh.hash.

kali@kali:~/passwordattacks$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

## Hydra
```
Syntax
hydra [OPTIONS] IP
Useful flags

    -h: see the help menu
    -l <LOGIN>: Pass single username/login
    -L <FILE>: Pass multiple usernames/logins
    -p <LOGIN>: Pass single known password
    -P <FILE>: Pass a password list or wordlist (ex.: rockyou.txt)
    -s <PORT>: Use custom port
    -f: Exit as soon as at least one a login and a password combination is found
    -R: Restore previous session (if crashed/aborted)

Options:
  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE
  -C FILE   colon separated "login:pass" format, instead of -L/-P options
  -M FILE   list of servers to attack, one entry per line, ':' to specify port
  -t TASKS  run TASKS number of connects in parallel per target (default: 16)
  -U        service module usage details
  -m OPT    options specific for a module, see -U output for information
  -h        more command line options (COMPLETE HELP)
  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
  service   the service to crack (see below for supported protocols)
  OPT       some service modules support additional input (-U for module help)
  -V for verbosity

HTTP-Post-Form
Bruteforce web HTTP form
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "<Login Page>:<Request Body>:<Error Message>"
sudo hydra <Username/List> <Password/List> <IP> <Method> "<Path>:<RequestBody>:<IncorrectVerbiage>"

After filling in the placeholders, here’s our command:
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.x http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"

HTTP-form-post
Putting these pieces together, we can complete the http-form-post syntax as given in Listing 21.
Specifying the http-form-post syntax
http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN"
    
The complete command can now be executed. 
We will supply the admin user name (-l admin) and wordlist (-P), request verbose output with -vV, and use -f to stop the attack when the first successful result is found. 
In addition, we will supply the service module name (http-form-post) and its required arguments ("/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN") 
kali@kali:~$ hydra 10.11.0.x http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f

Hydra Post on a forum
hydra -l mute -P /usr/share/wordlists/rockyou.txt internal.site.tld http-form-post "/simple_chat/login.php:uname=^USER^&passwd=^PASS^&submit=login:Invalid Username or Password"

Post with Cookies
hydra -l garry -F -P /usr/share/wordlists/rockyou.txt 10.11.x.x -s 8080 http-post-form "/php/index.php:tg=login&referer=index.php&login=login&sAuthType=Ovidentia&nickname=^USER^&password=^PASS^&submit=Login:F=Failed:H=Cookie\: OV3176019645=a4u215fgf3tj8718i0b1rj7ia5"

-F stop after getting login
http-post-form “<url>:<post data>:F=<fail text:H=<header>”
  
HTTP-Post  
sudo hydra <Username/List> <Password/List> <IP> <Method> "<Path>:<RequestBody>:<IncorrectVerbiage>"
After filling in the placeholders, here’s our actual command!
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"

The HTTP POST body sends two values in the login form to /service/rapture/sesssion — a username and a password, both base64 encoded.  
Check headers filename to see where the http post body is sending the two values

A valid hydra command would look like this:
# -I : ignore any restore files
# -f : stop when a login is found
# -L : username list
# -P : password list
# ^USER64^ and ^PASS64^ tells hydra to base64-encode the values <-- Base64 Encode
# C=/ tells hydra to establish session cookies at this URL
# F=403 tells hydra that HTTP 403 means invalid login

hydra -I -f -L usernames.txt -P passwords.txt 'http-post-form://192.168.207.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://192.168.207.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
kali@kali:~$ sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

FTP
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt x.x.x.x ftp
hydra -e nsr -C /usr/share/seclists/Passwords/Default-Credentials 10.11.x.x ftp
hydra -e nsr -L username <IP address> ftp 

The -e switch has three options, n, s, and r:
    n: This option checks for a null password
    s: This option is used for login name as password
    r: This is the reverse of login name as password
    - L: specify a list of usernames
    - P: specify a list of passwords
    -C: Colon separated file for username/password colon-seperated formatted files.
    
For FTP attack use this command
    #hydra -l userlogin -P password-list-adress ftp://----IP--Address -V
    
FTP: 
$ hydra -l admin -C /usr/share/seclists/Passwords/Default-Credentials 192.168.x.x ftp ← Good default cred list. 

SSH:
$ hydra -L users -P pass ssh://192.168.x.x -t 4 -s 43022

SSH
Bruteforce SSH credentials
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP -t 4 ssh

-f: Exit as soon as at least one a login and a password combination is found
-t: Tasks, run tasks number of connects in parallel per target, default is 16 Tasks. 

For ssh attack:
Hydra -l userlogin -P password-list-adress ssh:// — — IP — Address -V

MySQL:
Bruteforce MySQL credentials
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP mysql

SMB:
Bruteforce SMB credentials
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP smb

RDP:
hydra -t 1 -V -f -l administrator -P rockyou.txt rdp://192.168.x.x

RDP:
Windows RDP
Bruteforce Windows Remote Desktop credentials
hydra -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$IP

RDP:
Hydra RDP
sudo hydra -f -l nadine -P /usr/share/wordlists/rockyou.txt -s 3389 rdp://192.168.x.x -v -t 4
```























