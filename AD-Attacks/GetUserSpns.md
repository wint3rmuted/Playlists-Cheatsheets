## GetUserSPNs.py
```
The GetUserSPNs.py tool is part of the Impacket Suite of Tools
The beautiful thing about the GetUserSPNs.py script is that it is executed remotely on the attacker side, which means it is not necessary to have a foothold on the victim to perform this attack. 
However, you will still need a valid user/pass combo as that is ALWAYS a requirement for kerberoasting.

Now, using the following command, we can remotely request a service ticket (change the user/pass and IP for your needs):

GetUserSPNs.py corp.local/muted:pAssWord123 -dc-ip 172.16.1.5 -request
```
