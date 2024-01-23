## LDAP enumeration with Nmap
```
Enumeration with nmap scripts
nmap -p 389 --script ldap-search 10.10.10.x
nmap -n -sV --script "ldap*" -p 389 10.10.10.x
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='MEGACORP.CORP',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt 10.10.13.100
nmap -n -sV --script "ldap* and not brute" 192.168.152.122
```
