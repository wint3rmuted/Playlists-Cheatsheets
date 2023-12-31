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
