## Invoke-Kerberoast.ps1
```
Invoke-Kerberoast.ps1 is a PowerShell script that is part of the PowerShell Empire post-exploitation framework.

There are two ways that we can use this script: 
If you have a PowerShell prompt on the victim, download the script to disk, use dot sourcing to load it into the current session,
 and then run the following command to request a ticket and receive the hash in a hashcat crackable format:

. .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat hashcat | fl

If you have gotten a foothold on the victim but you are currently in a cmd.exe prompt, you can try using the command powershell -ep bypass to upgrade from cmd.exe to PowerShell. 
If that command causes the prompt to hang and ultimately fails to work, then you will need to send back a Nishang reverse PowerShell shell to yourself or find another way to upgrade to a PowerShell prompt.

Auto-Execute
Alternatively, the Invoke-Kerberoast command can be appended to the bottom of the script and then using the IEX command, we can download it directly into memory, which allows the command that we hardcoded to the bottom of the script to auto-execute.
For this, you will want to copy the Invoke-Kerberoast.ps1 script into your working directly so that you are not editing the original script.

Add the following command to bottom of script like so:
 Invoke-Kerberoast -OutputFormat hashcat | fl 
```
