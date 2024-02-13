# PG Nickel

## FTP
```
FTP service on port 21 is not accepting anonymous logins.
```
## Webserver on port 8089 (Devops Dash)
```
Navigating to ‘List Running Processes’ redirects to port 33333.
```
## GET ----> Post --> 411, content length
```
Doing a GET request on NICKEL:33333 does not work, however trying a post request gets a different response of 411.
The error in the HTTP Response states that the POST request requires a content length:
Content-Length:0

A list of running processes was retrieved.
There are some SSH credentials belonging to the user ‘ariah’. The password is encoded in base64.
Decode:
echo "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" | base64 -d
"NowiseSloopTheory139".

ssh ariah@192.168.152.99
Download a reverse shell and switch from ssh. 
```
## Privesc infrastructure.pdf
```
At the root of the C:\ drive, a folder named FTP can be found.
This folder houses the previously inaccessible FTP service.
The folder contains an interesting PDF file — “Infrastructure.pdf”.
Transfer to your local machine via SCP.
scp ariah@192.168.152.99:C:/ftp/Infrastructure.pdf .

The PDF file is password protected.
I will be using the tool Pdfcrack to crack the password-protected PDF file while leveraging the ‘rockyou’ wordlist.
pdfcrack -f Infrastructure.pdf -w /usr/share/wordlists/rockyou.txt
The password ‘ariah4168’ was recovered.
```
## /nickel/? endpoint
```
The cracked PDF file reveals information, the presence of more web servers.
A key finding is a temporary command endpoint that could be exploited using RCE.
A temporary command endpoint is identified at ‘http://nickel/?'.
This endpoint can be interacted with using PowerShell to send GET requests to the API endpoint.
This is done using the ‘Invoke-WebRequest’ command along with the ‘-UseBasicParsing’ parameter:

$Resp = Invoke-WebRequest 'http://nickel/?whoami' -UseBasicParsing

The command ‘$Resp = Invoke-WebRequest ‘http://nickel/?whoami' -UseBasicParsing’ is executed, running ‘whoami’ and returning the output.
This output is stored in the variable $Resp.RawContent, which holds the raw, unprocessed HTTP response.
This can include a range of information, such as the status line, headers, and body content.

$Resp.RawContent

When we inspect the $Resp.RawContent variable, it's revealed that we have RCE with SYSTEM privileges.
However, due to outbound traffic being blocked, it's not possible to spawn a secondary reverse shell with SYSTEM privileges.
Despite this, we're still able to execute commands as SYSTEM, which enables us to add the current user, 'ariah', to the Administrators group.

net localgroup Administrators

Alternatively, there’s also the option to gain a reverse shell by leveraging the same API GET request.
This can be done either by executing the same MSFVENOM payload previously uploaded to the ‘C:\users\ariah’ directory or by using CURL to the same temporary command execution endpoint.
```


