# OSCP Master Reference
## FTP (21)
```
Connect:
ftp <ip>

Anonymous Login:
anonymous : anonymous
anonymous :
ftp : ftp

Downloading files:
ftp <IP>
PASSIVE
BINARY 
get <FILE>
mget <-- Multiple files

Uploading files:
ftp <IP>
PASSIVE
BINARY
put <FILE>

Enumeration:
***Check Public exploits for ftp server software***
You can us the commands HELP and FEAT to obtain some information of the FTP server.
nmap --script ftp-* -p 21 <ip>
sudo nmap -sV -p 21 -sC -A <ip>
nmap -p 21 --script="+*ftp* and not brute and not dos and not fuzzer" -vv -oN ftp > $ip

Enumeration - Banner Grabbing
nc -vn <IP> 21

Brute force:
Seclists - /passwords/default-credentials/ftp-betterdefaultpasslist.txt
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV
hydra -e nsr -C /usr/share/seclists/Passwords/Default-Credentials 10.11.1.13 ftp
hydra -e nsr -L usernames.txt -P /usr/share/Seclists/passwords/default-credentials/ftp-betterdefaultpasslist.txt <IP address> ftp 

The -e switch has three options, n, s, and r:
    n: This option checks for a null password
    s: This option is used for login name as password
    r: This is the reverse of login name as password
    - L: specify a list of usernames
    - P: specify a list of passwords
    -C: Colon separated file for username/password colon-seperated formatted files.

NetExec Spray FTP:
netexec ftp <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords --continue-on-success
netexec ftp <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes  --continue-on-success

Do you have UPLOAD potential?
    $ Can you trigger execution of uploads?
    $ Swap binaries?

VSFTPd Post-Exploitation:
The default configuration of vsFTPd can be found in /etc/vsftpd.conf. In here, you could find some dangerous settings:
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/home/username/ftp - Directory for anonymous.
chown_uploads=YES - Change ownership of anonymously uploaded files
chown_username=username - User who is given ownership of anonymously uploaded files
local_enable=YES - Enable local users to login
no_anon_password=YES - Do not ask anonymous for password
write_enable=YES - Allow commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE

FTPBounce Attack: 
Some FTP servers allow the command PORT. 
This command can be used to indicate to the server that you wants to connect to other FTP server at some port. 
Then, you can use this to scan which ports of a host are open through a FTP server.

Filezilla Server vulnerability:
FileZilla usually binds to local an Administrative service for the FileZilla-Server (port 14147). 
If you can create a tunnel from your machine to access this port, you can connect to it using a blank password and create a new user for the FTP service.

Traditional ports, though they can be dynmically assigned:
Port 21 - control commands
Port 20 - data transfer

Active mode:
Client initiates control session on port 21 and leaves port 20 open for the server to send data, and the server initiates the connection for port 20.
***If client is behind a firewall, or NAT, then the sever might not be able to connect to send data.

Passive mode:
Server gives the client a port to initiate a connection to for data transfer.
***Most commonly used by browsers, etc.
```
