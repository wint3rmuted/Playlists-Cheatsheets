### NetExec Cheatsheet

## Installation
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

## Protocols
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

## Protocol Options
```
Using Protocol Options
To view a protocols options, run: nxc <protocol> --help
Then use those options: nxc <protocol> <protocol options>
```

## Viewing Available Protocols
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
