## GPO Abuse
```
If we see GPO mentioned in bloodhound graph,then that means we can perform actions on behalf of that group policy object

SharpGPOAbuse is an excellent tool for GP related attacks
gpp attack (group policy preferences) MS14-025

In this attack we utilize a windows misconfiguration in which we can read credentials which admin stores in a xml file named Groups.xml.
This policy is stored in SYSVOL share which is readbale by every authenticated domain user to access policies etc we can get local admins and domain admins credentials which are utilizing the policies in SYSVOL share

we get password in a cpassword type but we can decrypt it from kali or online because the key to this encryption was leaked from microsoft

We can utilize metasploit module gpp enum to get passwords

we can also use a powershell script called Get-GPPPassword

    This command will give all cleartext passwords from the found SYSVOL share.Remember that we are interested in passwords from Groups.xml

    Get-GPPPassword

    This command will look for all SYSVOL shares for the entire domain

    Get-GPPPassword -Server domain.name

    This command will search whole forest by mapping out trusts and accessing the accessible SYSVOL shares

    Get-GPPPassword -SearchForest

    This will list out the found passwords only

    Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq

If we get access of Groups.xml in any other way we can copy the password stored in cpassword variable and decrypt using a tool called gpp decrypt

    gpp-decrypt passwordhash
```
