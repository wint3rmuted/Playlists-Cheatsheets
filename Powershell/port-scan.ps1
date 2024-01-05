param($ip)

if(!ip){
    Write-Output "Usage: ./script.ps1 <ip>"
}else {
    foreach ($port in 1..65535){
        if(Test-NetConnection 127.0.0.1 -Port 80 -WarningAction SilentlyContinue -InformationLevel Quiet){
            Write-Output "$port is open"
        }else{
            write-Output "$port is closed"
        } 
    }
}
