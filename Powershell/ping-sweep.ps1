#$ip = "127.0.0.1"
param($p1)

if (!$p1){
    Write-Output "Usage: ./script.ps1 <ip>"
    Write-Output "Example: ./script.ps1 192.168.0"
} else {
    Write-Output "Host's Response:"
    foreach ($final in 1..254){ #class A networks only
        try{
            $response = ping -c 1 "$p1.$final" | Select-String "64","bytes=32"
            $response.Line.split(':')[0]
        } catch{}
    }
}
