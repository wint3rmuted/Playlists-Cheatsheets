# Get basic system information
$systemInfo = Get-WmiObject Win32_ComputerSystem
$osInfo = Get-WmiObject Win32_OperatingSystem

# Display system information
Write-Host "System Information:"
Write-Host "-------------------"
Write-Host "Computer Name: $($systemInfo.Name)"
Write-Host "Manufacturer: $($systemInfo.Manufacturer)"
Write-Host "Model: $($systemInfo.Model)"
Write-Host "Operating System: $($osInfo.Caption)"
Write-Host "Version: $($osInfo.Version)"
Write-Host "Service Pack: $($osInfo.ServicePackMajorVersion)"
Write-Host "Registered User: $($osInfo.RegisteredUser)"
Write-Host "Last Boot Time: $($osInfo.LastBootUpTime)"

# Get processor information
$processorInfo = Get-WmiObject Win32_Processor

# Display processor information
Write-Host "`nProcessor Information:"
Write-Host "----------------------"
Write-Host "Processor: $($processorInfo.Name)"
Write-Host "Cores: $($processorInfo.NumberOfCores)"
Write-Host "Threads: $($processorInfo.NumberOfLogicalProcessors)"
Write-Host "Max Clock Speed: $($processorInfo.MaxClockSpeed) MHz"

# Get memory (RAM) information
$memoryInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum

# Display memory information
Write-Host "`nMemory Information:"
Write-Host "-------------------"
Write-Host "Total Memory: $($memoryInfo.Sum / 1GB) GB"

# Get disk information
$diskInfo = Get-WmiObject Win32_LogicalDisk

# Display disk information
Write-Host "`nDisk Information:"
Write-Host "-----------------"
foreach ($disk in $diskInfo) {
    Write-Host "Drive $($disk.DeviceID): $($disk.Size / 1GB) GB Free Space"
}
