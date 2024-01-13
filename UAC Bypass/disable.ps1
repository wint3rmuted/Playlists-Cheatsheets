# This script retrieves the values of two important UAC registry keys: EnableLUA and ConsentPromptBehaviorAdmin. 
# These keys determine whether UAC is enabled and the behavior for administrative consent prompts.
# Continues to disable UAC in the Registry.

# Display ASCII banner
Write-Host @"
       __ _               __     __    
  ____/ /(_)_____ ____ _ / /_   / /___ 
 / __  // // ___// __ `// __ \ / // _ \
/ /_/ // /(__  )/ /_/ // /_/ // //  __/
\__,_//_//____/ \__,_//_.___//_/ \___/ 
           PS UAC Disable by @wint3rmute                                                       
"@

# Define the registry path for UAC settings
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Get the value of the EnableLUA registry key
$enableLUA = Get-ItemProperty -Path $registryPath -Name EnableLUA

# Get the value of the ConsentPromptBehaviorAdmin registry key
$consentPromptBehaviorAdmin = Get-ItemProperty -Path $registryPath -Name ConsentPromptBehaviorAdmin

# Display the UAC settings
Write-Host "UAC Settings:"
Write-Host "EnableLUA: $($enableLUA.EnableLUA)"
Write-Host "ConsentPromptBehaviorAdmin: $($consentPromptBehaviorAdmin.ConsentPromptBehaviorAdmin)"

# Disable UAC
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Cyan    
}

