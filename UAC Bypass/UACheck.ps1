# This script retrieves the values of two important UAC registry keys: EnableLUA and ConsentPromptBehaviorAdmin. 
# These keys determine whether UAC is enabled and the behavior for administrative consent prompts.


# Display ASCII banner
Write-Host @"

██╗   ██╗ █████╗  ██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██╔══██╗██╔════╝ ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║███████║██║█████╗██║     ███████║█████╗  ██║     █████╔╝ 
██║   ██║██╔══██║██║╚════╝██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
╚██████╔╝██║  ██║╚██████╗ ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
            Powershell UAC Check by @wint3rmute                                                       
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
