# A PowerShell script to query the UAC.
# Retrieves the values of the LocalAccountTokenFilterPolicy and FilterAdministratorToken registry keys, and take user input to save the output to a .txt file
# For Reference: 
# If EnableLUA=0 or doesn't exist, no UAC for anyone
# If EnableLua=1 and LocalAccountTokenFilterPolicy=1 , No UAC for anyone
# If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=0, No UAC for RID 500 (Built-in Administrator)
# If EnableLua=1 and LocalAccountTokenFilterPolicy=0 and FilterAdministratorToken=1, UAC for everyone

# Function to print colored text
function Write-ColoredText {
    param (
        [string]$text,
        [string]$color
    )

    Write-Host $text -ForegroundColor $color
}

# Display ASCII banner with colored text
Write-ColoredText @"

 _     _ _______ _______ _______ _______ _______ __   _
 |     | |_____| |       |______ |       |_____| | \  |
 |_____| |     | |_____  ______| |_____  |     | |  \_|
                            by @wint3rmute
"@ "Cyan"

# Define the registry path for UAC settings
$uacRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Get the value of the EnableLUA registry key
$enableLUA = Get-ItemProperty -Path $uacRegistryPath -Name EnableLUA

# Get the value of the ConsentPromptBehaviorAdmin registry key
$consentPromptBehaviorAdmin = Get-ItemProperty -Path $uacRegistryPath -Name ConsentPromptBehaviorAdmin

# Display the UAC settings with colored text
Write-ColoredText "UAC Settings:" "White"
Write-ColoredText "EnableLUA: $($enableLUA.EnableLUA)" "White"
Write-ColoredText "ConsentPromptBehaviorAdmin: $($consentPromptBehaviorAdmin.ConsentPromptBehaviorAdmin)" "White"

# Define the registry path for LocalAccountTokenFilterPolicy
$tokenFilterRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Get the value of the LocalAccountTokenFilterPolicy registry key
$localAccountTokenFilterPolicy = Get-ItemProperty -Path $tokenFilterRegistryPath -Name LocalAccountTokenFilterPolicy

# Get the value of the FilterAdministratorToken registry key
$filterAdministratorToken = Get-ItemProperty -Path $uacRegistryPath -Name FilterAdministratorToken

# Display the values of LocalAccountTokenFilterPolicy and FilterAdministratorToken with colored text
Write-ColoredText "LocalAccountTokenFilterPolicy: $($localAccountTokenFilterPolicy.LocalAccountTokenFilterPolicy)" "White"
Write-ColoredText "FilterAdministratorToken: $($filterAdministratorToken.FilterAdministratorToken)" "White"

# Prompt user for file path to save output
$filePath = Read-Host "Enter the path to save the output (include .txt extension):"

# Create a hashtable with data to be saved
$outputData = @{
    "EnableLUA" = $enableLUA.EnableLUA
    "ConsentPromptBehaviorAdmin" = $consentPromptBehaviorAdmin.ConsentPromptBehaviorAdmin
    "LocalAccountTokenFilterPolicy" = $localAccountTokenFilterPolicy.LocalAccountTokenFilterPolicy
    "FilterAdministratorToken" = $filterAdministratorToken.FilterAdministratorToken
}

# Convert hashtable to string and save to file
$outputData | Out-String | Out-File -FilePath $filePath

Write-ColoredText "Output saved to $filePath" "Green"
