Write-Host "WN10-CC-000260: Configure Windows 10 to require a minimum PIN length of 6 characters or greater” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
$valueName = "MinimumPINLength"
$valueData = 6
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-SO-000070: Set machine inactivity limit to 15 minutes, locking the system with the screensaver” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "InactivityTimeoutSecs"
$valueData = 900  # 0x00000384 in decimal
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AC-000010: The number of allowed bad logon attempts must be configured to 3 or less.

Write-Host "WN10-CC-000326: Enable PowerShell script block logging” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$valueName = "EnableScriptBlockLogging"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-AU-000510: Configure Application event log size to 32768 KB or greater” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$valueName = "MaxSize"
$valueData = 32768  # 0x00008000 in decimal
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-CC-000204: Limit Enhanced diagnostic data to the minimum required to support Windows Analytics” -ForegroundColor Cyan

Write-Host "WN10-CC-000100: Prevent downloading print driver packages over HTTP” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableWebPnPDownload"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

#Write-Host "WN10-SO-000220: The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.

Write-Host "WN10-AU-000500: Configure Application event log size to 32768 KB or greater” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 32768  # 0x00008000 in decimal
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-CC-000195: Enhanced anti-spoofing for facial recognition must be enabled on Window 10.

Write-Host "WN10-CC-000390: Disable third-party app suggestions in Windows Spotlight” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableThirdPartySuggestions"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-CC-000238: Prevent certificate error overrides in Microsoft Edge
# WN10-PK-000015: Install DoD Interoperability Root CA cross-certificates on unclassified systems
# WN10-UR-000160: Assign 'Restore files and directories' user right to Administrators only
# WN10-CC-000007: Windows 10 must cover or disable the built-in or attached camera when not in use.

Write-Host "WN10-CC-000044: Disable Internet Connection Sharing” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$valueName = "NC_ShowSharedAccessUI"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-CC-000085: Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers
# WN10-CC-000068: Enable Remote host allows delegation of non-exportable credentials
# WN10-AU-000005: Enable auditing of system events (success and failure)
# WN10-SO-000280: Passwords for enabled local Administrator accounts must be changed at least every 60 days

Write-Host "WN10-CC-000245: The password manager function in the Edge browser must be disabled.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
$valueName = "FormSuggest Passwords"
$valueData = "no"
$valueType = "String"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-UR-000085: The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.
# WN10-AU-000085: The system must be configured to audit Object Access - Removable Storage failures.
# WN10-AU-000570: Windows 10 must be configured to audit Detailed File Share Failures.”
# WN10-AU-000060: The system must be configured to audit Logon/Logoff - Group Membership successes
# WN10-AU-000120: The system must be configured to audit System - IPSec Driver failures
# WN10-00-000107: Disable Copilot in Windows
# WN10-00-000155: Disable Windows PowerShell 2.0 feature”
# WN10-CC-000285: Require secure RPC communication for Remote Desktop Session Host

Write-Host "WN10-CC-000305: Indexing of encrypted files must be turned off.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$valueName = "AllowIndexingEncryptedStoresOrItems"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-CC-000330: Disable Basic authentication for WinRM client” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowBasic"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-AU-000505: The Security event log size must be configured to 1024000 KB or greater.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valueName = "MaxSize"
$valueData = 1024000  # 0x000FA000 in decimal
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-CC-000385: Configure Windows Ink Workspace to disallow access above the lock screen” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"
$valueName = "AllowWindowsInkWorkspace"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AC-000035: Passwords must, at a minimum, be 14 characters.
# WN10-AU-000081: Configure audit policy for Object Access - File Share failures
# WN10-CC-000270: Prevent saving passwords in Remote Desktop Client

Write-Host "WN10-CC-000200: Disable enumeration of administrator accounts during elevation” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$valueName = "EnumerateAdministrators"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host “WN10-CC-000275: Local drives must be prevented from sharing with Remote Desktop Session Hosts.”-ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fDisableCdm"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-UR-000010: The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups.

Write-Host "STIG remediation complete. A reboot is recommended for all settings to apply." -ForegroundColor Green
