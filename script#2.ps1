# Run as Administrator

Write-Host "STIG WN10-CC-000252: Disable Windows Game Recording and Broadcasting." -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$valueName = "AllowGameDVR"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType


# WN10-00-000031: Require BitLocker PIN for pre-boot authentication”


Write-Host "WN10-CC-000038: Disable WDigest authentication” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
$valueName = "UseLogonCredential"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host “WN10-CC-000290: Set RDP encryption level to High” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "MinEncryptionLevel"
$valueData = 3
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType


# WN10-00-000032: Require BitLocker PIN with a minimum length of six digits” -ForegroundColor Cyan

# WN10-CC-000255: use of a hardware security device with Windows Hello for Business must be enabled

Write-Host "WN10-CC-000020: IPv6 source routing must be configured to highest protection.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$valueName = "DisableIpSourceRouting"
$valueData = 2
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-UR-000090

Write-Host "WN10-CC-000280: Remote Desktop Services must always prompt a client for passwords upon connection.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fPromptForPassword"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AU-000090: Removable Storage successes

# WN10-UR-000035: The Change the system time must only be assigned to Administrators and Local Service 

# WN10-AU-000110: Sensitive Privilege Use failures

# WN10-PK-000005: The DoD Root CA certificates must be installed in the Trusted Root Store.

Write-Host "WN10-CC-000210 - Enable Windows Defender SmartScreen for Explorer” -ForegroundColor Cyan
# Define registry path
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# === Default Configuration ===
# Applies to standard systems (and v1607 LTSB, per your note)
# Set EnableSmartScreen to 1
Set-ItemProperty -Path $registryPath -Name "EnableSmartScreen" -Value 1 -Type DWORD
# Set ShellSmartScreenLevel to "Block"
Set-ItemProperty -Path $registryPath -Name "ShellSmartScreenLevel" -Value "Block" -Type String
# === Optional: LTSB 1507-specific config ===
# Uncomment the following line **only if** targeting Windows 10 LTSB v1507
# Set-ItemProperty -Path $registryPath -Name "EnableSmartScreen" -Value 2 -Type DWORD


# "WN10-SO-000215: minimum session security requirement
# WN10-AU-000555: Configure audit policy for Logon/Logoff

# WN10-00-000175: Disable Secondary Logon service

Write-Host "WN10-CC-000180 - Disable Autoplay for non-volume devices” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$valueName = "NoAutoplayfornonVolume"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-CC-000070 - Enable Virtualization Based Security with Secure Boot

# WN10-SO-000075 - Configure legal notice before console logon” -ForegroundColor Cyan

# WN10-00-000145 - Configure Data Execution Prevention (DEP) to OptOut

Write-Host "WN10-CC-000350 - Disable unencrypted traffic for WinRM” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "AllowUnencryptedTraffic"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AU-000107 - Configure audit policy for Authorization Policy Change

Write-Host "WN10-CC-000155: Solicited Remote Assistance must not be allowed.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fAllowToGetHelp"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType


Write-Host "WN10-CC-000039: Run as different user must be removed from context menus.” -ForegroundColor Cyan
# Define the registry base paths
$paths = @(
    "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser"
)
$valueName = "SuppressionPolicy"
$valueData = 4096
$valueType = "DWORD"
foreach ($path in $paths) {
    # Create the registry key if it doesn't exist
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    # Set the registry value
    Set-ItemProperty -Path $path -Name $valueName -Value $valueData -Type $valueType
}

# WN10-AU-000560: Enable auditing for Logoff (Success and Failure)

Write-Host "WN10-SO-000030: Audit policy using subcategories must be enabled.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName = "SCENoApplyLegacyAuditPolicy"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-SO-000167: Restrict remote calls to the Security Account Manager (SAM) to Administrators

Write-Host "WN10-CC-000066: Include command line data in process creation events” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$valueName = "ProcessCreationIncludeCmdLine_Enabled"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AC-000030: The minimum password age must be configured to at least 1 day.

Write-Host "WN10-CC-000010: The display of slide shows on the lock screen must be disabled.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenSlideshow"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-CC-000060: Disable SMBv2 and SMBv3 protocols” -ForegroundColor Cyan
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

# WN10-SO-000095: The Smart Card removal option must be configured to Force Logoff or Lock Workstation.

Write-Host "WN10-CC-000315: Disable Windows Installer Always install with elevated privileges” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-CC-000040: Disable insecure logons to an SMB server” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$valueName = "AllowInsecureGuestAuth"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-UC-000015: Toast notifications to the lock screen must be turned off.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$valueName = "NoToastApplicationNotificationOnLockScreen"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AU-000115: The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.
# Write-Host "WN10-SO-000180: NTLM must be prevented from falling back to a Null session -ForegroundColor 
# WN10-UR-000025: Restrict the Allow log on locally user right to Administrators and Users groups
# WN10-EP-000310: Enable Kernel DMA Protection” -ForegroundColor Cyan

Write-Host "WN10-CC-000345: Disable Basic authentication for Windows Remote Management (WinRM)” # Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "AllowBasic"
$valueData = 0
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "WN10-CC-000235: Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge.” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "PreventOverrideAppRepUnknown"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-AU-000085: The system must be configured to audit Object Access - Removable Storage failures.
# WN10-AU-000010: The system must be configured to audit Account Logon - Credential Validation successes.
# WN10-SO-000190: Configure Kerberos encryption types to prevent DES and RC4”

Write-Host "WN10-CC-000250: Enable Windows Defender SmartScreen filter for Microsoft Edge” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "EnabledV9"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

# WN10-SO-000025: The built-in guest account must be renamed.

Write-Host “WN10-CC-000295: Prevent attachments from being downloaded from RSS feeds” -ForegroundColor Cyan
# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$valueName = "DisableEnclosureDownload"
$valueData = 1
$valueType = "DWORD"
# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "STIG remediation complete. A reboot is recommended for all settings to apply." -ForegroundColor Green
