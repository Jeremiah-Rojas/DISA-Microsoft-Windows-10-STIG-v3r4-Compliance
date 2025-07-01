# Run this script as Administrator

Write-Host " STIG WN10‑CC‑000185: Disable Autorun commands" -ForegroundColor Cyan
$reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
Set-ItemProperty -Path $reg -Name 'NoAutorun' -Value 1 -Type DWord

Write-Host “STIG WN10-CC-000145: Require password on resume " -ForegroundColor Cyan
# Configuration parameters
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$valueName = "DCSettingIndex"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-SO-000255: Deny UAC elevation for standard users” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "ConsentPromptBehaviorUser"
$valueData = 0
# Ensure the path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord -Force

Write-Host “STIG WN10-SO-000245: Enable Admin Approval Mode for built-in Administrator” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "FilterAdministratorToken"
$valueData = 1
# Ensure the registry key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-CC-000030: Prevent ICMP redirects from overriding OSPF routes” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$valueName = "EnableICMPRedirect"
$valueData = 0
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Error "Registry path not found: $regPath"
    exit 1
}
# Set the value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-CC-000327: Enable PowerShell transcription” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$valueName = "EnableTranscripting"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the EnableTranscripting value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-SO-000100: Require SMB Security Signature” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$valueName = "RequireSecuritySignature"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    Write-Error "Registry path not found: $regPath"
    exit 1
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host "STIG WN10-SO-000250: Disabling Autoplay for all drives..." -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#$valueName = "ConsentPromptBehaviorAdmin"
#$valueData = 2
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “WN10-CC-000205: Disable Windows Store (if not required)” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName = "AllowTelemetry"
$valueData = 0  # Set to 1 for Basic or 2 for Enhanced if required
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the AllowTelemetry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-SO-000120: Require SMB packet signing on SMB server” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
#$valueName = "RequireSecuritySignature"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    Write-Error "Registry path not found: $regPath"
#    exit 1
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-CC-000035: Ignore NetBIOS name release requests except from WINS servers” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
#$valueName = "NoNameReleaseOnDemand"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    Write-Error "Registry path not found: $regPath"
#    exit 1
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-CC-000310: Prevent users from changing Windows Installer options” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
#$valueName = "EnableUserControl"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host "STIG WN10-CC-000230: SmartScreen bypass disabled in Microsoft Edge." -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "PreventOverride"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host "STIG WN10-CC-000355: WinRM configured to NOT store RunAs credentials." -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
#$valueName = "DisableRunAs"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “Disable Full Telemetry (WN10‑CC‑000205)” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName = "AllowTelemetry"
# Set this to 0 (Security), 1 (Basic), or 2 (Enhanced) as needed
$valueData = 0
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the AllowTelemetry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10‑CC‑000090: Group Policy objects must be reprocessed even if they have not changed” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group #Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
#$valueName = "NoGPOListChanges"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

# MIGHT MESS WITH RDP OR TENABLE
#Write-Host “STIG WN10‑SO‑000230: configured to use FIPS-compliant algorithms for encryption, hashing, and signing” -ForegroundColor Cyan

Write-Host “Prevent Web‑publishing wizards download (WN10‑CC‑000105)” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoWebServices"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “Disable local drives access in RDS sessions (WN10‑CC‑000275)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
#$valueName = "fDisableCdm"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host "STIG WN10-CC-000190: Autoplay must be disabled for all drives" -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
#$valueName = "NoDriveTypeAutoRun"
#$valueData = 255  # 0xFF in decimal
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “Disable automatic restart sign-in (WN10-CC-000325)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#$valueName = "DisableAutomaticRestartSignOn"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “PKU2U auth off (WN10-SO-000185)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u"
#$valueName = "AllowOnlineID"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “Legal notice title dialog box configured (WN10-SO-000080)” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$captionName = "LegalNoticeCaption"
$captionValue = "DoD Notice and Consent Banner"

$textName = "LegalNoticeText"
$textValue = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests—not for your personal benefit or privacy.

Use of this IS indicates consent to monitoring and recording.
"@

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set LegalNoticeCaption and LegalNoticeText
New-ItemProperty -Path $regPath -Name $captionName -PropertyType String -Value $captionValue -Force
New-ItemProperty -Path $regPath -Name $textName -PropertyType String -Value $textValue -Force

#Write-Host “STIG WN10-CC-000165: Unauthenticated RPC clients must be restricted from connecting to the RPC server)” -ForegroundColor Cyan

#Write-Host “STIG WN10-CC-000150: The user must be prompted for a password on resume from sleep (plugged in))” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
#$valueName = "ACSettingIndex"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “Disable Microsoft Accounts optional (WN10-CC-000170)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
#$valueName = "MSAOptional"
#$valueData = 1  # 0x00000001 in decimal
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “Restrict anonymous enumeration of shares (WN10-SO-000150)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
#$valueName = "RestrictAnonymous"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-CC-000175: The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
#$valueName = "DisableInventory"
#$valueData = 1
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “WinRM client require encrypted (WN10-CC-000335)” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
#$valueName = "AllowUnencryptedTraffic"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-CC-000110: Printing over HTTP must be prevented)” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
$valueData = 1
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-CC-000052: Must be configured to prioritize ECC Curves with longer key lengths first.” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
#$valueName = "EccCurves"
#$valueData = @("NistP384", "NistP256")
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value as Multi-String (REG_MULTI_SZ)
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType MultiString -Value $valueData -Force

#Write-Host “STIG WN10-CC-000365: Must be configured to prevent Windows apps from being activated by voice while the system is locked.” -ForegroundColor Cyan
# Registry configuration for LetAppsActivateWithVoiceAboveLock
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
#$aboveLockName = "LetAppsActivateWithVoiceAboveLock"
#$voiceName = "LetAppsActivateWithVoice"
#$valueData = 2
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Check if LetAppsActivateWithVoice is already set to 2
#$voiceValue = Get-ItemProperty -Path $regPath -Name $voiceName -ErrorAction SilentlyContinue
#if ($voiceValue.$voiceName -eq 2) {
#    Write-Output "LetAppsActivateWithVoice is already set to 2 — LetAppsActivateWithVoiceAboveLock is not applicable (NA)."
#} else {
    # Set LetAppsActivateWithVoiceAboveLock to 2
#    New-ItemProperty -Path $regPath -Name $aboveLockName -PropertyType DWord -Value $valueData -Force
#}

#Write-Host “STIG WN10-CC-000370: The convenience PIN for Windows 10 must be disabled.” -ForegroundColor #Cyan
# Registry configuration
#$regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
#$valueName = "AllowDomainPINLogon"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

#Write-Host “STIG WN10-CC-000050: Hardened UNC paths must be defined to require mutual authentication and integrity.” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
# Define values to set
#$netlogonName = "\\*\NETLOGON"
#$sysvolName   = "\\*\SYSVOL"
#$valueData    = "RequireMutualAuthentication=1, RequireIntegrity=1"
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry values
#New-ItemProperty -Path $regPath -Name $netlogonName -PropertyType String -Value $valueData -Force
#New-ItemProperty -Path $regPath -Name $sysvolName -PropertyType String -Value $valueData -Force

#Write-Host “STIG WN10-CC-000360: The Windows Remote Management (WinRM) client must not use Digest authentication.” -ForegroundColor Cyan
# Registry configuration
#$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
#$valueName = "AllowDigest"
#$valueData = 0
# Ensure the registry path exists
#if (-not (Test-Path $regPath)) {
#    New-Item -Path $regPath -Force | Out-Null
#}
# Set the registry value
#New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

Write-Host “STIG WN10-CC-000197: Microsoft consumer experiences must be turned off.” -ForegroundColor Cyan
# Registry configuration
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
$valueData = 1  # 0x00000001
# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry value
New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $valueData -Force

# WN10-UR-000070
# WN10-AC-000020
# WN10-AU-000585
# WN10‑SO‑000005
# WN10‑CC‑000391
# WN10‑UR‑000030
# WN10-AU-000565
# WN10-00-000090
# WN10-AU-000050
# WN10‑AU‑000082
# WN10-PK-000010
# WN10-PK-000020

Write-Host "STIG remediation complete. A reboot is recommended for all settings to apply." -ForegroundColor Green
