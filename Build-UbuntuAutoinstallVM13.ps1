<#
.SYNOPSIS
    Ubuntu 24.04 Desktop Autoinstall ISO Builder & Multi-VM Deployment - FIXED VERSION

.DESCRIPTION
    Enterprise-grade automation script that:
    - Builds custom Ubuntu 24.04 Desktop ISO with autoinstall configuration
    - Creates multiple VMware VMs simultaneously with unique configurations
    - Provides real-time progress reporting and detailed logging
    - Generates secure password hashes for autoinstall user configuration

.PARAMETER SourceIsoPath
    Path to the original Ubuntu 24.04 Desktop ISO file

.PARAMETER OutputDirectory
    Directory where custom ISOs, VMs, and logs will be created

.PARAMETER VMNamePrefix
    Prefix for VM names (e.g., "ubuntu-vm" creates ubuntu-vm-01, ubuntu-vm-02, etc.)

.PARAMETER VMCount
    Number of VMs to create (default: 1, max: 50)

.PARAMETER VMStartNumber
    Starting number for VM naming (default: 1)

.PARAMETER VMCpuCount
    Number of CPU cores per VM (default: 2)

.PARAMETER VMMemoryMB
    Memory allocation per VM in MB (default: 4096)

.PARAMETER VMDiskSizeGB
    Virtual disk size per VM in GB (default: 40)

.PARAMETER VMNetworkType
    Network adapter type: nat, bridged, or hostonly (default: nat)

.PARAMETER RootPassword
    Root password (plain text, will be hashed automatically)

.PARAMETER UserPassword
    User password (plain text, will be hashed automatically)

.PARAMETER Timezone
    System timezone (default: Etc/UTC)

.PARAMETER GeneratePasswordHash
    Switch to generate a password hash only

.PARAMETER PlainTextPassword
    Plain text password to hash (use with -GeneratePasswordHash)

.PARAMETER MaxParallelVMs
    Maximum number of VMs to start simultaneously (default: 5)

.EXAMPLE
    .\Build-UbuntuAutoinstallVM.ps1 `
        -SourceIsoPath "C:\ISOs\ubuntu-24.04-desktop-amd64.iso" `
        -OutputDirectory "C:\VMBuild" `
        -VMNamePrefix "ubuntu-vm" `
        -VMCount 5 `
        -RootPassword "RootP@ss123" `
        -UserPassword "UserP@ss123"

.NOTES
    Author: Enterprise Automation Engineer
    Version: 5.0 - STABLE
    Requires: Windows 10/11, WSL2, Ubuntu-24.04 (WSL), VMware Workstation/Player
#>

[CmdletBinding(DefaultParameterSetName = 'BuildVM')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildVM')]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "Source ISO file not found: $_"
        }
        if ($_ -notmatch '\.(iso|ISO)$') {
            throw "File must be an ISO file: $_"
        }
        return $true
    })]
    [string]$SourceIsoPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'BuildVM')]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'BuildVM')]
    [ValidatePattern('^[a-zA-Z0-9_-]+$')]
    [string]$VMNamePrefix,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(1, 50)]
    [int]$VMCount = 1,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(1, 999)]
    [int]$VMStartNumber = 1,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(1, 32)]
    [int]$VMCpuCount = 2,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(1024, 131072)]
    [int]$VMMemoryMB = 4096,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(10, 2048)]
    [int]$VMDiskSizeGB = 40,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateSet('nat', 'bridged', 'hostonly')]
    [string]$VMNetworkType = 'nat',

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [string]$RootPassword,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [string]$UserPassword,

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [string]$Timezone = 'Etc/UTC',

    [Parameter(Mandatory = $false, ParameterSetName = 'BuildVM')]
    [ValidateRange(1, 10)]
    [int]$MaxParallelVMs = 5,

    [Parameter(Mandatory = $true, ParameterSetName = 'GenerateHash')]
    [switch]$GeneratePasswordHash,

    [Parameter(Mandatory = $false, ParameterSetName = 'GenerateHash')]
    [string]$PlainTextPassword
)

# Script-level variables
$ErrorActionPreference = 'Stop'
$script:LogFile = $null
$script:WorkingDir = $null
$script:VmrunPath = $null
$script:VMJobs = [System.Collections.ArrayList]::new()
$script:WSLDistribution = $null

#region Logging Functions

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor White }
    }
    
    if ($script:LogFile) {
        $mutex = New-Object System.Threading.Mutex($false, "Global\UbuntuAutoinstallLog")
        try {
            [void]$mutex.WaitOne()
            Add-Content -Path $script:LogFile -Value $logEntry
        }
        finally {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }
    }
}

#endregion

#region Password Hash Functions

function New-SecurePasswordHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [int]$Rounds = 5000
    )
    
    Write-Log "Generating SHA-512 password hash..." -Level INFO
    
    $saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    $salt = -join ((1..16) | ForEach-Object { $saltChars[(Get-Random -Maximum $saltChars.Length)] })
    
    $escapedPassword = $Password -replace '\\', '\\\\' -replace "'", "\\'"
    
    $pythonScript = @"
import crypt
password = '$escapedPassword'
salt = '\$6\$rounds=$Rounds\$$salt\$'
print(crypt.crypt(password, salt))
"@
    
    try {
        $pythonCheck = wsl -d $script:WSLDistribution bash -c "which python3 2>/dev/null"
        if ([string]::IsNullOrWhiteSpace($pythonCheck)) {
            Write-Log "Python3 not found in WSL, installing..." -Level WARNING
            wsl -d $script:WSLDistribution bash -c "sudo apt-get update -qq && sudo apt-get install -y -qq python3" | Out-Null
        }
        
        $hashResult = $pythonScript | wsl -d $script:WSLDistribution python3
        
        if ([string]::IsNullOrWhiteSpace($hashResult) -or $LASTEXITCODE -ne 0) {
            throw "Python hash generation failed"
        }
        
        Write-Log "Password hash generated successfully" -Level SUCCESS
        return $hashResult.Trim()
    }
    catch {
        Write-Log "Failed to generate password hash using Python, trying mkpasswd..." -Level WARNING
        
        try {
            wsl -d $script:WSLDistribution bash -c "command -v mkpasswd >/dev/null 2>&1 || sudo apt-get install -y -qq whois" | Out-Null
            
            $shellEscapedPassword = $Password -replace "'", "'\\''"
            
            $hashResult = wsl -d $script:WSLDistribution bash -c "echo '$shellEscapedPassword' | mkpasswd -m sha-512 -R $Rounds -s"
            
            if ([string]::IsNullOrWhiteSpace($hashResult)) {
                throw "mkpasswd hash generation failed"
            }
            
            Write-Log "Password hash generated successfully using mkpasswd" -Level SUCCESS
            return $hashResult.Trim()
        }
        catch {
            Write-Log "All hash generation methods failed: $_" -Level ERROR
            throw "Unable to generate password hash. Please ensure WSL has Python3 or whois package installed."
        }
    }
}

function Show-PasswordHashGenerator {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Password
    )
    
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "  Ubuntu Autoinstall Password Hash Generator" -ForegroundColor Cyan
    Write-Host "==================================================================`n" -ForegroundColor Cyan
    
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $securePassword = Read-Host "Enter password to hash" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        if ([string]::IsNullOrWhiteSpace($Password)) {
            Write-Host "Error: Password cannot be empty" -ForegroundColor Red
            return
        }
    }
    
    Write-Host "`nGenerating password hash..." -ForegroundColor Yellow
    
    try {
        $distributionsRaw = wsl --list --quiet
        $distributions = $distributionsRaw | ForEach-Object { 
            $_.Trim() -replace "`0", "" -replace "\s+", " " 
        } | Where-Object { $_ -ne "" }
        
        $script:WSLDistribution = $distributions | Where-Object { $_ -match 'Ubuntu' } | Select-Object -First 1
        
        if (-not $script:WSLDistribution) {
            throw "No Ubuntu distribution found in WSL"
        }
        
        $passwordHash = New-SecurePasswordHash -Password $Password -Rounds 5000
        
        Write-Host "`n------------------------------------------------------------------" -ForegroundColor Green
        Write-Host "Password Hash Generated Successfully!" -ForegroundColor Green
        Write-Host "------------------------------------------------------------------" -ForegroundColor Green
        
        Write-Host "`nPassword Hash (SHA-512):" -ForegroundColor Cyan
        Write-Host $passwordHash -ForegroundColor Yellow
        
        try {
            Set-Clipboard -Value $passwordHash
            Write-Host "`n✓ Password hash copied to clipboard!" -ForegroundColor Green
        }
        catch {
            Write-Host "`nNote: Could not copy to clipboard automatically" -ForegroundColor Yellow
        }
        
        Write-Host "`n------------------------------------------------------------------" -ForegroundColor Green
        Write-Host "Usage in autoinstall.yaml:" -ForegroundColor Cyan
        Write-Host "------------------------------------------------------------------" -ForegroundColor Green
        
        $yamlExample = @"

identity:
  username: vboxuser
  password: '$passwordHash'

user-data:
  users:
    - name: root
      passwd: '$passwordHash'

"@
        Write-Host $yamlExample -ForegroundColor White
        
    }
    catch {
        Write-Host "`nError generating password hash: $_" -ForegroundColor Red
        Write-Host "Please ensure WSL2 is properly configured with Ubuntu" -ForegroundColor Yellow
    }
}

#endregion

#region Prerequisite Functions

function Test-Prerequisites {
    param()
    
    Write-Log "Starting prerequisite validation..." -Level INFO
    Write-Progress -Activity "Validating Environment" -Status "Checking WSL2..." -PercentComplete 10
    
    try {
        $wslVersion = wsl --status 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "WSL is not installed or not configured properly"
        }
        Write-Log "WSL2 is available" -Level SUCCESS
    }
    catch {
        Write-Log "WSL2 validation failed: $_" -Level ERROR
        throw "Please install WSL2: wsl --install"
    }
    
    Write-Progress -Activity "Validating Environment" -Status "Checking Ubuntu distribution..." -PercentComplete 30
    
    $distributionsRaw = wsl --list --quiet
    $distributions = $distributionsRaw | ForEach-Object { 
        $_.Trim() -replace "`0", "" -replace "\s+", " " 
    } | Where-Object { $_ -ne "" }
    
    Write-Log "Detected WSL distributions: $($distributions -join ', ')" -Level INFO
    
    $ubuntuDist = $distributions | Where-Object { $_ -match 'Ubuntu' } | Select-Object -First 1
    
    if (-not $ubuntuDist) {
        Write-Log "No Ubuntu distribution found in WSL" -Level ERROR
        Write-Log "Available distributions: $($distributions -join ', ')" -Level INFO
        throw "Please install Ubuntu: wsl --install -d Ubuntu-24.04"
    }
    
    $script:WSLDistribution = $ubuntuDist.Trim()
    Write-Log "Ubuntu WSL distribution found: $script:WSLDistribution" -Level SUCCESS
    
    Write-Progress -Activity "Validating Environment" -Status "Configuring sudo..." -PercentComplete 40
    
    Write-Host "`n------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  WSL Sudo Configuration" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------`n" -ForegroundColor Yellow
    
    $sudoConfigured = wsl -d $script:WSLDistribution bash -c "sudo -n true 2>&1"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "This script requires sudo access in WSL." -ForegroundColor White
        Write-Host "You will be prompted ONCE for your password." -ForegroundColor Cyan
        Write-Host "After this, sudo will not ask for password again during this session." -ForegroundColor Cyan
        Write-Host ""
        
        $username = wsl -d $script:WSLDistribution bash -c "whoami"
        $username = $username.Trim()
        
        wsl -d $script:WSLDistribution bash -c "sudo -v"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to authenticate with sudo"
        }
        
        $sudoersContent = @"
# Temporary config for VM deployment script
Defaults timestamp_timeout=180
$username ALL=(ALL) NOPASSWD: /bin/mount, /bin/umount, /usr/bin/apt-get
"@
        
        wsl -d $script:WSLDistribution bash -c "echo '$sudoersContent' | sudo tee /etc/sudoers.d/vm_deploy_temp > /dev/null"
        wsl -d $script:WSLDistribution bash -c "sudo chmod 440 /etc/sudoers.d/vm_deploy_temp"
        
        Write-Log "Sudo configured for passwordless operation" -Level SUCCESS
        Write-Host ""
        Write-Host "Note: Passwordless sudo is configured for mount/umount/apt-get only." -ForegroundColor Green
        Write-Host "You can remove it after the script with:" -ForegroundColor Yellow
        Write-Host "  wsl -d $script:WSLDistribution sudo rm /etc/sudoers.d/vm_deploy_temp" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Log "Sudo access already available" -Level SUCCESS
    }
    
    Write-Progress -Activity "Validating Environment" -Status "Installing Linux packages..." -PercentComplete 50
    
    Write-Log "Installing required Linux packages..." -Level INFO
    $packages = @(
        'xorriso',
        'isolinux',
        'cloud-init',
        'rsync',
        'grub-pc-bin',
        'grub-efi-amd64-bin',
        'python3',
        'whois',
        'syslinux-utils'
    )
    
    $packageList = $packages -join ' '
    
    try {
        Write-Log "Running apt-get update..." -Level INFO
        wsl -d $script:WSLDistribution bash -c "sudo apt-get update -qq"
        
        Write-Log "Installing packages: $packageList" -Level INFO
        wsl -d $script:WSLDistribution bash -c "sudo apt-get install -y -qq $packageList"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Package installation failed"
        }
        Write-Log "Linux packages installed successfully" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to install Linux packages: $_" -Level ERROR
        throw
    }
    
    Write-Progress -Activity "Validating Environment" -Status "Checking VMware..." -PercentComplete 70
    
    $vmwarePaths = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Player\vmrun.exe",
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe"
    )
    
    $vmrunPath = $vmwarePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    
    if (-not $vmrunPath) {
        Write-Log "VMware not found" -Level ERROR
        throw "Please install VMware Workstation or Player"
    }
    
    $script:VmrunPath = $vmrunPath
    Write-Log "VMware found at: $vmrunPath" -Level SUCCESS
    
    Write-Progress -Activity "Validating Environment" -Status "Complete" -PercentComplete 100
    Write-Log "All prerequisites validated successfully" -Level SUCCESS
    
    Start-Sleep -Seconds 1
    Write-Progress -Activity "Validating Environment" -Completed
}

#endregion

#region ISO Building Functions

function Initialize-WorkingDirectory {
    param()
    
    Write-Log "Initializing working directory..." -Level INFO
    
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputDirectory" -Level INFO
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:WorkingDir = Join-Path $OutputDirectory "build_$timestamp"
    New-Item -Path $script:WorkingDir -ItemType Directory -Force | Out-Null
    
    $script:LogFile = Join-Path $script:WorkingDir "build.log"
    Write-Log "Working directory: $script:WorkingDir" -Level INFO
}

function ConvertTo-WslPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WindowsPath
    )
    
    $wslPath = wsl -d $script:WSLDistribution wslpath -u "$WindowsPath"
    return $wslPath.Trim()
}

function New-AutoinstallConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$Hostname,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPasswordHash,
        
        [Parameter(Mandatory = $true)]
        [string]$RootPasswordHash,
        
        [Parameter(Mandatory = $true)]
        [string]$Timezone
    )
    
    $autoinstallYaml = @"
#cloud-config
autoinstall:
  version: 1
  apt:
    fallback: offline-install
  locale: en_US
  keyboard:
    layout: us
  identity:
    realname: '$Username'
    username: '$Username'
    password: '$UserPasswordHash'
    hostname: '$Hostname'
  shutdown: reboot
  storage:
    layout:
      name: direct
    swap:
      size: 0
  user-data:
    users:
      - name: root
        primary_group: root
        groups: sudo
        lock-passwd: false
        passwd: '$RootPasswordHash'
        uid: 0
    timezone: $Timezone
    ntp:
        enabled: true
"@
    
    return $autoinstallYaml
}

function Prepare-AutoinstallFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$Hostname,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPasswordHash,
        
        [Parameter(Mandatory = $true)]
        [string]$RootPasswordHash,
        
        [Parameter(Mandatory = $true)]
        [string]$Timezone
    )
    
    Write-Log "Preparing autoinstall files for $VMName..." -Level INFO
    
    $vmWorkDir = Join-Path $script:WorkingDir $VMName
    New-Item -Path $vmWorkDir -ItemType Directory -Force | Out-Null
    
    $nocloudDir = Join-Path $vmWorkDir "nocloud"
    New-Item -Path $nocloudDir -ItemType Directory -Force | Out-Null
    
    $autoinstallContent = New-AutoinstallConfig `
        -VMName $VMName `
        -Username $Username `
        -Hostname $Hostname `
        -UserPasswordHash $UserPasswordHash `
        -RootPasswordHash $RootPasswordHash `
        -Timezone $Timezone
    
    $userData = Join-Path $nocloudDir "user-data"
    Set-Content -Path $userData -Value $autoinstallContent -Force
    Write-Log "Created user-data for $VMName" -Level INFO
    
    $metaData = Join-Path $nocloudDir "meta-data"
    $metaDataContent = @"
instance-id: ubuntu-autoinstall-$VMName-$(Get-Date -Format 'yyyyMMddHHmmss')
local-hostname: $Hostname
"@
    Set-Content -Path $metaData -Value $metaDataContent -Force
    Write-Log "Created meta-data for $VMName" -Level INFO
    
    return $nocloudDir
}

function Extract-UbuntuISO {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IsoPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    if (Test-Path -LiteralPath $ExtractPath) {
        Write-Log "ISO already extracted, skipping..." -Level INFO
        return
    }
    
    Write-Log "Extracting Ubuntu ISO..." -Level INFO
    Write-Progress -Activity "Extracting ISO" -Status "Preparing..." -PercentComplete 0
    
    $wslIsoPath = ConvertTo-WslPath -WindowsPath $IsoPath
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    Write-Log "ISO Path: $wslIsoPath" -Level INFO
    Write-Log "Extract Path: $wslExtractPath" -Level INFO
    
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    
    try {
        Write-Log "Checking for existing mounts..." -Level INFO
        
        wsl -d $script:WSLDistribution bash -c "sudo umount /tmp/iso_mount 2>/dev/null || true"
        wsl -d $script:WSLDistribution bash -c "rmdir /tmp/iso_mount 2>/dev/null || true"
        
        Write-Progress -Activity "Extracting ISO" -Status "Creating mount point..." -PercentComplete 10
        wsl -d $script:WSLDistribution bash -c "mkdir -p /tmp/iso_mount"
        
        Write-Progress -Activity "Extracting ISO" -Status "Mounting ISO..." -PercentComplete 20
        Write-Log "Mounting ISO..." -Level INFO
        wsl -d $script:WSLDistribution bash -c "sudo mount -o loop '$wslIsoPath' /tmp/iso_mount"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to mount ISO"
        }
        
        $fileCount = wsl -d $script:WSLDistribution bash -c "ls /tmp/iso_mount 2>/dev/null | wc -l"
        
        if ([int]$fileCount -eq 0) {
            throw "ISO mounted but appears empty"
        }
        
        Write-Log "ISO mounted successfully, found $fileCount items" -Level SUCCESS
        
        Write-Progress -Activity "Extracting ISO" -Status "Copying all ISO contents (this will take several minutes)..." -PercentComplete 30
        Write-Log "Copying all ISO contents..." -Level INFO
        
        wsl -d $script:WSLDistribution bash -c "rsync -a --info=progress2 /tmp/iso_mount/ '$wslExtractPath/'"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy ISO contents"
        }
        
        Write-Log "All files copied successfully" -Level SUCCESS
        
        Write-Progress -Activity "Extracting ISO" -Status "Setting permissions..." -PercentComplete 90
        Write-Log "Making extracted files writable..." -Level INFO
        wsl -d $script:WSLDistribution bash -c "chmod -R u+w '$wslExtractPath' 2>/dev/null || true"
        
        Write-Progress -Activity "Extracting ISO" -Status "Cleaning up..." -PercentComplete 95
        Write-Log "Unmounting ISO..." -Level INFO
        wsl -d $script:WSLDistribution bash -c "sudo umount /tmp/iso_mount"
        
        wsl -d $script:WSLDistribution bash -c "rmdir /tmp/iso_mount"
        
        Write-Progress -Activity "Extracting ISO" -Status "Complete" -PercentComplete 100
        Write-Log "ISO extracted successfully" -Level SUCCESS
        
        Start-Sleep -Seconds 1
        Write-Progress -Activity "Extracting ISO" -Completed
    }
    catch {
        Write-Log "Extraction error, cleaning up..." -Level WARNING
        
        for ($i = 1; $i -le 3; $i++) {
            Write-Log "Cleanup attempt $i..." -Level INFO
            
            wsl -d $script:WSLDistribution bash -c "sudo umount -f /tmp/iso_mount 2>/dev/null || true"
            wsl -d $script:WSLDistribution bash -c "sudo umount -l /tmp/iso_mount 2>/dev/null || true"
            
            Start-Sleep -Seconds 1
            
            $mountCheck = wsl -d $script:WSLDistribution bash -c "mount | grep /tmp/iso_mount || echo 'not_mounted'"
            if ($mountCheck -match 'not_mounted') {
                Write-Log "Successfully unmounted" -Level SUCCESS
                break
            }
        }
        
        wsl -d $script:WSLDistribution bash -c "rmdir /tmp/iso_mount 2>/dev/null || true"
        
        Write-Log "Failed to extract ISO: $_" -Level ERROR
        throw
    }
}

function Update-GrubConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    Write-Log "Updating GRUB configuration (VirtualBox-compatible)..." -Level INFO
    
    # VirtualBox-compatible GRUB config - uses /cdrom/ not /cdrom/nocloud/
    $grubConfig = @'
set timeout=4
loadfont unicode
set menu_color_normal=white/black
set menu_color_highlight=black/light-gray
menuentry "Try or Install Ubuntu" {
	set gfxpayload=keep
	linux	/casper/vmlinuz autoinstall ds=nocloud\;s=/cdrom/ --- quiet splash noprompt noshell automatic-ubiquity debian-installer/locale=en_US keyboard-configuration/layoutcode=us languagechooser/language-name=English localechooser/supported-locales=en_US.UTF-8 countrychooser/shortlist=IN --
	initrd	/casper/initrd
}
menuentry "Ubuntu (safe graphics)" {
	set gfxpayload=keep
	linux	/casper/vmlinuz autoinstall ds=nocloud\;s=/cdrom/ --- quiet splash noprompt noshell automatic-ubiquity debian-installer/locale=en_US keyboard-configuration/layoutcode=us languagechooser/language-name=English localechooser/supported-locales=en_US.UTF-8 countrychooser/shortlist=IN --
	initrd	/casper/initrd
}
grub_platform
if [ "$grub_platform" = "efi" ]; then
menuentry 'Boot from next volume' {
	exit 1
}
menuentry 'UEFI Firmware Settings' {
	fwsetup
}
else
menuentry 'Test memory' {
	linux16 /boot/memtest86+x64.bin
}
fi
'@
    
    $grubCfgPath = "$wslExtractPath/boot/grub/grub.cfg"
    $fileCheck = wsl -d $script:WSLDistribution bash -c "test -f '$grubCfgPath' && echo exists || echo missing"
    
    if ($fileCheck.Trim() -eq 'exists') {
        wsl -d $script:WSLDistribution bash -c "cp '$grubCfgPath' '$grubCfgPath.backup' 2>/dev/null || true"
        Write-Log "Backed up original boot/grub/grub.cfg" -Level INFO
        
        $tempGrubFileWSL = "/tmp/grub_config_$([guid]::NewGuid().ToString('N')).cfg"
        
        $grubConfigBytes = [System.Text.Encoding]::UTF8.GetBytes($grubConfig)
        $grubConfigBase64 = [Convert]::ToBase64String($grubConfigBytes)
        
        wsl -d $script:WSLDistribution bash -c "echo '$grubConfigBase64' | base64 -d > '$tempGrubFileWSL'"
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to create temporary grub config" -Level ERROR
            throw "Failed to write GRUB configuration"
        }
        
        wsl -d $script:WSLDistribution bash -c "cp '$tempGrubFileWSL' '$grubCfgPath'"
        
        if ($LASTEXITCODE -ne 0) {
            wsl -d $script:WSLDistribution bash -c "rm -f '$tempGrubFileWSL'"
            Write-Log "Failed to copy grub config" -Level ERROR
            throw "Failed to write GRUB configuration"
        }
        
        wsl -d $script:WSLDistribution bash -c "chmod 644 '$grubCfgPath'"
        wsl -d $script:WSLDistribution bash -c "rm -f '$tempGrubFileWSL'"
        
        Write-Log "Updated boot/grub/grub.cfg" -Level SUCCESS
    }
    else {
        Write-Log "boot/grub/grub.cfg not found" -Level WARNING
    }
    
    $loopbackCfgPath = "$wslExtractPath/boot/grub/loopback.cfg"
    $fileCheck = wsl -d $script:WSLDistribution bash -c "test -f '$loopbackCfgPath' && echo exists || echo missing"
    
    if ($fileCheck.Trim() -eq 'exists') {
        wsl -d $script:WSLDistribution bash -c "cp '$loopbackCfgPath' '$loopbackCfgPath.backup' 2>/dev/null || true"
        Write-Log "Backed up original boot/grub/loopback.cfg" -Level INFO
        
        $tempLoopbackFileWSL = "/tmp/loopback_config_$([guid]::NewGuid().ToString('N')).cfg"
        
        wsl -d $script:WSLDistribution bash -c "echo '$grubConfigBase64' | base64 -d > '$tempLoopbackFileWSL'"
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to create temporary loopback config" -Level ERROR
        }
        else {
            wsl -d $script:WSLDistribution bash -c "cp '$tempLoopbackFileWSL' '$loopbackCfgPath'"
            
            if ($LASTEXITCODE -ne 0) {
                wsl -d $script:WSLDistribution bash -c "rm -f '$tempLoopbackFileWSL'"
                Write-Log "Failed to copy loopback config" -Level ERROR
            }
            else {
                wsl -d $script:WSLDistribution bash -c "chmod 644 '$loopbackCfgPath'"
                wsl -d $script:WSLDistribution bash -c "rm -f '$tempLoopbackFileWSL'"
                Write-Log "Updated boot/grub/loopback.cfg" -Level SUCCESS
            }
        }
    }
    
    Write-Log "GRUB configuration updated (VirtualBox-compatible)" -Level SUCCESS
}

function Copy-NocloudFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NocloudSource,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    $wslNocloudSource = ConvertTo-WslPath -WindowsPath $NocloudSource
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    Write-Log "Copying NoCloud files to ISO root (VirtualBox-compatible)..." -Level INFO
    
    # VirtualBox puts files in /cdrom/ root, not /cdrom/nocloud/
    # Copy user-data and meta-data to ISO root
    wsl -d $script:WSLDistribution bash -c "cp '$wslNocloudSource/user-data' '$wslExtractPath/'"
    wsl -d $script:WSLDistribution bash -c "cp '$wslNocloudSource/meta-data' '$wslExtractPath/'"
    wsl -d $script:WSLDistribution bash -c "chmod 644 '$wslExtractPath/user-data'"
    wsl -d $script:WSLDistribution bash -c "chmod 644 '$wslExtractPath/meta-data'"
    
    Write-Log "NoCloud files copied to ISO root" -Level SUCCESS
}

function Copy-NocloudFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NocloudSource,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    $wslNocloudSource = ConvertTo-WslPath -WindowsPath $NocloudSource
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    Write-Log "Copying NoCloud files..." -Level INFO
    
    wsl -d $script:WSLDistribution bash -c "mkdir -p '$wslExtractPath/nocloud'"
    wsl -d $script:WSLDistribution bash -c "cp '$wslNocloudSource/user-data' '$wslExtractPath/nocloud/'"
    wsl -d $script:WSLDistribution bash -c "cp '$wslNocloudSource/meta-data' '$wslExtractPath/nocloud/'"
    wsl -d $script:WSLDistribution bash -c "chmod 644 '$wslExtractPath/nocloud/user-data'"
    wsl -d $script:WSLDistribution bash -c "chmod 644 '$wslExtractPath/nocloud/meta-data'"
    
    Write-Log "NoCloud files copied" -Level SUCCESS
}

#ISO creation worked without issue onlyh need to fix the boot problem
#this is only for UEFI and BIOS finetuned
function Build-CustomISO {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputIsoPath,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    Write-Log "Building bootable ISO for $VMName (preserving original boot structure)..." -Level INFO
    Write-Progress -Activity "Building ISO" -Status "Preparing..." -PercentComplete 0
    
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    $wslOutputIsoPath = ConvertTo-WslPath -WindowsPath $OutputIsoPath
    
    try {
        Write-Progress -Activity "Building ISO" -Status "Analyzing boot structure..." -PercentComplete 10
        
        Write-Log "=== BOOT STRUCTURE ANALYSIS ===" -Level INFO
        
        # Detect all boot components
        $bootx64 = wsl -d $script:WSLDistribution bash -c "test -f '$wslExtractPath/EFI/boot/bootx64.efi' && echo exists || echo missing"
        $hasUefiBoot = $bootx64.Trim() -eq 'exists'
        
        $isolinuxBin = wsl -d $script:WSLDistribution bash -c "test -f '$wslExtractPath/isolinux/isolinux.bin' && echo exists || echo missing"
        $hasBiosBoot = $isolinuxBin.Trim() -eq 'exists'
        
        Write-Log "UEFI boot files: $hasUefiBoot" -Level INFO
        Write-Log "BIOS boot files: $hasBiosBoot" -Level INFO
        
        # Add BIOS boot if missing (for hybrid support)
        if (-not $hasBiosBoot) {
            Write-Log "Adding BIOS boot support..." -Level INFO
            
            wsl -d $script:WSLDistribution bash -c "mkdir -p '$wslExtractPath/isolinux'"
            
            # Find and copy isolinux.bin
            $isolinuxSource = wsl -d $script:WSLDistribution bash -c "find /usr/lib /usr/share -name 'isolinux.bin' 2>/dev/null | head -1"
            $isolinuxSource = $isolinuxSource.Trim()
            
            if (-not [string]::IsNullOrWhiteSpace($isolinuxSource)) {
                wsl -d $script:WSLDistribution bash -c "cp '$isolinuxSource' '$wslExtractPath/isolinux/isolinux.bin'"
                
                # Copy required .c32 modules
                wsl -d $script:WSLDistribution bash -c "find /usr/lib/syslinux/modules/bios -name '*.c32' -exec cp {} '$wslExtractPath/isolinux/' \; 2>/dev/null || true"
                
                # Create isolinux.cfg
                $isolinuxCfg = @'
DEFAULT vesamenu.c32
TIMEOUT 40
PROMPT 0
MENU TITLE Ubuntu Autoinstall

LABEL install
  MENU LABEL Try or Install Ubuntu
  KERNEL /casper/vmlinuz
  APPEND initrd=/casper/initrd autoinstall ds=nocloud;s=/cdrom/ --- quiet splash noprompt noshell automatic-ubiquity debian-installer/locale=en_US keyboard-configuration/layoutcode=us languagechooser/language-name=English localechooser/supported-locales=en_US.UTF-8 countrychooser/shortlist=IN --
'@
                
                $isolinuxCfgBytes = [System.Text.Encoding]::UTF8.GetBytes($isolinuxCfg)
                $isolinuxCfgBase64 = [Convert]::ToBase64String($isolinuxCfgBytes)
                wsl -d $script:WSLDistribution bash -c "echo '$isolinuxCfgBase64' | base64 -d > '$wslExtractPath/isolinux/isolinux.cfg'"
                
                # Verify it was created
                $check = wsl -d $script:WSLDistribution bash -c "test -f '$wslExtractPath/isolinux/isolinux.bin' && echo exists || echo missing"
                if ($check.Trim() -eq 'exists') {
                    $hasBiosBoot = $true
                    Write-Log "BIOS boot files added successfully" -Level SUCCESS
                }
            }
        }
        
        Write-Log "=== END ANALYSIS ===" -Level INFO
        
        if (-not $hasUefiBoot -and -not $hasBiosBoot) {
            throw "No boot files available - cannot create bootable ISO"
        }
        
        Write-Progress -Activity "Building ISO" -Status "Building ISO with xorriso..." -PercentComplete 30
        
        $startTime = Get-Date
        
        # THE CRITICAL FIX: Use xorriso with proper boot preservation
        # This is the EXACT method that creates bootable Ubuntu ISOs
        
        if ($hasBiosBoot -and $hasUefiBoot) {
            Write-Log "Building HYBRID BIOS+UEFI bootable ISO" -Level SUCCESS
            
            # Find isohdpfx.bin (MBR template)
            $isohdpfx = wsl -d $script:WSLDistribution bash -c "find /usr/lib -name 'isohdpfx.bin' 2>/dev/null | head -1"
            $isohdpfx = $isohdpfx.Trim()
            
            if ([string]::IsNullOrWhiteSpace($isohdpfx)) {
                Write-Log "isohdpfx.bin not found - using alternative method" -Level WARNING
                
                # Method without isohdpfx.bin
                $xorrisoCmd = @"
cd '$wslExtractPath' && \
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid 'Ubuntu-Autoinstall' \
  -output '$wslOutputIsoPath' \
  -eltorito-boot isolinux/isolinux.bin \
  -eltorito-catalog isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -eltorito-alt-boot \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -rational-rock \
  -joliet \
  -joliet-long \
  . 2>&1
"@
            } else {
                Write-Log "Using isohdpfx.bin: $isohdpfx" -Level INFO
                
                # Full hybrid boot with MBR
                $xorrisoCmd = @"
cd '$wslExtractPath' && \
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid 'Ubuntu-Autoinstall' \
  -output '$wslOutputIsoPath' \
  -eltorito-boot isolinux/isolinux.bin \
  -eltorito-catalog isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -eltorito-alt-boot \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -isohybrid-mbr '$isohdpfx' \
  -partition_offset 16 \
  -rational-rock \
  -joliet \
  -joliet-long \
  . 2>&1
"@
            }
        }
        elseif ($hasUefiBoot) {
            Write-Log "Building UEFI-only bootable ISO" -Level INFO
            
            $xorrisoCmd = @"
cd '$wslExtractPath' && \
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid 'Ubuntu-Autoinstall' \
  -output '$wslOutputIsoPath' \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -partition_offset 16 \
  -rational-rock \
  -joliet \
  -joliet-long \
  . 2>&1
"@
        }
        else {
            Write-Log "Building BIOS-only bootable ISO" -Level INFO
            
            $xorrisoCmd = @"
cd '$wslExtractPath' && \
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid 'Ubuntu-Autoinstall' \
  -output '$wslOutputIsoPath' \
  -eltorito-boot isolinux/isolinux.bin \
  -eltorito-catalog isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -rational-rock \
  -joliet \
  -joliet-long \
  . 2>&1
"@
        }
        
        Write-Log "Executing xorriso (this will take 3-8 minutes)..." -Level INFO
        Write-Log "Command:" -Level INFO
        foreach ($line in ($xorrisoCmd -split "`n")) {
            Write-Host "  $line" -ForegroundColor Gray
        }
        
        $output = wsl -d $script:WSLDistribution bash -c $xorrisoCmd
        
        $buildTime = ((Get-Date) - $startTime).TotalSeconds
        $xorrisoExitCode = $LASTEXITCODE
        
        Write-Log "xorriso completed in $([math]::Round($buildTime, 2))s (exit code: $xorrisoExitCode)" -Level INFO
        
        # Show output
        if ($output) {
            Write-Log "xorriso output:" -Level INFO
            $outputLines = $output -split "`n"
            $lineCount = [Math]::Min(20, $outputLines.Count)
            for ($i = 0; $i -lt $lineCount; $i++) {
                $line = $outputLines[$i]
                if ($line -match 'warning|error' -and $line -notmatch 'NOTE') {
                    Write-Host "  $line" -ForegroundColor Yellow
                } else {
                    Write-Host "  $line" -ForegroundColor Gray
                }
            }
            if ($outputLines.Count -gt 20) {
                Write-Host "  ... ($($outputLines.Count - 20) more lines)" -ForegroundColor Gray
            }
        }
        
        # Verify ISO
        if (-not (Test-Path -LiteralPath $OutputIsoPath)) {
            Write-Log "ERROR: ISO file was not created" -Level ERROR
            if ($output) {
                Write-Log "Full xorriso output:" -Level ERROR
                foreach ($line in ($output -split "`n")) {
                    Write-Host "  $line" -ForegroundColor Red
                }
            }
            throw "ISO file was not created (exit code: $xorrisoExitCode)"
        }
        
        $isoFileInfo = Get-Item -LiteralPath $OutputIsoPath
        if ($isoFileInfo.Length -eq 0) {
            throw "ISO file is empty (0 bytes)"
        }
        
        $isoSize = $isoFileInfo.Length / 1GB
        
        # Verify bootability by checking for boot signatures
        Write-Log "Verifying boot structure..." -Level INFO
        
        # Check if ISO has boot signatures
        $bootCheck = wsl -d $script:WSLDistribution bash -c "xorriso -indev '$wslOutputIsoPath' -report_el_torito as_mkisofs 2>&1 | head -20"
        
        if ($bootCheck) {
            Write-Log "Boot structure verification:" -Level INFO
            foreach ($line in ($bootCheck -split "`n")) {
                if ($line -match '-e |--eltorito|boot') {
                    Write-Host "  $line" -ForegroundColor Cyan
                }
            }
        }
        
        Write-Progress -Activity "Building ISO" -Status "Complete" -PercentComplete 100
        Write-Log "✓ Bootable ISO created: $('{0:N2}' -f $isoSize) GB in $([math]::Round($buildTime, 2))s" -Level SUCCESS
        
        if ($hasBiosBoot -and $hasUefiBoot) {
            Write-Log "✓ ISO supports HYBRID boot (BIOS + UEFI)" -Level SUCCESS
        } elseif ($hasUefiBoot) {
            Write-Log "✓ ISO supports UEFI boot" -Level SUCCESS
        } elseif ($hasBiosBoot) {
            Write-Log "✓ ISO supports BIOS boot" -Level SUCCESS
        }
        
        Write-Progress -Activity "Building ISO" -Completed
        
    }
    catch {
        Write-Log "Failed to build ISO: $_" -Level ERROR
        throw
    }
    finally {
        Clear-IsoMounts
    }
}
function Clear-IsoMounts {
    param()
    
    Write-Log "Cleaning up ISO mounts..." -Level INFO
    
    wsl -d $script:WSLDistribution bash -c "sudo umount -f /tmp/iso_mount 2>/dev/null || true"
    wsl -d $script:WSLDistribution bash -c "sudo umount -l /tmp/iso_mount 2>/dev/null || true"
    wsl -d $script:WSLDistribution bash -c "sudo umount /tmp/iso_mount 2>/dev/null || true"
    wsl -d $script:WSLDistribution bash -c "rmdir /tmp/iso_mount 2>/dev/null || true"
    
    $mountCheck = wsl -d $script:WSLDistribution bash -c "mount | grep /tmp/iso_mount || echo 'clean'"
    
    if ($mountCheck -match 'clean') {
        Write-Log "Mount cleanup successful" -Level SUCCESS
    }
    else {
        Write-Log "Warning: Mount may still exist" -Level WARNING
    }
}

#endregion

#region VMware Functions

function Create-VMwareVM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$IsoPath,
        
        [Parameter(Mandatory = $true)]
        [int]$CpuCount,
        
        [Parameter(Mandatory = $true)]
        [int]$MemoryMB,
        
        [Parameter(Mandatory = $true)]
        [int]$DiskSizeGB,
        
        [Parameter(Mandatory = $true)]
        [string]$NetworkType
    )
    
    Write-Log "Creating VMware VM: $Name..." -Level INFO
    
    $vmDir = Join-Path $OutputDirectory $Name
    if (Test-Path -LiteralPath $vmDir) {
        Remove-Item -LiteralPath $vmDir -Recurse -Force
    }
    New-Item -Path $vmDir -ItemType Directory -Force | Out-Null
    
    $vmxPath = Join-Path $vmDir "$Name.vmx"
    $vmdkPath = Join-Path $vmDir "$Name.vmdk"
    
    $vmxContent = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "$Name"
guestOS = "ubuntu-64"
firmware = "efi"

numvcpus = "$CpuCount"
cpuid.coresPerSocket = "1"
memsize = "$MemoryMB"

scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "$Name.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"

ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "$IsoPath"
ide1:0.startConnected = "TRUE"

ethernet0.present = "TRUE"
ethernet0.connectionType = "$NetworkType"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"
ethernet0.startConnected = "TRUE"

usb.present = "TRUE"
ehci.present = "TRUE"
sound.present = "TRUE"
sound.fileName = "-1"
sound.autodetect = "TRUE"
svga.autodetect = "TRUE"
mks.enable3d = "TRUE"

pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
floppy0.present = "FALSE"
"@
    
    Set-Content -Path $vmxPath -Value $vmxContent -Force
    
    $vmwareDir = Split-Path -Parent $script:VmrunPath
    $vdiskManager = Join-Path $vmwareDir "vmware-vdiskmanager.exe"
    
    if (Test-Path -LiteralPath $vdiskManager) {
        & $vdiskManager -c -s ${DiskSizeGB}GB -a lsilogic -t 0 $vmdkPath | Out-Null
    }
    else {
        $vmdkDescriptor = @"
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicSparse"

RW $($DiskSizeGB * 2097152) SPARSE "$Name.vmdk"

ddb.virtualHWVersion = "21"
ddb.geometry.cylinders = "$(($DiskSizeGB * 130))"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.adapterType = "lsilogic"
"@
        Set-Content -Path $vmdkPath -Value $vmdkDescriptor -Force
    }
    
    Write-Log "VM created: $Name" -Level SUCCESS
    return $vmxPath
}

function Start-VMwareVM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    Write-Log "Starting VM: $VMName..." -Level INFO
    
    try {
        & $script:VmrunPath -T ws start $VmxPath nogui 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "VM started: $VMName" -Level SUCCESS
        }
        else {
            throw "Failed to start VM (exit code: $LASTEXITCODE)"
        }
    }
    catch {
        Write-Log "Failed to start VM: $_" -Level ERROR
        throw
    }
}

#endregion

#region Multi-VM Orchestration

function Build-VMConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$VMConfig,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseExtractPath
    )
    
    $vmName = $VMConfig.Name
    
    try {
        Write-Log "[$vmName] Building configuration..." -Level INFO
        
        $vmExtractPath = Join-Path $script:WorkingDir "$vmName`_iso"
        
        Write-Log "[$vmName] Copying ISO workspace..." -Level INFO
        
        $wslBase = ConvertTo-WslPath -WindowsPath $BaseExtractPath
        $wslVm = ConvertTo-WslPath -WindowsPath $vmExtractPath
        
        $startTime = Get-Date
        
        # SIMPLE, RELIABLE COPY - no hard links needed
        wsl -d $script:WSLDistribution bash -c "rsync -a '$wslBase/' '$wslVm/'"
        
        $copyTime = ((Get-Date) - $startTime).TotalSeconds
        Write-Log "[$vmName] ISO workspace created in $([math]::Round($copyTime, 2)) seconds" -Level SUCCESS
        
        $nocloudDir = Prepare-AutoinstallFiles `
            -VMName $vmName `
            -Username $VMConfig.Username `
            -Hostname $VMConfig.Hostname `
            -UserPasswordHash $VMConfig.UserPasswordHash `
            -RootPasswordHash $VMConfig.RootPasswordHash `
            -Timezone $VMConfig.Timezone
        
        Copy-NocloudFiles -NocloudSource $nocloudDir -ExtractPath $vmExtractPath
        
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $customIsoPath = Join-Path $script:WorkingDir "$vmName-autoinstall-$timestamp.iso"
        
        Build-CustomISO -ExtractPath $vmExtractPath -OutputIsoPath $customIsoPath -VMName $vmName
        
        $vmxPath = Create-VMwareVM `
            -Name $vmName `
            -IsoPath $customIsoPath `
            -CpuCount $VMConfig.CpuCount `
            -MemoryMB $VMConfig.MemoryMB `
            -DiskSizeGB $VMConfig.DiskSizeGB `
            -NetworkType $VMConfig.NetworkType
        
        Write-Log "[$vmName] Configuration complete" -Level SUCCESS
        
        return @{
            VMName = $vmName
            VmxPath = $vmxPath
            Success = $true
        }
    }
    catch {
        Write-Log "[$vmName] Configuration failed: $_" -Level ERROR
        return @{
            VMName = $vmName
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-ParallelVMDeployment {
    param(
        [Parameter(Mandatory = $true)]
        [array]$VMConfigurations
    )
    
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "  Starting VMs (Max: $MaxParallelVMs simultaneous)" -ForegroundColor Cyan
    Write-Host "==================================================================`n" -ForegroundColor Cyan
    
    $totalVMs = $VMConfigurations.Count
    $startedVMs = 0
    $runningJobs = @()
    
    foreach ($vmConfig in $VMConfigurations) {
        while ($runningJobs.Count -ge $MaxParallelVMs) {
            Start-Sleep -Seconds 2
            $runningJobs = $runningJobs | Where-Object { $_.State -eq 'Running' }
        }
        
        $vmName = $vmConfig.VMName
        $vmxPath = $vmConfig.VmxPath
        
        $job = Start-Job -ScriptBlock {
            param($vmrunPath, $vmxPath, $vmName)
            
            try {
                & $vmrunPath -T ws start $vmxPath nogui 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    return @{
                        VMName = $vmName
                        Success = $true
                        Message = "VM started successfully"
                    }
                }
                else {
                    return @{
                        VMName = $vmName
                        Success = $false
                        Message = "Failed to start"
                    }
                }
            }
            catch {
                return @{
                    VMName = $vmName
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        } -ArgumentList $script:VmrunPath, $vmxPath, $vmName
        
        $runningJobs += $job
        $startedVMs++
        
        Write-Log "[$vmName] Startup initiated ($startedVMs/$totalVMs)" -Level INFO
        Write-Progress -Activity "Starting VMs" -Status "Started $startedVMs of $totalVMs" -PercentComplete (($startedVMs / $totalVMs) * 100)
    }
    
    Write-Log "Waiting for all VMs to start..." -Level INFO
    $completedJobs = $runningJobs | Wait-Job
    
    $results = @()
    foreach ($job in $completedJobs) {
        $result = Receive-Job -Job $job
        $results += $result
        
        if ($result.Success) {
            Write-Log "[$($result.VMName)] $($result.Message)" -Level SUCCESS
        }
        else {
            Write-Log "[$($result.VMName)] $($result.Message)" -Level ERROR
        }
        
        Remove-Job -Job $job
    }
    
    Write-Progress -Activity "Starting VMs" -Completed
    
    $successCount = ($results | Where-Object { $_.Success }).Count
    $failCount = ($results | Where-Object { -not $_.Success }).Count
    
    Write-Host "`n==================================================================" -ForegroundColor Green
    Write-Host "  VM Startup Summary" -ForegroundColor Green
    Write-Host "==================================================================`n" -ForegroundColor Green
    Write-Host "Total: $totalVMs | Started: $successCount | Failed: $failCount" -ForegroundColor White
    Write-Host ""
}

#endregion

#region Main Execution

function Invoke-Main {
    param()
    
    try {
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  Ubuntu 24.04 Desktop Multi-VM Autoinstall Deployment" -ForegroundColor Cyan
        Write-Host "  Version 5.0 - STABLE" -ForegroundColor Cyan
        Write-Host "==================================================================`n" -ForegroundColor Cyan
        
        Initialize-WorkingDirectory
        Test-Prerequisites
        
        Write-Log "Generating password hashes..." -Level INFO
        
        if ([string]::IsNullOrWhiteSpace($UserPassword)) {
            $userPasswordHash = '$6$sutOa4xN101B97Ht$CZ5mQaVpDnGIPjUDWxEwMkhM.HdEiUuytljcAUqqp6Q1C/co7l9gGhybEI0RTx.Wzd0PTk1Xw5qHnQJ1Eg2YK/'
            Write-Log "Using default user password hash" -Level WARNING
        }
        else {
            $userPasswordHash = New-SecurePasswordHash -Password $UserPassword
        }
        
        if ([string]::IsNullOrWhiteSpace($RootPassword)) {
            $rootPasswordHash = '$6$LI.Aif1qG.AOcagO$n7Fmrm24Quo3KDTGoR9dV13kmUrRgarAsxyCEHjQzRM4OAE5dhRFm2p9SaRfEBQckFwIN5SlZ1KHVsEPLY8vy1'
            Write-Log "Using default root password hash" -Level WARNING
        }
        else {
            $rootPasswordHash = New-SecurePasswordHash -Password $RootPassword
        }
        
        Write-Log "`n=== Configuration ===" -Level INFO
        Write-Log "Source ISO: $SourceIsoPath" -Level INFO
        Write-Log "VM Prefix: $VMNamePrefix" -Level INFO
        Write-Log "VM Count: $VMCount" -Level INFO
        Write-Log "CPU: $VMCpuCount | Memory: $VMMemoryMB MB | Disk: $VMDiskSizeGB GB" -Level INFO
        Write-Log "==================`n" -Level INFO
        
        $baseExtractDir = Join-Path $script:WorkingDir "base_iso_extract"
        Extract-UbuntuISO -IsoPath $SourceIsoPath -ExtractPath $baseExtractDir
        
        Write-Log "Updating GRUB..." -Level INFO
        Update-GrubConfig -ExtractPath $baseExtractDir
        
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  Building VM Configurations" -ForegroundColor Cyan
        Write-Host "==================================================================`n" -ForegroundColor Cyan
        
        $vmConfigurations = @()
        
        for ($i = 0; $i -lt $VMCount; $i++) {
            $vmNumber = $VMStartNumber + $i
            $vmNumberPadded = $vmNumber.ToString("D2")
            $vmName = "$VMNamePrefix-$vmNumberPadded"
            $username = "$VMNamePrefix$vmNumberPadded"
            $hostname = "$VMNamePrefix-$vmNumberPadded"
            
            $vmConfig = @{
                Number = $vmNumber
                Name = $vmName
                Username = $username
                Hostname = $hostname
                UserPasswordHash = $userPasswordHash
                RootPasswordHash = $rootPasswordHash
                Timezone = $Timezone
                CpuCount = $VMCpuCount
                MemoryMB = $VMMemoryMB
                DiskSizeGB = $VMDiskSizeGB
                NetworkType = $VMNetworkType
            }
            
            Write-Progress -Activity "Building VMs" -Status "Processing $vmName ($($i + 1)/$VMCount)" -PercentComplete ((($i + 1) / $VMCount) * 100)
            
            $result = Build-VMConfiguration -VMConfig $vmConfig -BaseExtractPath $baseExtractDir
            
            if ($result.Success) {
                $vmConfigurations += $result
            }
        }
        
        Write-Progress -Activity "Building VMs" -Completed
        
        if ($vmConfigurations.Count -gt 0) {
            Start-ParallelVMDeployment -VMConfigurations $vmConfigurations
        }
        
        Write-Host "`n==================================================================" -ForegroundColor Green
        Write-Host "  Deployment Complete!" -ForegroundColor Green
        Write-Host "==================================================================`n" -ForegroundColor Green
        
        Write-Log "Deployed: $($vmConfigurations.Count) VMs" -Level SUCCESS
        Write-Log "Working Dir: $script:WorkingDir" -Level SUCCESS
        Write-Log "Log File: $script:LogFile" -Level SUCCESS
        
        Write-Host "`nVM Details:" -ForegroundColor Cyan
        foreach ($vm in $vmConfigurations) {
            Write-Host "  $($vm.VMName): $($vm.VmxPath)" -ForegroundColor Yellow
        }
        Write-Host ""
        
    }
    catch {
        Write-Log "CRITICAL ERROR: $_" -Level ERROR
        throw
    }
}

if ($PSCmdlet.ParameterSetName -eq 'GenerateHash') {
    Show-PasswordHashGenerator -Password $PlainTextPassword
}
else {
    Invoke-Main
}

#endregion