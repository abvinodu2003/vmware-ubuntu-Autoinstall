<#
.SYNOPSIS
    Ubuntu 24.04 Desktop Autoinstall ISO Builder & Multi-VM Deployment

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
    # Create 10 VMs simultaneously
    .\Build-UbuntuAutoinstallVM.ps1 `
        -SourceIsoPath "C:\Users\OPTIMUS PRIME\Downloads\ubuntu-24.04-desktop-amd64.iso" `
        -OutputDirectory "C:\Users\OPTIMUS PRIME\Documents\Virtual Machines" `
        -VMNamePrefix "ubuntu-vm" `
        -VMCount 10 `
        -VMStartNumber 1 `
        -RootPassword "RootP@ss123" `
        -UserPassword "UserP@ss123" `
        -VMCpuCount 4 `
        -VMMemoryMB 8192 `
        -MaxParallelVMs 5

.EXAMPLE
    # Generate password hash only
    .\Build-UbuntuAutoinstallVM.ps1 -GeneratePasswordHash -PlainTextPassword "MySecureP@ssw0rd"

.NOTES
    Author: Enterprise Automation Engineer
    Version: 3.1
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
    <#
    .SYNOPSIS
        Writes timestamped log entries to file and console
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor White }
    }
    
    # File output (thread-safe)
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
    <#
    .SYNOPSIS
        Generates SHA-512 password hash compatible with Ubuntu autoinstall
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [int]$Rounds = 5000
    )
    
    Write-Log "Generating SHA-512 password hash..." -Level INFO
    
    # Generate random salt (16 characters)
    $saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    $salt = -join ((1..16) | ForEach-Object { $saltChars[(Get-Random -Maximum $saltChars.Length)] })
    
    # Escape special characters for bash
    $escapedPassword = $Password -replace "'", "'\\''"
    $escapedSalt = $salt -replace "'", "'\\''"
    
    # Generate hash using WSL with Python (most reliable method)
    $pythonCmd = @"
import crypt
import sys
password = '$escapedPassword'
salt = '\$6\$rounds=$Rounds\$$escapedSalt\$'
hash_result = crypt.crypt(password, salt)
print(hash_result)
"@
    
    try {
        # First, ensure Python3 is available in WSL
        $pythonCheck = wsl -d $script:WSLDistribution bash -c "which python3 2>/dev/null || which python 2>/dev/null"
        if ([string]::IsNullOrWhiteSpace($pythonCheck)) {
            Write-Log "Python not found in WSL, installing..." -Level WARNING
            wsl -d $script:WSLDistribution bash -c "sudo apt-get update -qq && sudo apt-get install -y -qq python3" | Out-Null
        }
        
        # Generate the hash
        $hashResult = wsl -d $script:WSLDistribution bash -c "python3 -c `"$pythonCmd`""
        
        if ([string]::IsNullOrWhiteSpace($hashResult) -or $LASTEXITCODE -ne 0) {
            throw "Hash generation failed"
        }
        
        Write-Log "Password hash generated successfully" -Level SUCCESS
        return $hashResult.Trim()
    }
    catch {
        Write-Log "Failed to generate password hash using Python, trying mkpasswd..." -Level WARNING
        
        # Fallback to mkpasswd method
        try {
            # Install mkpasswd if needed
            wsl -d $script:WSLDistribution bash -c "command -v mkpasswd >/dev/null 2>&1 || sudo apt-get install -y -qq whois" | Out-Null
            
            # Generate hash using mkpasswd
            $mkpasswdCmd = "echo '$escapedPassword' | mkpasswd -m sha-512 -R $Rounds -S '$escapedSalt' -s"
            $hashResult = wsl -d $script:WSLDistribution bash -c $mkpasswdCmd
            
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
    <#
    .SYNOPSIS
        Interactive password hash generator
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$Password
    )
    
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "  Ubuntu Autoinstall Password Hash Generator" -ForegroundColor Cyan
    Write-Host "==================================================================`n" -ForegroundColor Cyan
    
    # Get password if not provided
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
        # Detect WSL distribution first
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
        
        # Copy to clipboard if available
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
    <#
    .SYNOPSIS
        Validates all required components and dependencies
    #>
    param()
    
    Write-Log "Starting prerequisite validation..." -Level INFO
    Write-Progress -Activity "Validating Environment" -Status "Checking WSL2..." -PercentComplete 10
    
    # Check WSL2
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
    
    # Check Ubuntu distribution (improved detection)
    $distributionsRaw = wsl --list --quiet
    
    # Clean up the distribution names (remove null characters and whitespace)
    $distributions = $distributionsRaw | ForEach-Object { 
        $_.Trim() -replace "`0", "" -replace "\s+", " " 
    } | Where-Object { $_ -ne "" }
    
    Write-Log "Detected WSL distributions: $($distributions -join ', ')" -Level INFO
    
    # Find any Ubuntu distribution
    $ubuntuDist = $distributions | Where-Object { $_ -match 'Ubuntu' } | Select-Object -First 1
    
    if (-not $ubuntuDist) {
        Write-Log "No Ubuntu distribution found in WSL" -Level ERROR
        Write-Log "Available distributions: $($distributions -join ', ')" -Level INFO
        throw "Please install Ubuntu: wsl --install -d Ubuntu-24.04"
    }
    
    # Set the distribution to use
    $script:WSLDistribution = $ubuntuDist.Trim()
    Write-Log "Ubuntu WSL distribution found: $script:WSLDistribution" -Level SUCCESS
    
    Write-Progress -Activity "Validating Environment" -Status "Installing Linux packages..." -PercentComplete 50
    
    # Install required Linux packages
    Write-Log "Installing required Linux packages in $script:WSLDistribution..." -Level INFO
    $packages = @(
        'xorriso',
        'isolinux',
        'cloud-init',
        'rsync',
        'grub-pc-bin',
        'grub-efi-amd64-bin',
        'python3',
        'whois'
    )
    
    $packageList = $packages -join ' '
    $installCmd = "sudo apt-get update -qq && sudo apt-get install -y -qq $packageList"
    
    try {
        # Use the detected distribution
        wsl -d $script:WSLDistribution bash -c $installCmd
        if ($LASTEXITCODE -ne 0) {
            throw "Package installation failed with exit code $LASTEXITCODE"
        }
        Write-Log "Linux packages installed successfully" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to install Linux packages: $_" -Level ERROR
        throw
    }
    
    Write-Progress -Activity "Validating Environment" -Status "Checking VMware installation..." -PercentComplete 70
    
    # Check VMware installation
    $vmwarePaths = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Player\vmrun.exe",
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe"
    )
    
    $vmrunPath = $vmwarePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    
    if (-not $vmrunPath) {
        Write-Log "VMware Workstation or Player not found" -Level ERROR
        throw "Please install VMware Workstation or VMware Player"
    }
    
    $script:VmrunPath = $vmrunPath
    Write-Log "VMware found at: $vmrunPath" -Level SUCCESS
    
    Write-Progress -Activity "Validating Environment" -Status "Validation complete" -PercentComplete 100
    Write-Log "All prerequisites validated successfully" -Level SUCCESS
    
    Start-Sleep -Seconds 1
    Write-Progress -Activity "Validating Environment" -Completed
}

#endregion

#region ISO Building Functions

function Initialize-WorkingDirectory {
    <#
    .SYNOPSIS
        Creates and initializes working directory structure
    #>
    param()
    
    Write-Log "Initializing working directory..." -Level INFO
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputDirectory" -Level INFO
    }
    
    # Create timestamped working directory
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:WorkingDir = Join-Path $OutputDirectory "build_$timestamp"
    New-Item -Path $script:WorkingDir -ItemType Directory -Force | Out-Null
    
    # Initialize log file
    $script:LogFile = Join-Path $script:WorkingDir "build.log"
    Write-Log "Working directory: $script:WorkingDir" -Level INFO
}

function ConvertTo-WslPath {
    <#
    .SYNOPSIS
        Converts Windows path to WSL path format
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$WindowsPath
    )
    
    # Use the detected WSL distribution
    $wslPath = wsl -d $script:WSLDistribution wslpath -a "$WindowsPath"
    return $wslPath.Trim()
}

function New-AutoinstallConfig {
    <#
    .SYNOPSIS
        Creates autoinstall.yaml configuration for a specific VM
    #>
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
  # version is an Autoinstall required field.
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
  # Additional cloud-init configuration affecting the target system
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
    <#
    .SYNOPSIS
        Prepares autoinstall configuration files for injection
    #>
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
    
    # Create VM-specific directory
    $vmWorkDir = Join-Path $script:WorkingDir $VMName
    New-Item -Path $vmWorkDir -ItemType Directory -Force | Out-Null
    
    # Create nocloud directory
    $nocloudDir = Join-Path $vmWorkDir "nocloud"
    New-Item -Path $nocloudDir -ItemType Directory -Force | Out-Null
    
    # Generate autoinstall.yaml
    $autoinstallContent = New-AutoinstallConfig `
        -VMName $VMName `
        -Username $Username `
        -Hostname $Hostname `
        -UserPasswordHash $UserPasswordHash `
        -RootPasswordHash $RootPasswordHash `
        -Timezone $Timezone
    
    # Save user-data
    $userData = Join-Path $nocloudDir "user-data"
    Set-Content -Path $userData -Value $autoinstallContent -Force
    Write-Log "Created autoinstall.yaml (user-data) for $VMName" -Level INFO
    
    # Create meta-data
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
    <#
    .SYNOPSIS
        Extracts original Ubuntu ISO contents using WSL (only once for all VMs)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IsoPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    # Check if already extracted
    if (Test-Path -LiteralPath $ExtractPath) {
        Write-Log "ISO already extracted, skipping..." -Level INFO
        return
    }
    
    Write-Log "Extracting Ubuntu ISO (this only happens once)..." -Level INFO
    Write-Progress -Activity "Building Custom ISOs" -Status "Extracting original ISO (this may take several minutes)..." -PercentComplete 15
    
    # Convert paths to WSL format
    $wslIsoPath = ConvertTo-WslPath -WindowsPath $IsoPath
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    # Create extraction directory
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    
    # Extract ISO using xorriso in WSL
    $extractCmd = @"
mkdir -p /tmp/iso_mount && \
sudo mount -o loop '$wslIsoPath' /tmp/iso_mount && \
rsync -a --exclude=/casper/filesystem.squashfs /tmp/iso_mount/ '$wslExtractPath/' && \
rsync -a /tmp/iso_mount/casper/filesystem.squashfs '$wslExtractPath/casper/' && \
sudo umount /tmp/iso_mount && \
rmdir /tmp/iso_mount
"@
    
    try {
        wsl -d $script:WSLDistribution bash -c $extractCmd
        if ($LASTEXITCODE -ne 0) {
            throw "ISO extraction failed with exit code $LASTEXITCODE"
        }
        Write-Log "ISO extracted successfully" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to extract ISO: $_" -Level ERROR
        throw
    }
}

function Update-GrubConfig {
    <#
    .SYNOPSIS
        Modifies GRUB configuration to include autoinstall boot parameters
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    # Define the autoinstall boot parameters
    $autoinstallParams = 'autoinstall ds=nocloud\;s=/cdrom/nocloud/ ---'
    
    # Update boot/grub/grub.cfg
    $grubCfgPath = "$wslExtractPath/boot/grub/grub.cfg"
    $updateGrubCmd = @"
if [ -f '$grubCfgPath' ]; then
    sed -i 's|quiet splash|quiet splash $autoinstallParams|g' '$grubCfgPath'
    sed -i 's|---\$||g' '$grubCfgPath'
fi
"@
    
    wsl -d $script:WSLDistribution bash -c $updateGrubCmd
    
    # Update boot/grub/loopback.cfg if present
    $loopbackCfgPath = "$wslExtractPath/boot/grub/loopback.cfg"
    $updateLoopbackCmd = @"
if [ -f '$loopbackCfgPath' ]; then
    sed -i 's|quiet splash|quiet splash $autoinstallParams|g' '$loopbackCfgPath'
    sed -i 's|---\$||g' '$loopbackCfgPath'
fi
"@
    
    wsl -d $script:WSLDistribution bash -c $updateLoopbackCmd
}

function Copy-NocloudFiles {
    <#
    .SYNOPSIS
        Copies NoCloud datasource files into extracted ISO
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$NocloudSource,
        
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath
    )
    
    $wslNocloudSource = ConvertTo-WslPath -WindowsPath $NocloudSource
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    
    $copyCmd = @"
mkdir -p '$wslExtractPath/nocloud' && \
cp '$wslNocloudSource/user-data' '$wslExtractPath/nocloud/' && \
cp '$wslNocloudSource/meta-data' '$wslExtractPath/nocloud/' && \
chmod 644 '$wslExtractPath/nocloud/user-data' && \
chmod 644 '$wslExtractPath/nocloud/meta-data'
"@
    
    wsl -d $script:WSLDistribution bash -c $copyCmd
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to copy NoCloud files"
    }
}

function Build-CustomISO {
    <#
    .SYNOPSIS
        Rebuilds bootable ISO with injected autoinstall configuration
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExtractPath,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputIsoPath,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    Write-Log "Building custom ISO for $VMName..." -Level INFO
    
    $wslExtractPath = ConvertTo-WslPath -WindowsPath $ExtractPath
    $wslOutputIsoPath = ConvertTo-WslPath -WindowsPath $OutputIsoPath
    
    # Build ISO with xorriso (hybrid UEFI + BIOS)
    $buildCmd = @"
cd '$wslExtractPath' && \
xorriso -as mkisofs \
    -r -V 'Ubuntu 24.04 Autoinstall' \
    -o '$wslOutputIsoPath' \
    -J -joliet-long \
    -cache-inodes \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -isohybrid-apm-hfsplus \
    -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
    . 2>&1
"@
    
    try {
        $output = wsl -d $script:WSLDistribution bash -c $buildCmd
        if ($LASTEXITCODE -ne 0) {
            throw "ISO build failed with exit code $LASTEXITCODE"
        }
        Write-Log "Custom ISO created for $VMName : $OutputIsoPath" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to build ISO for $VMName : $_" -Level ERROR
        throw
    }
}

#endregion

#region VMware Functions

function Create-VMwareVM {
    <#
    .SYNOPSIS
        Creates and configures VMware virtual machine
    #>
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
    
    # Create VM directory
    $vmDir = Join-Path $OutputDirectory $Name
    if (Test-Path -LiteralPath $vmDir) {
        Write-Log "VM directory already exists, removing..." -Level WARNING
        Remove-Item -LiteralPath $vmDir -Recurse -Force
    }
    New-Item -Path $vmDir -ItemType Directory -Force | Out-Null
    
    # Define file paths
    $vmxPath = Join-Path $vmDir "$Name.vmx"
    $vmdkPath = Join-Path $vmDir "$Name.vmdk"
    
    # Generate VMX configuration
    $vmxContent = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "$Name"
guestOS = "ubuntu-64"
firmware = "efi"

# CPU Configuration
numvcpus = "$CpuCount"
cpuid.coresPerSocket = "1"

# Memory Configuration
memsize = "$MemoryMB"

# Disk Configuration
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "$Name.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"

# CD/DVD Configuration
ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "$IsoPath"
ide1:0.startConnected = "TRUE"

# Network Configuration
ethernet0.present = "TRUE"
ethernet0.connectionType = "$NetworkType"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"
ethernet0.startConnected = "TRUE"

# USB Configuration
usb.present = "TRUE"
ehci.present = "TRUE"

# Sound Configuration
sound.present = "TRUE"
sound.fileName = "-1"
sound.autodetect = "TRUE"

# Display Configuration
svga.autodetect = "TRUE"
mks.enable3d = "TRUE"

# Miscellaneous
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
    
    # Create virtual disk
    $vmwareDir = Split-Path -Parent $script:VmrunPath
    $vdiskManager = Join-Path $vmwareDir "vmware-vdiskmanager.exe"
    
    if (Test-Path -LiteralPath $vdiskManager) {
        $createDiskCmd = "& `"$vdiskManager`" -c -s ${DiskSizeGB}GB -a lsilogic -t 0 `"$vmdkPath`" 2>&1"
        $null = Invoke-Expression $createDiskCmd
    }
    else {
        # Create basic VMDK descriptor
        $vmdkDescriptor = @"
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicSparse"

# Extent description
RW $($DiskSizeGB * 2097152) SPARSE "$Name.vmdk"

# The Disk Data Base
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
    <#
    .SYNOPSIS
        Powers on the VMware virtual machine
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    Write-Log "Starting VM: $VMName..." -Level INFO
    
    try {
        $startCmd = "& `"$script:VmrunPath`" -T ws start `"$VmxPath`" nogui 2>&1"
        $output = Invoke-Expression $startCmd
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "VM started successfully: $VMName" -Level SUCCESS
        }
        else {
            throw "Failed to start VM (exit code: $LASTEXITCODE) - $output"
        }
    }
    catch {
        Write-Log "Failed to start VM $VMName : $_" -Level ERROR
        throw
    }
}

#endregion

#region Multi-VM Orchestration

function Build-VMConfiguration {
    <#
    .SYNOPSIS
        Builds a single VM configuration and ISO
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$VMConfig,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseExtractPath
    )
    
    $vmName = $VMConfig.Name
    $vmNumber = $VMConfig.Number
    
    try {
        Write-Log "[$vmName] Starting VM configuration build..." -Level INFO
        
        # Create VM-specific extract directory
        $vmExtractPath = Join-Path $script:WorkingDir "$vmName`_iso_extract"
        
        # Copy base extraction to VM-specific directory
        Write-Log "[$vmName] Creating VM-specific ISO workspace..." -Level INFO
        Copy-Item -LiteralPath $BaseExtractPath -Destination $vmExtractPath -Recurse -Force
        
        # Prepare autoinstall files
        $nocloudDir = Prepare-AutoinstallFiles `
            -VMName $vmName `
            -Username $VMConfig.Username `
            -Hostname $VMConfig.Hostname `
            -UserPasswordHash $VMConfig.UserPasswordHash `
            -RootPasswordHash $VMConfig.RootPasswordHash `
            -Timezone $VMConfig.Timezone
        
        # Copy NoCloud files to extracted ISO
        Copy-NocloudFiles -NocloudSource $nocloudDir -ExtractPath $vmExtractPath
        
        # Build custom ISO
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $customIsoPath = Join-Path $script:WorkingDir "$vmName-autoinstall-$timestamp.iso"
        
        Build-CustomISO -ExtractPath $vmExtractPath -OutputIsoPath $customIsoPath -VMName $vmName
        
        # Create VMware VM
        $vmxPath = Create-VMwareVM `
            -Name $vmName `
            -IsoPath $customIsoPath `
            -CpuCount $VMConfig.CpuCount `
            -MemoryMB $VMConfig.MemoryMB `
            -DiskSizeGB $VMConfig.DiskSizeGB `
            -NetworkType $VMConfig.NetworkType
        
        Write-Log "[$vmName] VM configuration completed successfully" -Level SUCCESS
        
        return @{
            VMName = $vmName
            VmxPath = $vmxPath
            Success = $true
        }
    }
    catch {
        Write-Log "[$vmName] VM configuration failed: $_" -Level ERROR
        return @{
            VMName = $vmName
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-ParallelVMDeployment {
    <#
    .SYNOPSIS
        Starts VMs in parallel batches
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$VMConfigurations
    )
    
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "  Starting VMs in Parallel (Max: $MaxParallelVMs simultaneous)" -ForegroundColor Cyan
    Write-Host "==================================================================`n" -ForegroundColor Cyan
    
    $totalVMs = $VMConfigurations.Count
    $startedVMs = 0
    $runningJobs = @()
    
    foreach ($vmConfig in $VMConfigurations) {
        # Wait if we've reached max parallel VMs
        while ($runningJobs.Count -ge $MaxParallelVMs) {
            Start-Sleep -Seconds 2
            $runningJobs = $runningJobs | Where-Object { $_.State -eq 'Running' }
        }
        
        # Start VM in background job
        $vmName = $vmConfig.VMName
        $vmxPath = $vmConfig.VmxPath
        
        $job = Start-Job -ScriptBlock {
            param($vmrunPath, $vmxPath, $vmName)
            
            try {
                $startCmd = "& `"$vmrunPath`" -T ws start `"$vmxPath`" nogui 2>&1"
                $output = Invoke-Expression $startCmd
                
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
                        Message = "Failed to start VM: $output"
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
        
        Write-Log "[$vmName] VM startup initiated ($startedVMs/$totalVMs)" -Level INFO
        Write-Progress -Activity "Starting VMs" -Status "Started $startedVMs of $totalVMs VMs" -PercentComplete (($startedVMs / $totalVMs) * 100)
    }
    
    # Wait for all jobs to complete
    Write-Log "Waiting for all VM startup jobs to complete..." -Level INFO
    $completedJobs = $runningJobs | Wait-Job
    
    # Collect results
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
    
    # Summary
    $successCount = ($results | Where-Object { $_.Success }).Count
    $failCount = ($results | Where-Object { -not $_.Success }).Count
    
    Write-Host "`n==================================================================" -ForegroundColor Green
    Write-Host "  VM Startup Summary" -ForegroundColor Green
    Write-Host "==================================================================`n" -ForegroundColor Green
    Write-Host "Total VMs: $totalVMs" -ForegroundColor White
    Write-Host "Successfully Started: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
}

#endregion

#region Main Execution

function Invoke-Main {
    <#
    .SYNOPSIS
        Main orchestration function for multi-VM deployment
    #>
    param()
    
    try {
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  Ubuntu 24.04 Desktop Multi-VM Autoinstall Deployment" -ForegroundColor Cyan
        Write-Host "==================================================================`n" -ForegroundColor Cyan
        
        # Initialize working directory and logging
        Initialize-WorkingDirectory
        
        # Generate password hashes
        Write-Log "Generating password hashes..." -Level INFO
        
        if ([string]::IsNullOrWhiteSpace($UserPassword)) {
            # Use default from template
            $userPasswordHash = '$6$sutOa4xN101B97Ht$CZ5mQaVpDnGIPjUDWxEwMkhM.HdEiUuytljcAUqqp6Q1C/co7l9gGhybEI0RTx.Wzd0PTk1Xw5qHnQJ1Eg2YK/'
            Write-Log "Using default user password hash from template" -Level WARNING
        }
        else {
            $userPasswordHash = New-SecurePasswordHash -Password $UserPassword
            Write-Log "Generated user password hash" -Level SUCCESS
        }
        
        if ([string]::IsNullOrWhiteSpace($RootPassword)) {
            # Use default from template
            $rootPasswordHash = '$6$LI.Aif1qG.AOcagO$n7Fmrm24Quo3KDTGoR9dV13kmUrRgarAsxyCEHjQzRM4OAE5dhRFm2p9SaRfEBQckFwIN5SlZ1KHVsEPLY8vy1'
            Write-Log "Using default root password hash from template" -Level WARNING
        }
        else {
            $rootPasswordHash = New-SecurePasswordHash -Password $RootPassword
            Write-Log "Generated root password hash" -Level SUCCESS
        }
        
        Write-Log "`n=== Deployment Configuration ===" -Level INFO
        Write-Log "Source ISO: $SourceIsoPath" -Level INFO
        Write-Log "Output Directory: $OutputDirectory" -Level INFO
        Write-Log "VM Name Prefix: $VMNamePrefix" -Level INFO
        Write-Log "VM Count: $VMCount" -Level INFO
        Write-Log "Starting Number: $VMStartNumber" -Level INFO
        Write-Log "CPU per VM: $VMCpuCount cores" -Level INFO
        Write-Log "Memory per VM: $VMMemoryMB MB" -Level INFO
        Write-Log "Disk per VM: $VMDiskSizeGB GB" -Level INFO
        Write-Log "Network Type: $VMNetworkType" -Level INFO
        Write-Log "Max Parallel VMs: $MaxParallelVMs" -Level INFO
        Write-Log "Timezone: $Timezone" -Level INFO
        Write-Log "WSL Distribution: $script:WSLDistribution" -Level INFO
        Write-Log "================================`n" -Level INFO
        
        # Step 1: Validate prerequisites
        Test-Prerequisites
        
        # Step 2: Extract Ubuntu ISO once (base extraction)
        $baseExtractDir = Join-Path $script:WorkingDir "base_iso_extract"
        Extract-UbuntuISO -IsoPath $SourceIsoPath -ExtractPath $baseExtractDir
        
        # Step 3: Update GRUB configuration in base extraction
        Write-Log "Updating GRUB configuration in base extraction..." -Level INFO
        Update-GrubConfig -ExtractPath $baseExtractDir
        
        # Step 4: Build VM configurations
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  Building VM Configurations and ISOs" -ForegroundColor Cyan
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
            
            Write-Progress -Activity "Building VM Configurations" -Status "Processing $vmName ($($i + 1) of $VMCount)" -PercentComplete ((($i + 1) / $VMCount) * 100)
            
            $result = Build-VMConfiguration -VMConfig $vmConfig -BaseExtractPath $baseExtractDir
            
            if ($result.Success) {
                $vmConfigurations += $result
            }
            else {
                Write-Log "Skipping VM $($vmConfig.Name) due to build failure" -Level WARNING
            }
        }
        
        Write-Progress -Activity "Building VM Configurations" -Completed
        
        # Step 5: Start VMs in parallel
        if ($vmConfigurations.Count -gt 0) {
            Start-ParallelVMDeployment -VMConfigurations $vmConfigurations
        }
        else {
            Write-Log "No VMs were successfully configured" -Level ERROR
            return
        }
        
        Write-Host "`n==================================================================" -ForegroundColor Green
        Write-Host "  Multi-VM Deployment Complete!" -ForegroundColor Green
        Write-Host "==================================================================`n" -ForegroundColor Green
        
        Write-Log "Total VMs Deployed: $($vmConfigurations.Count)" -Level SUCCESS
        Write-Log "Working Directory: $script:WorkingDir" -Level SUCCESS
        Write-Log "Log File: $script:LogFile" -Level SUCCESS
        Write-Log "`nAll VMs are now booting and will perform unattended Ubuntu Desktop installations." -Level INFO
        Write-Log "Monitor individual VM consoles for installation progress." -Level INFO
        
        # Display VM Details
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  VM Details" -ForegroundColor Cyan
        Write-Host "==================================================================`n" -ForegroundColor Cyan
        
        foreach ($vm in $vmConfigurations) {
            Write-Host "VM Name: $($vm.VMName)" -ForegroundColor Yellow
            Write-Host "  VMX File: $($vm.VmxPath)" -ForegroundColor White
            Write-Host ""
        }
        
    }
    catch {
        Write-Log "CRITICAL ERROR: $_" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        throw
    }
}

# Execute based on parameter set
if ($PSCmdlet.ParameterSetName -eq 'GenerateHash') {
    # Password hash generation mode
    Show-PasswordHashGenerator -Password $PlainTextPassword
}
else {
    # Multi-VM deployment mode
    Invoke-Main
}

#endregion