$troubleshootingGuide = @'
# Ubuntu Autoinstall ISO Troubleshooting Guide

## Quick Reference: Testing ISO Bootability Manually

This guide helps you test and troubleshoot Ubuntu autoinstall ISOs when they don't boot properly in VMware.

---

## Prerequisites

- WSL2 with Ubuntu installed
- xorriso installed in WSL (`sudo apt-get install xorriso`)
- Access to the extracted ISO directory from your PowerShell script

---

## Step 1: Access Your ISO Files in WSL

### 1.1 Open WSL Terminal

In PowerShell, type:
```powershell
wsl
```

### 1.2 Navigate to Your ISO Directory

Replace the path with your actual build directory (check your PowerShell script output for the exact path):
```bash
cd '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_YYYYMMDD_HHMMSS/ubuntu-vm-01_iso'
```

Example:
```bash
cd '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/ubuntu-vm-01_iso'
```

### 1.3 Verify Required Files Exist

Check that all critical boot and autoinstall files are present:
```bash
# Check autoinstall files (must be in ISO root)
ls -lh user-data meta-data

# Check UEFI boot files
ls -lh EFI/boot/bootx64.efi
ls -lh EFI/boot/grubx64.efi

# Check BIOS boot files
ls -lh isolinux/isolinux.bin
ls -lh isolinux/isolinux.cfg

# Check GRUB configuration
ls -lh boot/grub/grub.cfg
cat boot/grub/grub.cfg | grep autoinstall
```

**Expected output:**
- `user-data` should be ~500-1000 bytes
- `meta-data` should be ~100 bytes
- `bootx64.efi` and `grubx64.efi` should exist in EFI/boot/
- `isolinux.bin` should exist in isolinux/
- `grub.cfg` should contain `ds=nocloud;s=/cdrom/`

---

## Step 2: Test Different xorriso Commands

Try these three commands in order. Each creates a test ISO with different boot configurations.

### Command 1: Basic Hybrid Boot (Recommended - Simplest)

This is the most compatible method that works with both BIOS and UEFI.
```bash
xorriso -as mkisofs \
  -r \
  -V 'Ubuntu-Autoinstall' \
  -o '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test1.iso' \
  -J -joliet-long \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -eltorito-alt-boot \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  .
```

**What it does:**
- Creates hybrid BIOS + UEFI bootable ISO
- Uses isolinux for BIOS boot
- Uses bootx64.efi for UEFI boot
- Creates GPT partition table for compatibility

---

### Command 2: Hybrid Boot with MBR Template (More Compatible)

First, find the MBR template:
```bash
find /usr/lib -name 'isohdpfx.bin'
```

Expected output: `/usr/lib/ISOLINUX/isohdpfx.bin` or `/usr/lib/syslinux/mbr/isohdpfx.bin`

Then run (replace the path with what you found):
```bash
xorriso -as mkisofs \
  -r \
  -V 'Ubuntu-Autoinstall' \
  -o '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test2.iso' \
  -J -joliet-long \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -eltorito-alt-boot \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
  .
```

**What it does:**
- Same as Command 1, but adds MBR boot sector
- Better compatibility with older systems
- Allows booting from USB drives

---

### Command 3: Advanced Ubuntu Method (Official Ubuntu Approach)

This is what Ubuntu uses for their official ISOs.
```bash
xorriso -as mkisofs \
  -r \
  -V 'Ubuntu-Autoinstall' \
  -o '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test3.iso' \
  -J -joliet-long \
  -iso-level 3 \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  --eltorito-alt-boot \
  -e EFI/boot/bootx64.efi \
  -no-emul-boot \
  -partition_offset 16 \
  -append_partition 2 0xef EFI/boot/bootx64.efi \
  --mbr-force-bootable \
  -appended_part_as_gpt \
  -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
  .
```

**What it does:**
- Creates EFI System Partition
- Adds advanced partition tables
- Most compatible with modern UEFI systems
- May not work if bootx64.efi path is too long

---

## Step 3: Verify and Test Each ISO

### 3.1 Check Boot Structure

After creating each ISO, verify it has proper boot information:
```bash
xorriso -indev '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test1.iso' -report_el_torito as_mkisofs
```

**Look for these lines in the output:**
```
-b isolinux/isolinux.bin
-c isolinux/boot.cat
-e EFI/boot/bootx64.efi
```

If you see these lines, the boot structure is correct.

---

### 3.2 Check ISO Size
```bash
ls -lh /mnt/c/Users/OPTIMUS\ PRIME/Documents/Virtual\ Machines/build_20260124_120258/test*.iso
```

**Expected size:** 5-6 GB for Ubuntu 24.04 Desktop

If the ISO is much smaller (< 3 GB), something went wrong.

---

### 3.3 Test Boot in VMware

Exit WSL:
```bash
exit
```

In PowerShell, manually attach the test ISO to your VM:
```powershell
# Set paths
$vmxPath = "C:\Users\OPTIMUS PRIME\Documents\Virtual Machines\ubuntu-vm-01\ubuntu-vm-01.vmx"
$testIsoPath = "C:\Users\OPTIMUS PRIME\Documents\Virtual Machines\build_20260124_120258\test1.iso"

# Stop VM if running
& "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe" stop "$vmxPath" 2>$null

# Update ISO path in VMX
$vmxContent = Get-Content $vmxPath
$vmxContent = $vmxContent -replace 'ide1:0.fileName = ".*"', "ide1:0.fileName = `"$testIsoPath`""
$vmxContent | Set-Content $vmxPath

# Start VM with GUI to see boot process
& "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe" start "$vmxPath" gui
```

---

## Common Issues and Solutions

### Issue 1: ISO Doesn't Boot at All (Black Screen)

**Symptoms:**
- VM shows "No bootable device"
- Black screen with cursor
- "Operating system not found"

**Diagnosis:**
```bash
# Check if isolinux files exist
ls -lh isolinux/isolinux.bin isolinux/boot.cat

# Check if EFI files exist
ls -lh EFI/boot/bootx64.efi
```

**Solutions:**

1. **Try BIOS boot instead of UEFI:**
   - In your VM's `.vmx` file, change `firmware = "efi"` to `firmware = "bios"`
   - Restart the VM

2. **Verify boot files are present:**
```bash
   # If isolinux.bin is missing, copy it from system
   sudo cp /usr/lib/ISOLINUX/isolinux.bin isolinux/
   sudo cp /usr/lib/syslinux/modules/bios/*.c32 isolinux/
```

3. **Rebuild ISO with Command 2** (MBR template method)

---

### Issue 2: ISO Boots But Shows Manual Install Menu

**Symptoms:**
- GRUB menu appears
- Shows "Try or Install Ubuntu" but doesn't autoinstall
- Asks for language/keyboard selection

**Diagnosis:**
```bash
# Check if autoinstall files are in ISO root
ls -lh user-data meta-data

# Check GRUB config for autoinstall parameters
cat boot/grub/grub.cfg | grep "ds=nocloud"
```

**Solutions:**

1. **Verify autoinstall files location:**
   - Files MUST be in ISO root: `/user-data` and `/meta-data`
   - NOT in `/nocloud/user-data` subdirectory

2. **Check GRUB configuration:**
```bash
   cat boot/grub/grub.cfg
```
   
   Should contain:
```
   linux /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/ --- quiet splash
```
   
   NOT:
```
   linux /casper/vmlinuz ds=nocloud;s=/cdrom/nocloud/
```

3. **Verify user-data format:**
```bash
   head -20 user-data
```
   
   Should start with:
```yaml
   #cloud-config
   autoinstall:
     version: 1
```

---

### Issue 3: UEFI Boot Fails, BIOS Boot Works

**Symptoms:**
- VM boots fine with `firmware = "bios"`
- VM doesn't boot with `firmware = "efi"`

**Diagnosis:**
```bash
# Check if EFI boot files exist
ls -lh EFI/boot/bootx64.efi EFI/boot/grubx64.efi

# Check if efi.img exists (needed for some UEFI implementations)
ls -lh boot/grub/efi.img
```

**Solutions:**

1. **Easiest: Use BIOS mode**
   - Change VM configuration to use BIOS instead of UEFI
   - In `.vmx` file: `firmware = "bios"`

2. **Advanced: Create EFI boot image**
```bash
   # Calculate size needed
   EFI_SIZE=$(du -sk EFI | cut -f1)
   EFI_SIZE=$((EFI_SIZE * 12 / 10))  # Add 20% overhead
   
   # Create EFI boot image
   dd if=/dev/zero of=boot/grub/efi.img bs=1K count=$EFI_SIZE
   mkfs.vfat boot/grub/efi.img
   
   # Copy EFI files into image
   mmd -i boot/grub/efi.img ::EFI
   mmd -i boot/grub/efi.img ::EFI/boot
   mcopy -i boot/grub/efi.img -s EFI/boot/bootx64.efi ::EFI/boot/
   mcopy -i boot/grub/efi.img -s EFI/boot/grubx64.efi ::EFI/boot/
```
   
   Then rebuild ISO using:
```bash
   # Change -e parameter to use efi.img
   -e boot/grub/efi.img
```
   instead of:
```bash
   -e EFI/boot/bootx64.efi
```

---

### Issue 4: ISO Too Small or Incomplete

**Symptoms:**
- ISO is less than 3 GB
- ISO builds quickly (< 1 minute)
- Missing files when mounted

**Diagnosis:**
```bash
# Check ISO size
ls -lh /mnt/c/Users/OPTIMUS\ PRIME/Documents/Virtual\ Machines/build_20260124_120258/test1.iso

# Count files in source directory
find . -type f | wc -l
```

**Solutions:**

1. **Verify source directory is complete:**
```bash
   # Should have ~1200+ files for Ubuntu Desktop
   find . -type f | wc -l
   
   # Check for critical directories
   ls -ld casper/ dists/ pool/ EFI/ boot/
```

2. **Re-extract original ISO:**
```bash
   # Mount original ISO
   sudo mkdir -p /tmp/iso_mount
   sudo mount -o loop '/mnt/c/Users/OPTIMUS PRIME/Downloads/ubuntu-24.04-desktop-amd64.iso' /tmp/iso_mount
   
   # Copy all files
   rsync -a /tmp/iso_mount/ ./
   
   # Unmount
   sudo umount /tmp/iso_mount
```

---

## Testing Checklist

Before considering an ISO "working", verify:

- [ ] ISO file exists and is 5-6 GB in size
- [ ] `user-data` and `meta-data` are in ISO root (not in subdirectory)
- [ ] `boot/grub/grub.cfg` contains `ds=nocloud;s=/cdrom/`
- [ ] Boot structure verified with `xorriso -report_el_torito`
- [ ] VM boots (BIOS or UEFI mode)
- [ ] GRUB menu shows "Try or Install Ubuntu"
- [ ] Autoinstall starts automatically (no language/keyboard prompts)

---

## Quick Command Reference

### All commands in one place for easy copy-paste:
```bash
# 1. Navigate to ISO directory
cd '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/ubuntu-vm-01_iso'

# 2. Verify files
ls -lh user-data meta-data EFI/boot/bootx64.efi isolinux/isolinux.bin boot/grub/grub.cfg

# 3. Check GRUB config
cat boot/grub/grub.cfg | grep autoinstall

# 4. Test Command 1 (Basic Hybrid)
xorriso -as mkisofs -r -V 'Ubuntu-Autoinstall' -o '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test1.iso' -J -joliet-long -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e EFI/boot/bootx64.efi -no-emul-boot -isohybrid-gpt-basdat .

# 5. Verify boot structure
xorriso -indev '/mnt/c/Users/OPTIMUS PRIME/Documents/Virtual Machines/build_20260124_120258/test1.iso' -report_el_torito as_mkisofs

# 6. Check ISO size
ls -lh /mnt/c/Users/OPTIMUS\ PRIME/Documents/Virtual\ Machines/build_20260124_120258/test1.iso
```

---

## Integration with PowerShell Script

Once you find a working xorriso command, integrate it into your PowerShell script by:

1. Replacing the `$xorrisoCmd` variable in the `Build-CustomISO` function
2. Using the exact parameters from your working command
3. Testing with one VM first before deploying multiple VMs

Example:
```powershell
# In Build-CustomISO function, replace the xorriso command with:
$xorrisoCmd = "cd '$wslExtractPath' && xorriso -as mkisofs " +
              "-r -V 'Ubuntu-Autoinstall' -o '$wslOutputIsoPath' " +
              "-J -joliet-long " +
              "-b isolinux/isolinux.bin -c isolinux/boot.cat " +
              "-no-emul-boot -boot-load-size 4 -boot-info-table " +
              "-eltorito-alt-boot -e EFI/boot/bootx64.efi -no-emul-boot " +
              "-isohybrid-gpt-basdat " +
              ". 2>&1"
```

---

## Fix for UEFI Boot Issue

If your ISO boots in BIOS mode but not UEFI mode, the simplest solution is to configure your VMs to use BIOS boot.

### In the PowerShell script:

Find the `Create-VMwareVM` function and change this line:
```powershell
firmware = "efi"
```

To:
```powershell
firmware = "bios"
```

This will make all VMs boot in BIOS mode, which works with your current ISO.

**Full corrected VMX section:**
```powershell
$vmxContent = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "$Name"
guestOS = "ubuntu-64"
firmware = "bios"

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
```

---

## Additional Resources

- **xorriso manual:** `man xorriso` or `xorriso -help`
- **Ubuntu autoinstall docs:** https://ubuntu.com/server/docs/install/autoinstall
- **Cloud-init docs:** https://cloudinit.readthedocs.io/
- **El Torito specification:** ISO 9660 bootable CD standard

---

## Troubleshooting Log Template

When reporting issues, include:
```
Date: 
ISO Path: 
Command Used: 
Exit Code: 
ISO Size: 
Boot Mode Tested: [BIOS/UEFI]
VM Behavior: [Black screen / GRUB menu / Manual install / Autoinstall started]
Error Messages: 

Boot structure output:
[Paste output of: xorriso -indev <iso> -report_el_torito as_mkisofs]

GRUB config check:
[Paste output of: cat boot/grub/grub.cfg | grep autoinstall]

Files present:
[Paste output of: ls -lh user-data meta-data]
```

---

**End of Troubleshooting Guide**
'@

# Save to Downloads folder
$downloadsPath = [Environment]::GetFolderPath("UserProfile") + "\Downloads\Ubuntu-Autoinstall-ISO-Troubleshooting.md"
$troubleshootingGuide | Out-File -FilePath $downloadsPath -Encoding UTF8

Write-Host "`n✓ Troubleshooting guide saved to:" -ForegroundColor Green
Write-Host "  $downloadsPath" -ForegroundColor Cyan
Write-Host "`nYou can open it with any text editor or Markdown viewer." -ForegroundColor White