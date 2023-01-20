<#
Script version 1.0, written by Paul Loewenkamp

Script must be ran from an elevated PowerShell session or some data may not be properly collected. 

This script collects basic information about Windows computers in order to facilitate more efficient troubleshooting. It collects the following:
- Windows OS information
- Installed Programs
- Currently loaded filter drivers
- Information about disks, volumes, and volume cluster sizes
- Whether or not BitLocker is enabled on volumes
- Whether or not the Windows deduplication role is installed
- NIC and IPv4/IPv6 information
- All Windows Event logs in EVTX format along with the LocaleMetaData

TO ADD:
- Collect running services & port numbers
- Possibly add ability to automatically elevate to administrator

#>

$ScriptVer = "1.0"

#######################
# CREATE LOG FILE DIRECTORIES
#######################
$logPath = "C:\Temp\CollectComputerInfo"
$logFile = "$logPath\CollectComputerInfo_$ScriptVer-$env:COMPUTERNAME-$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).txt"
$eventLogPath = $logPath + '\' + 'EventLogs'

if (!(Test-Path -PathType Container $logPath )) {
    Write-Host -ForegroundColor Yellow "C:\Temp\CollectComputerInfo folder is not found. Creating it to store temporary files."
    New-Item -Path $logPath -ItemType Directory
}

if (!(Test-Path -PathType Container $eventLogPath )) {
    Write-Host -ForegroundColor Yellow "C:\Temp\CollectComputerInfo\EventLogs folder is not found. Creating it to store event logs."
    New-Item -Path $eventLogPath -ItemType Directory
}

#######################
# OPERATING SYSTEM, INSTALLED PROGRAMS, & FLTMC
#######################
Write-Host -ForegroundColor Green "Collecting OS information..."
Write-Output "Computer Name: $env:COMPUTERNAME" | Out-File $logFile -Append
$computer = Get-ComputerInfo | Select-Object OsName,OsVersion,OsBuildnumber,Windowsversion,WindowsEditionId
Write-Output $Computer | Out-File $logFile -Append

Write-Host -ForegroundColor Green "Collecting installed programs and currently loaded filter drivers..."

Write-Output "Installed Programs" | Sort-Object Name | Out-File $logFile -Append
$installedPrograms = Get-CimInstance -Class Win32_Product | Select-Object name,Vendor,Version | Format-Table -Autosize | Out-File $logFile -Append
Write-Output `n "Loaded filter drivers" | Out-File $logFile -Append
$drivers = fltmc.exe | Out-File $logFile -Append

#######################
# DISK, VOLUME, AND PARTITION INFORMATION
#######################
Write-Host -ForegroundColor Green "Collecting disk,volume, and partition information..."
Write-Output `n "Disks visible to the Operating System" | Out-File $logFile -Append
$disks = Get-Disk | Out-File $logFile -Append
Write-Output `n "Volumes visible to the Operating System" | Out-File $logFile -Append
$volumes = Get-Volume | Out-File $logFile -Append
Write-Output `n "Volume cluster (block) sizes" | Out-File $logFile -Append
$clusterSize = Get-CimInstance -ClassName Win32_Volume | Select-Object DriveLetter,Name,Label,BlockSize | Format-Table -Autosize | Out-File $logFile -Append
Write-Output `n "Partition information" | Out-File $logFile -Append
$partitions = Get-Partition | Out-File $logFile -Append
Write-Output `n | Out-File $logFile -Append

#######################
# BITLOCKER STATUS
#######################
Write-Host -ForegroundColor Green "Checking if BitLocker is enabled for any volumes..."
$bitLockerVolumes = Get-BitLockervolume
foreach ($volume in $bitLockerVolumes) {
    if ($bitLockerVolumes.ProtectionStatus -eq "ON") {
        Write-Output `n "Bitlocker is enabled on volume" $volume.MountPoint | Out-File $logFile -Append
    }
    else {
        Write-Output `n "Bitlocker is NOT enabled on volume" $volume.MountPoint | Out-File $logFile -Append
    }
}

#######################
# WINDOWS DEDUPLICATION STATUS
#######################
Write-Host -ForegroundColor Green "Checking if Windows Deduplication is enabled for any volumes..."
if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor Green "Checking if Windows Deduplication role is installed..."
    $dedupe = (Get-WindowsFeature -Name FS-Data-Deduplication).installed
    if ($dedupe) {
        Write-Output "Windows Deduplication role is installed on $env:COMPUTERNAME" | Out-File $logFile -Append
        $dedupedVolumes = Get-DedupVolume
        foreach ($volume in $dedupedVolumes) {
            if ($volume.Enabled) {
                Write-Output "Deduplication enabled on volume $volume.Volume"
            }
        }
    }
}
else {
    Write-Output `n`n`n"Windows Deduplication role is either not installed or is not available" | Out-File $logFile -Append
}

#######################
# NIC INFORMATION
#######################
Write-Host -ForegroundColor Green "Collecting NIC configuration information..."
Write-Output `n "NIC Configuration (IPv4 addresses- Connected NICs ONLY)" | Out-File $logFile -Append
$IPv4Addresses = Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | Select-Object ifIndex,InterfaceAlias,AddressFamily,NLMtu, @{Name="IPv4 Address";Expression={(Get-NetIPAddress -AddressFamily IPv4)}} | Sort-Object ifIndex | Format-Table | Out-File $logFile -Append
Write-Output `n "NIC Configuration (IPv6 addresses- Connected NICs ONLY)" | Out-File $logFile -Append
$IPv6Addresses= Get-NetIPInterface -AddressFamily IPv6 -ConnectionState Connected | Select-Object ifIndex,InterfaceAlias,AddressFamily,NLMtu, @{Name="IPv6 Address";Expression={(Get-NetIPAddress -AddressFamily IPv6)}} | Sort-Object ifIndex | Format-Table | Out-File $logFile -Append


#######################
# EVENT LOG COLLECTION
#######################
Write-Host -ForegroundColor Green "Collecting all Windows event logs. This may take several minutes"
$events = wevtutil.exe el
$i=0
foreach ($event in $events) {
    $eventPath = New-Item -Path $eventLogPath\$event -ItemType Directory
    $eventName = $event | Split-Path -Leaf
    wevtutil.exe epl $event $eventPath\$eventName.evtx #Exports the event logs
    wevtutil.exe al $EventPath\$EventName.evtx /l:en-US #Archives the event logs with LocaleMetaData in en-US locale
    $i++
    Write-Progress -Activity "Collecting Windows event logs..." -CurrentOperation "Collecting $event" -Status "Progress:" -PercentComplete (($i/$events.Count) * 100)
}

#######################
# COMPRESS COLLECTED DATA TO ARCHIVE
#######################
Write-Host -ForegroundColor Blue "Compressing collected information into ZIP archive."

$dataToCompress = @{
    Path = "$logFile", "$eventLogPath"
    CompressionLevel = "Optimal"
    DestinationPath = "$logPath\CollectComputerInfo_$env:COMPUTERNAME-$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).zip"
}

Try {
    Compress-Archive @dataToCompress
}
Catch {
    Write-Host -ForegroundColor Red "An error occurred while compressing the files into a ZIP"
    Write-Host -ForegroundColor Red $PSItem.Exception.Message
}
Finally {
    $Error.Clear()
}

$archivePath = Get-ChildItem $logPath\* -Include *.zip | Where-Object {$_.Name -like 'CollectComputerInfo_*'} | Sort-Object CreationTime -Descending | Select-Object -First 1

#######################
# CLEANUP
#######################
Write-Host -ForegroundColor Red "Removing uncompressed files from $logPath"

Try{
    Remove-Item $logPath\*.txt
    Remove-Item $eventLogPath -Recurse
}
Catch {
    Write-Host -ForegroundColor Red "An error occurred while removing the uncompressed files"
    Write-Host -ForegroundColor Red $PSItem.Exception.Message
}
Finally {
    $Error.Clear()
}

Write-Host -ForegroundColor Yellow "Script has completed. Please upload the ZIP file located at this location: $archivePath"

