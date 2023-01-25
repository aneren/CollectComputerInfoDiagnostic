# CollectComputerInfoDiagnostic
PowerShell script to collect detailed computer information for troubleshooting purposes

Requires PowerShell 5.1 or above, and the script must be ran from an elevated PowerShell session. 

Once the script has completed it collects the information and compresses into a ZIP file saved at C:\Temp\CollectComputerInfo

Collects the following information:
- Windows OS information
- Local user account information
- Installed Programs from both Win32_Product and the registry
- Currently loaded filter drivers (FLTC)
- Information about disks, volumes, and volume cluster sizes
- Whether or not BitLocker is enabled on volumes
- Whether or not the Windows deduplication role is installed
- NIC and IPv4/IPv6 information
- Windows Application & System event logs in EVTX format along with the LocaleMetaData. Optional -AllEvents parameter to collect all Windows events instead

Running the script: <br>
.\CollectComputerInfo.ps1  <br>
.\CollectComputerInfo.ps1 -allEvents <br>