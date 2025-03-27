# DFIR PowerShell Tool

## Overview
This Digital Forensics and Incident Response (DFIR) PowerShell script provides cybersecurity analysts with a comprehensive system analysis tool. It collects detailed information about a Windows system and generates an interactive HTML report for analysis.

## Features
The script collects and reports on:

- **System Information**
  - Basic system details (OS, hardware, installation date)
  - Network adapter configuration
  - Installed drivers
  - Installed software inventory
  - Windows Update history
  - USB device history

- **Network Information**
  - Active network connections
  - Listening ports
  - SMB shares
  - DNS cache entries

- **User Information**
  - Local user accounts
  - Active user sessions
  - PowerShell command history
  - RDP session history
  - Startup items and autorun entries

- **Process Information**
  - Running processes with command lines and parent processes
  - Services with paths and status
  - Scheduled tasks
  - Startup programs

- **File System Information**
  - Directory listings from key system locations
  - Suspicious executables in temp and download directories
  - Recent files accessed

- **Browser History**
  - Chrome browsing history
  - Edge browsing history

## Requirements
- Windows operating system
- PowerShell 5.1 or higher
- Administrative privileges (recommended for full data collection)
- If needed, the script will automatically install the required PSSQLite module

## Usage

### Basic Usage
```powershell
.\DFIR_EDR_Deployment.ps1
```
This will run the script and save the report to the default location: `C:\Investigation\DFIR_Report_COMPUTERNAME_DATE-TIME.html`

### Custom Output Path
```powershell
.\DFIR_EDR_Deployment.ps1 -OutputPath "C:\Path\To\Report.html"
```

### Automatically Open Report
```powershell
.\DFIR_EDR_Deployment.ps1 -OpenReport
```

## Advanced Features

### Primary User Profile Detection
The script automatically detects the primary user profile by:
1. Checking active user sessions
2. If no active sessions, examining the most recently used profile
3. Using environment variables as a fallback

### Browser History Analysis
Browser history extraction handles locked database files and includes flexible fallback methods:
- Uses PSSQLite module when available
- Implements .NET SQLite access as a secondary method
- Falls back to metadata analysis when direct database access isn't possible

### Suspicious File Detection
The script identifies potentially suspicious items:
- Executable files in temp and download folders
- Non-Microsoft scheduled tasks in system paths
- Unusual autorun entries

## Report Navigation
The generated HTML report features:
- Tabbed sections for easy navigation
- Sortable tables
- Detailed information display
- Mobile-friendly responsive design

## Notes
- Some data collection may be limited without administrative privileges
- Certain operations may trigger security software alerts due to the forensic nature of the collection
- The script is designed to be non-destructive and only reads data from the system

## Author
Sterling Clifton  
Version 1.0  
March 26, 2025
