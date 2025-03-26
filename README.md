# Digital Forensics & Incident Response (DFIR) PowerShell Script

## Overview

This comprehensive PowerShell script automates the collection and reporting of digital forensics and incident response data from Windows systems. Designed for cybersecurity analysts and IT professionals, it gathers extensive system information and generates a well-organized HTML report for analysis.

The script performs a non-invasive collection of data from the local system, including system configuration, network connections, user activity, running processes, file system information, and browser history. All collected information is organized into an interactive HTML report with expandable sections for easy analysis.

## Features

- **Single-file script**: Self-contained PowerShell script with no external dependencies
- **Comprehensive data collection**:
  - System information (OS, hardware, installed software)
  - Network connections and configuration
  - User accounts and activity
  - Process and service information
  - File system data
  - Browser history
  - USB device history
  - Directory listings
  - Scheduled tasks
- **Interactive HTML reporting**:
  - Tabbed interface for easy navigation
  - Expandable sections
  - Sortable tables
  - Mobile-friendly design
- **EDR deployment ready**: Designed to be deployed via enterprise EDR platforms
- **Minimal system impact**: Optimized for performance with minimal system footprint
- **No external dependencies**: Uses built-in PowerShell commands and .NET classes

## Prerequisites

- Windows operating system (Windows 7/Server 2008 R2 or later)
- PowerShell 5.1 or later
- Administrative privileges recommended (but not required for basic collection)

## Usage

### Basic Execution

Run the script from a PowerShell prompt:

```powershell
.\DFIR_EDR_Deployment.ps1
```

This will execute the script with default settings and create an HTML report in the current directory named `DFIR_Report_COMPUTERNAME_TIMESTAMP.html`.

### Advanced Usage

Specify a custom output path:

```powershell
.\DFIR_EDR_Deployment.ps1 -OutputPath "C:\Investigation\CustomReport.html"
```

Suppress automatic report opening:

```powershell
.\DFIR_EDR_Deployment.ps1 -OpenReport:$false
```

## Data Collection Details

The script collects information from the following sources:

### System Information
- Computer system details (name, manufacturer, model)
- Operating system details (version, installation date)
- BIOS information
- Processor details
- Memory configuration
- Boot time
- Installed hotfixes
- Network adapter configuration
- Installed drivers
- Installed software (from registry)
- Windows Update history

### Network Information
- Active network connections (netstat equivalent)
- Listening ports
- SMB shares
- DNS cache entries

### User Information
- Local user accounts
- Active user sessions
- AutoRun entries
- Startup programs
- PowerShell command history
- RDP session history

### Process Information
- Running processes with details
- Services information
- Command line arguments
- Parent process information
- Process start time and resource usage

### File System Information
- Volume information
- Potentially suspicious executables in temp directories

### Scheduled Tasks Information
- Scheduled task details
- Task actions and triggers
- Suspicious tasks identification (non-Microsoft tasks in system paths)

### USB Device Information
- USB storage device history from registry

### Browser History
- Chrome and Edge browsing history
- Visit times, titles, and URLs
- Intelligent title extraction for better readability

### Directory Listings
- System directories (Windows, Program Files, etc.)
- User profile directories
- Temporary directories
- Recent files

## Report Structure

The HTML report is organized into the following sections:

1. **System Information**
   - Basic Info
   - Network Adapters
   - Drivers
   - Installed Software
   - Windows Updates
   - USB Devices

2. **Network Connections**
   - Active Connections
   - Listening Ports
   - SMB Shares
   - DNS Cache

3. **Process Information**
   - Running Processes
   - Services
   - Scheduled Tasks
   - AutoRun Entries
   - Startup Items

4. **User Information**
   - Local Users
   - Active Sessions
   - PowerShell History
   - RDP Sessions

5. **Directory Listings**
   - Windows
   - Prefetch
   - Windows Temp
   - Program Files
   - Program Files (x86)
   - ProgramData
   - Recycle Bin
   - Users
   - Desktop
   - Documents
   - Downloads
   - Recent Files
   - AppData Local
   - AppData Roaming

6. **Browser History**
   - Chrome
   - Edge

## Technical Implementation

### Data Collection Functions

- `Get-SystemInformation`: Collects system hardware, OS, and configuration details
- `Get-NetworkInformation`: Gathers network connections, ports, and configuration
- `Get-UserInformation`: Retrieves user accounts, sessions, and activity
- `Get-ProcessInformation`: Captures running processes and services
- `Get-FileSystemInformation`: Collects disk and suspicious file details
- `Get-ScheduledTaskInfo`: Gathers scheduled task information
- `Get-UsbDeviceInfo`: Retrieves USB storage device history
- `Get-BrowserHistory`: Extracts browser history using binary parsing techniques
- `Get-DirectoryListings`: Creates listings of important directories

### HTML Report Generation

The `Generate-HTMLReport` function creates a comprehensive HTML report with:
- Responsive CSS styling
- Interactive tabbed interface
- Sortable tables for data presentation
- Collapsible sections for easy navigation

### Browser History Extraction

The script uses a specialized technique to extract browser history from Chrome and Edge without requiring third-party tools:
- Creates a temporary copy of browser history database
- Performs binary parsing using regex patterns
- Extracts URLs and attempts to identify page titles
- Generates missing titles from URL patterns when needed
- Maps common domain names to recognizable website titles

## Security and Privacy Considerations

The script operates with the following security and privacy considerations:

- **Read-only operation**: No modifications are made to system files or configurations
- **Local execution**: All data stays on the local system, with no external data transmission
- **Temporary files**: Any temporary files created are automatically deleted after use
- **Permission requirements**: Some data collection may be limited without administrative privileges

## Troubleshooting

### Common Issues

1. **Permission errors**: Run the script with administrative privileges to collect all available data
2. **Browser history unavailable**: Script cannot access browser databases if the browser is currently running
3. **Missing data in report**: Some information may not be available depending on system configuration and permissions

### Logging

The script creates a detailed log file in the temp directory (`%TEMP%\DFIR_Log_TIMESTAMP.txt`) for troubleshooting.

## License

This script is provided for legitimate cybersecurity analysis and incident response purposes only. Always ensure you have proper authorization before running it in any environment.

## Author

Sterling Clifton
