<#
.DESCRIPTION
    PowerShell script for Digital Forensics and Incident Response.
    Collects system, network, process, user, directory, and browser information 
    Outputs a detailed HTML report.
.NOTES
    Author: Sterling Clifton
    Version: 1.0
    Date: March 26, 2025
    Requirements: PowerShell 5.1+, Administrative privileges recommended
.EXAMPLE
    .\DFIR_EDR_Deployment.ps1
    Runs script and creates report in the current directory
.EXAMPLE
    .\DFIR_EDR_Deployment.ps1 -OutputPath "C:\Investigation\Report.html"
    Runs script and outputs report to specified path
#>

#Script Configuration
param(
    [string]$OutputPath = "C:\Investigation\DFIR_Report_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyy-MM-dd-HH-mm').html",
    [switch]$OpenReport = $false
)

# Create output directory if it doesn't exist
$outputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $outputDir)) {
    try {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $outputDir" -ForegroundColor Green
    } catch {
        Write-Host "Error creating output directory: $_" -ForegroundColor Red
        $OutputPath = "$PWD\DFIR_Report_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyy-MM-dd-HH-mm').html"
        Write-Host "Falling back to current directory: $OutputPath" -ForegroundColor Yellow
    }
}

# Error handling settings
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Hide progress bars for faster execution

# Function to get the primary user profile path
function Get-PrimaryUserProfile {
    Write-Host "Identifying primary user profile..." -ForegroundColor Green
    
    # Initial default to current user profile
    $primaryUserProfile = $env:USERPROFILE
    $primaryUserName = $env:USERNAME
    
    # Get active user sessions
    $activeUsers = @()
    try {
        $activeUsers = quser 2>$null | ForEach-Object {
            $line = $_.Trim() -replace '\s+', ' '
            if ($line -notmatch "USERNAME") {
                $parts = $line.Split(' ')
                
                # Parse the quser output depending on the format
                $username = $parts[0]
                $state = if ($parts[1] -eq '>') { $parts[3] } else { $parts[2] }
                $idleTime = if ($parts[1] -eq '>') { $parts[4] } else { $parts[3] }
                
                [PSCustomObject]@{
                    Username = $username
                    State = $state
                    IdleTime = $idleTime
                    Active = ($state -eq "Active")
                }
            }
        }
    } 
    catch {
        Write-Host "Error detecting active users: $_" -ForegroundColor Yellow
    }
    
    # Check if we found any active users
    $activeUserCount = ($activeUsers | Measure-Object).Count
    
    if ($activeUserCount -gt 0) {
        # First, look for users in "Active" state
        $activeUser = $activeUsers | Where-Object { $_.Active -eq $true } | Select-Object -First 1
        
        if ($activeUser) {
            $primaryUserName = $activeUser.Username
            Write-Host "Found active user: $primaryUserName" -ForegroundColor Green
        } 
        else {
            # If no active users, take the first logged-in user
            $primaryUserName = $activeUsers[0].Username
            Write-Host "No active users found. Using first logged-in user: $primaryUserName" -ForegroundColor Yellow
        }
        
        # Get user profile path
        $primaryUserProfile = "C:\Users\$primaryUserName"
    } 
    else {
        # If no active sessions, get most recently used profile from registry
        try {
            $profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
                           Where-Object { $_.ProfileImagePath -like "C:\Users\*" -and $_.ProfileImagePath -notlike "*systemprofile*" -and $_.ProfileImagePath -notlike "*LocalService*" -and $_.ProfileImagePath -notlike "*NetworkService*" }
            
            # Convert LastUseTime property if exists
            if ($profileList -and $profileList.Count -gt 0 -and $profileList[0].PSObject.Properties.Name -contains "LastUseTime") {
                # Sort by LastUseTime if available
                $mostRecentProfile = $profileList | Sort-Object -Property LastUseTime -Descending | Select-Object -First 1
            } 
            else {
                # Otherwise, just take the first one or try sorting by ProfileLoadTimeLow if it exists
                if ($profileList -and $profileList.Count -gt 0 -and $profileList[0].PSObject.Properties.Name -contains "ProfileLoadTimeLow") {
                    $mostRecentProfile = $profileList | Sort-Object -Property ProfileLoadTimeLow -Descending | Select-Object -First 1
                } 
                else {
                    $mostRecentProfile = $profileList | Select-Object -First 1
                }
            }
            
            if ($mostRecentProfile) {
                $primaryUserProfile = $mostRecentProfile.ProfileImagePath
                $primaryUserName = Split-Path -Path $primaryUserProfile -Leaf
                Write-Host "No active users found. Using most recent profile: $primaryUserProfile" -ForegroundColor Yellow
            }
        } 
        catch {
            Write-Host "Error detecting user profiles from registry: $_" -ForegroundColor Yellow
            Write-Host "Fallback to default profile path: $primaryUserProfile" -ForegroundColor Yellow
        }
    }
    
    # Return both the profile path and the username
    return @{
        ProfilePath = $primaryUserProfile
        Username = $primaryUserName
    }
}

# Get the primary user info
$primaryUserInfo = Get-PrimaryUserProfile
$PrimaryUserProfile = $primaryUserInfo.ProfilePath
$PrimaryUserName = $primaryUserInfo.Username

# Define user-specific paths based on the primary user profile
$PrimaryUserLocalAppData = Join-Path -Path $PrimaryUserProfile -ChildPath "AppData\Local"
$PrimaryUserRoamingAppData = Join-Path -Path $PrimaryUserProfile -ChildPath "AppData\Roaming"
$PrimaryUserTemp = Join-Path -Path $PrimaryUserLocalAppData -ChildPath "Temp"
$PrimaryUserDesktop = Join-Path -Path $PrimaryUserProfile -ChildPath "Desktop"
$PrimaryUserDocuments = Join-Path -Path $PrimaryUserProfile -ChildPath "Documents"
$PrimaryUserDownloads = Join-Path -Path $PrimaryUserProfile -ChildPath "Downloads"

Write-Host "Primary User Identified: $PrimaryUserName" -ForegroundColor Green
Write-Host "Primary User Profile: $PrimaryUserProfile" -ForegroundColor Green
Write-Host "Starting DFIR data collection..." -ForegroundColor Green

# Create timestamp for logging
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFile = "$env:TEMP\DFIR_Log_$timestamp.txt"

function Write-DFIRLog {
    param (
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    switch ($Level) {
        "Info"    { Write-Host $Message -ForegroundColor Cyan }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error"   { Write-Host $Message -ForegroundColor Red }
    }
    
    "$timestamp [$Level] $Message" | Out-File -FilePath $logFile -Append
}

function Format-DataSize {
    param (
        [Parameter(Mandatory=$true)]
        [double]$Bytes,
        [int]$Precision = 2
    )
    
    if ($Bytes -lt 1KB) {
        return "$Bytes B"
    }
    elseif ($Bytes -lt 1MB) {
        return "$([math]::Round($Bytes/1KB, $Precision)) KB"
    }
    elseif ($Bytes -lt 1GB) {
        return "$([math]::Round($Bytes/1MB, $Precision)) MB"
    }
    elseif ($Bytes -lt 1TB) {
        return "$([math]::Round($Bytes/1GB, $Precision)) GB"
    }
    else {
        return "$([math]::Round($Bytes/1TB, $Precision)) TB"
    }
}
#endregion

#region Data Collection Functions
function Get-SystemInformation {
    Write-DFIRLog "Collecting system information..." 
    
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $processors = Get-CimInstance -ClassName Win32_Processor
    $timeZone = Get-TimeZone
    $bootTime = $operatingSystem.LastBootUpTime
    
    $hotfixes = Get-HotFix | Select-Object -Property HotFixID, InstalledOn, Description
    
    $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" | 
                      Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled, DHCPServer, MACAddress
    
    # Get installed drivers
    $drivers = @()
    try {
        $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue | 
                  Where-Object { $_.DeviceName -ne $null } | 
                  Select-Object DeviceName, Manufacturer, DriverVersion, DriverDate, IsSigned, Status
    } catch {
        Write-DFIRLog "Error collecting driver information: $_" "Warning"
    }
    
    # Get installed software
    $software = @()
    try {
        # Get software from 64-bit registry
        $software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -ne $null } | 
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, @{Name="Architecture"; Expression={"x64"}}
        
        # Get software from 32-bit registry
        $software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -ne $null } | 
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, @{Name="Architecture"; Expression={"x86"}}
    } catch {
        Write-DFIRLog "Error collecting installed software: $_" "Warning"
    }
    
    # Get Windows Update history
    $updateHistory = @()
    try {
        # Using WMI to get update history
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        
        if ($historyCount -gt 0) {
            $updateHistory = $searcher.QueryHistory(0, $historyCount) | 
                             Select-Object Title, Description, Date, @{
                                 Name="Operation"; 
                                 Expression={
                                     switch($_.Operation) {
                                         1 {"Installation"}
                                         2 {"Uninstallation"}
                                         3 {"Other"}
                                         default {"Unknown"}
                                     }
                                 }
                             }, @{
                                 Name="Status"; 
                                 Expression={
                                     switch($_.ResultCode) {
                                         0 {"Not Started"}
                                         1 {"In Progress"}
                                         2 {"Succeeded"}
                                         3 {"Succeeded With Errors"}
                                         4 {"Failed"}
                                         5 {"Aborted"}
                                         default {"Unknown"}
                                     }
                                 }
                             }
        }
    } catch {
        Write-DFIRLog "Error collecting Windows Update history: $_" "Warning"
    }
    
    return @{
        ComputerSystem = $computerSystem
        OperatingSystem = $operatingSystem
        BIOS = $bios
        Processors = $processors
        TimeZone = $timeZone
        BootTime = $bootTime
        Hotfixes = $hotfixes
        NetworkAdapters = $networkAdapters
        Drivers = $drivers
        InstalledSoftware = $software
        WindowsUpdateHistory = $updateHistory
    }
}

function Get-NetworkInformation {
    Write-DFIRLog "Collecting network information..." 
    
    # Get network connections
    $connections = @()
    try {
        $netstat = netstat -ano | Select-Object -Skip 4
        foreach ($line in $netstat) {
            if ($line -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(\d+)?$') {
                $proto = $matches[1]
                $localAddress = $matches[2]
                $foreignAddress = $matches[3]
                $state = if ($matches[4] -ne $null -and $matches[4] -ne '') { $matches[4] } else { "N/A" }
                $procId = if ($matches[5] -ne $null) { $matches[5] } else { $matches[4] }
                
                try {
                    $process = Get-Process -Id $procId -ErrorAction SilentlyContinue
                    $processName = if ($process) { $process.Name } else { "Unknown" }
                } catch {
                    $processName = "Unknown"
                }
                
                $connections += [PSCustomObject]@{
                    Protocol = $proto
                    LocalAddress = $localAddress
                    ForeignAddress = $foreignAddress
                    State = $state
                    PID = $procId
                    ProcessName = $processName
                }
            }
        }
    } catch {
        Write-DFIRLog "Error collecting network connections: $_" "Warning"
    }
    
    # Get listening ports
    $listeningPorts = @()
    try {
        $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
                          Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{
                              Name = "ProcessName"
                              Expression = {
                                  try {
                                      (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
                                  } catch {
                                      "Unknown"
                                  }
                              }
                          }
    } catch {
        Write-DFIRLog "Error collecting listening ports: $_" "Warning"
    }
    
    # Get SMB shares
    $smbShares = @()
    try {
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue | 
                    Select-Object Name, Path, Description, @{
                        Name = "AccessRights"; 
                        Expression = {
                            try {
                                (Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue | 
                                 Select-Object AccountName, AccessRight, AccessControlType) -join ", "
                            } catch {
                                "Access rights unavailable"
                            }
                        }
                    }
    } catch {
        Write-DFIRLog "Error collecting SMB shares: $_" "Warning"
    }
    
    # Get DNS cache
    $dnsCache = @()
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
                   Select-Object Name, Data, TimeToLive, Type
    } catch {
        Write-DFIRLog "Error collecting DNS cache: $_" "Warning"
    }
    
    return @{
        Connections = $connections
        ListeningPorts = $listeningPorts
        SMBShares = $smbShares
        DNSCache = $dnsCache
    }
}

function Get-UserInformation {
    Write-DFIRLog "Collecting user information..."
    
    # Get local users
    $localUsers = @()
    try {
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, 
                                     PasswordLastSet, LastLogon, SID, Description
    } catch {
        Write-DFIRLog "Error collecting local users: $_" "Warning"
    }
    
    # Get active user sessions
    $activeUsers = @()
    try {
        $activeUsers = quser 2>$null | ForEach-Object {
            $line = $_.Trim() -replace '\s+', ' '
            if ($line -notmatch "USERNAME") {
                $parts = $line.Split(' ')
                [PSCustomObject]@{
                    Username = $parts[0]
                    SessionName = if ($parts[1] -eq '>') { $parts[2] } else { $parts[1] }
                    State = if ($parts[1] -eq '>') { $parts[3] } else { $parts[2] }
                    IdleTime = if ($parts[1] -eq '>') { $parts[4] } else { $parts[3] }
                    LogonTime = if ($parts[1] -eq '>') { $parts[5..($parts.Length-1)] -join ' ' } else { $parts[4..($parts.Length-1)] -join ' ' }
                }
            }
        }
    } catch {
        Write-DFIRLog "Error collecting active user sessions: $_" "Warning"
    }
    
    # Get AutoRun entries
    $autoRuns = @()
    try {
        # Common autorun locations
        $autoRunLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($location in $autoRunLocations) {
            if (Test-Path $location) {
                $properties = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                if ($properties) {
                    foreach ($prop in $properties.PSObject.Properties) {
                        if ($prop.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                            $autoRuns += [PSCustomObject]@{
                                Location = $location
                                EntryName = $prop.Name
                                Command = $prop.Value
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Write-DFIRLog "Error collecting AutoRun entries: $_" "Warning"
    }
    
    # Get startup programs from startup folders
    $startupPrograms = @()
    try {
        $startupFolders = @(
            "$PrimaryUserRoamingAppData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Extension -eq '.lnk') {
                        try {
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($_.FullName)
                            
                            $startupPrograms += [PSCustomObject]@{
                                Name = $_.Name
                                Path = $_.FullName
                                Target = $shortcut.TargetPath
                                Arguments = $shortcut.Arguments
                                WorkingDirectory = $shortcut.WorkingDirectory
                                Type = "Shortcut"
                            }
                        } catch {
                            Write-DFIRLog "Error processing shortcut $($_.Name): $_" "Warning"
                        }
                    } else {
                        $startupPrograms += [PSCustomObject]@{
                            Name = $_.Name
                            Path = $_.FullName
                            Target = $_.FullName
                            Arguments = ""
                            WorkingDirectory = ""
                            Type = "File"
                        }
                    }
                }
            }
        }
    } catch {
        Write-DFIRLog "Error collecting startup programs: $_" "Warning"
    }
    
    # Get PowerShell history
    $psHistory = @()
    try {
        $historyPath = "$PrimaryUserRoamingAppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $historyPath) {
            $psHistory = Get-Content -Path $historyPath -ErrorAction SilentlyContinue | 
                        Select-Object -Last 100 | 
                        ForEach-Object {
                            [PSCustomObject]@{
                                Command = $_
                            }
                        }
        }
    } catch {
        Write-DFIRLog "Error collecting PowerShell history: $_" "Warning"
    }
    
    # Get RDP Sessions history
    $rdpSessions = @()
    try {
        # Query event logs for RDP session events
        $rdpLoginEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -ErrorAction SilentlyContinue | 
                          Where-Object { $_.Id -in @(21, 22, 23, 24, 25, 39, 40) } | 
                          Select-Object -First 100
        
        foreach ($event in $rdpLoginEvents) {
            $eventXml = [xml]$event.ToXml()
            $sessionData = [PSCustomObject]@{
                Time = $event.TimeCreated
                EventId = $event.Id
                Username = ""
                SourceIP = ""
                Action = ""
            }
            
            # Extract fields based on event ID
            switch ($event.Id) {
                21 { # Session logon
                    $sessionData.Action = "Logon"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                    $sessionData.SourceIP = $eventXml.Event.UserData.EventXML.Address
                }
                22 { # Session logout
                    $sessionData.Action = "Logoff"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                }
                23 { # Session disconnected
                    $sessionData.Action = "Disconnected"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                }
                24 { # Session reconnected
                    $sessionData.Action = "Reconnected"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                    $sessionData.SourceIP = $eventXml.Event.UserData.EventXML.Address
                }
                25 { # Session reconnected to another session
                    $sessionData.Action = "Reconnect to different session"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                }
                39 { # Session request/creation
                    $sessionData.Action = "Session created"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                    $sessionData.SourceIP = $eventXml.Event.UserData.EventXML.Address
                }
                40 { # Session connection/display initialization
                    $sessionData.Action = "Connection initialized"
                    $sessionData.Username = $eventXml.Event.UserData.EventXML.User
                }
            }
            
            $rdpSessions += $sessionData
        }
    } catch {
        Write-DFIRLog "Error collecting RDP session history: $_" "Warning"
    }
    
    return @{
        LocalUsers = $localUsers
        ActiveUsers = $activeUsers
        AutoRuns = $autoRuns
        StartupPrograms = $startupPrograms
        PowerShellHistory = $psHistory
        RDPSessions = $rdpSessions
    }
}

function Get-ProcessInformation {
    Write-DFIRLog "Collecting process information..."
    
    # Get running processes with detailed information
    $processes = @()
    try {
        $processes = Get-Process | Select-Object Id, ProcessName, Path, 
                                 @{Name="CommandLine"; Expression={
                                     (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$($_.Id)'" -ErrorAction SilentlyContinue).CommandLine
                                 }},
                                 @{Name="ParentProcessId"; Expression={
                                     (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = '$($_.Id)'" -ErrorAction SilentlyContinue).ParentProcessId
                                 }},
                                 StartTime, CPU, WorkingSet, Handles
    } catch {
        Write-DFIRLog "Error collecting process information: $_" "Warning"
    }
    
    # Get services
    $services = @()
    try {
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType,
                               @{Name="Path"; Expression={
                                   (Get-CimInstance -ClassName Win32_Service -Filter "Name = '$($_.Name)'" -ErrorAction SilentlyContinue).PathName
                               }}
    } catch {
        Write-DFIRLog "Error collecting services information: $_" "Warning"
    }
    
    return @{
        Processes = $processes
        Services = $services
    }
}

function Get-FileSystemInformation {
    Write-DFIRLog "Collecting file system information..."
    
    # Get disk information
    $disks = @()
    try {
        $disks = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, 
                                         @{Name="SizeGB"; Expression={[math]::Round($_.Size / 1GB, 2)}},
                                         @{Name="FreeSpaceGB"; Expression={[math]::Round($_.SizeRemaining / 1GB, 2)}},
                                         @{Name="PercentFree"; Expression={[math]::Round(($_.SizeRemaining / $_.Size) * 100, 2)}}
    } catch {
        Write-DFIRLog "Error collecting disk information: $_" "Warning"
    }
    
    # Get executable files in suspicious locations
    $suspiciousExecutables = @()
    try {
        $suspiciousLocations = @(
            "$PrimaryUserLocalAppData\Temp",
            "$PrimaryUserTemp",
            "$PrimaryUserDownloads"
        )
        
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                $suspiciousExecutables += Get-ChildItem -Path $location -Include "*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js" -File -ErrorAction SilentlyContinue | 
                                        Select-Object FullName, LastWriteTime, CreationTime, Length
            }
        }
    } catch {
        Write-DFIRLog "Error collecting suspicious executables: $_" "Warning"
    }
    
    return @{
        Disks = $disks
        SuspiciousExecutables = $suspiciousExecutables
    }
}

function Get-ScheduledTaskInfo {
    Write-DFIRLog "Collecting scheduled task information..."
    
    # Get scheduled tasks
    $scheduledTasks = @()
    try {
        $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName, TaskPath, State, 
                                                       @{Name="Actions"; Expression={
                                                           ($_.Actions | ForEach-Object {
                                                               if ($_.Execute) {
                                                                   "$($_.Execute) $($_.Arguments)"
                                                               } else {
                                                                   $_.Uri
                                                               }
                                                           }) -join "; "
                                                       }},
                                                       @{Name="Principal"; Expression={$_.Principal.UserId}}
    } catch {
        Write-DFIRLog "Error collecting scheduled tasks: $_" "Warning"
    }
    
    # Get suspicious scheduled tasks (non-Microsoft tasks in system paths)
    $suspiciousTasks = @()
    try {
        $suspiciousTasks = $scheduledTasks | Where-Object {
            ($_.Actions -match "C:\\Windows\\|%windir%|%SystemRoot%" -or 
             $_.Actions -match "C:\\Program Files\\|%ProgramFiles%" -or
             $_.Actions -match "powershell|cmd|wscript|cscript") -and
            (-not ($_.TaskPath -match "\\Microsoft\\"))
        }
    } catch {
        Write-DFIRLog "Error analyzing suspicious tasks: $_" "Warning"
    }
    
    return @{
        ScheduledTasks = $scheduledTasks
        SuspiciousTasks = $suspiciousTasks
    }
}

function Get-UsbDeviceInfo {
    Write-DFIRLog "Collecting USB device information..."
    
    # Get USB storage device history from registry
    $usbDevices = @()
    try {
        $usbDevices = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | 
                     Select-Object FriendlyName, PSChildName
    } catch {
        Write-DFIRLog "Error collecting USB device history: $_" "Warning"
    }
    
    return @{
        USBHistory = $usbDevices
    }
}

function Get-BrowserHistory {
    param (
        [int]$MaxRetries = 3,
        [int]$MaxEntries = 1000,
        [string]$CustomModulePath = $null,
        [switch]$Force
    )

    Write-DFIRLog "Collecting browser history..."
    
    $browserHistory = @{
        Chrome = @()
        Edge = @()
    }
    
    # Define module installation paths for verification
    $modulePaths = @(
        "$env:ProgramFiles\WindowsPowerShell\Modules\PSSQLite",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\PSSQLite",
        "$([Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules\PSSQLite",
        "$env:USERPROFILE\Documents\PowerShell\Modules\PSSQLite",
        "$([Environment]::GetFolderPath('MyDocuments'))\PowerShell\Modules\PSSQLite"
    )
    
    if ($CustomModulePath) {
        $modulePaths += $CustomModulePath
    }
    
    # Function to pause execution with progress display
    function Wait-WithProgress {
        param (
            [int]$Seconds,
            [string]$Activity
        )
        
        for ($i = 1; $i -le $Seconds; $i++) {
            $percent = ($i / $Seconds) * 100
            Write-Progress -Activity $Activity -Status "Please wait..." -PercentComplete $percent
            Start-Sleep -Seconds 1
        }
        
        Write-Progress -Activity $Activity -Completed
    }
    
    # Function to retry operations with exponential backoff
    function Invoke-WithRetry {
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [int]$MaxRetries = 3,
            [int]$InitialDelay = 2,
            [string]$OperationName = "Operation",
            [switch]$Silent
        )
        
        $retryCount = 0
        $delay = $InitialDelay
        $success = $false
        $result = $null
        $lastError = $null
        
        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                if ($retryCount -gt 0 -and -not $Silent) {
                    Write-DFIRLog "Retrying $OperationName (Attempt $retryCount of $MaxRetries)..." "Info"
                }
                
                $result = & $ScriptBlock
                $success = $true
                return $result
            }
            catch {
                $lastError = $_
                $retryCount++
                
                if (-not $Silent) {
                    Write-DFIRLog "$OperationName failed: $lastError" "Warning"
                }
                
                if ($retryCount -le $MaxRetries) {
                    if (-not $Silent) {
                        Write-DFIRLog "Waiting $delay seconds before retrying..." "Info"
                    }
                    
                    Wait-WithProgress -Seconds $delay -Activity "Waiting before retry"
                    $delay *= 2  # Exponential backoff
                }
                else {
                    if (-not $Silent) {
                        Write-DFIRLog "$OperationName failed after $MaxRetries attempts" "Warning"
                    }
                    throw $lastError
                }
            }
        }
    }
    
    # Function to safely remove items with retries
    function Remove-FileWithRetry {
        param (
            [string]$Path,
            [int]$Retries = 3
        )
        
        if (-not (Test-Path -Path $Path)) {
            return $true
        }
        
        $attempt = 0
        while ($attempt -lt $Retries) {
            try {
                Remove-Item -Path $Path -Force -ErrorAction Stop
                return $true
            }
            catch {
                $attempt++
                if ($attempt -ge $Retries) {
                    Write-DFIRLog "Failed to remove file $Path after $Retries attempts: $_" "Warning"
                    return $false
                }
                Start-Sleep -Seconds 1
            }
        }
        
        return $false
    }
    
    # Function to check if PSSQLite module is correctly installed and loaded
    function Test-PSSQLiteModule {
        # Check if module is available in PSModulePath
        $moduleLoaded = Get-Module -Name PSSQLite -ErrorAction SilentlyContinue
        $moduleAvailable = Get-Module -ListAvailable -Name PSSQLite -ErrorAction SilentlyContinue
        
        if ($moduleLoaded) {
            # Module is already loaded, test if it's functioning
            try {
                # Try to access a cmdlet from the module to verify it's working
                $null = Get-Command -Name Invoke-SqliteQuery -ErrorAction Stop
                return $true
            }
            catch {
                Write-DFIRLog "PSSQLite module is loaded but not functioning correctly" "Warning"
                return $false
            }
        }
        elseif ($moduleAvailable) {
            # Module is available but not loaded, try to import it
            try {
                Import-Module PSSQLite -Force -ErrorAction Stop
                $null = Get-Command -Name Invoke-SqliteQuery -ErrorAction Stop
                return $true
            }
            catch {
                Write-DFIRLog "Failed to import available PSSQLite module: $_" "Warning"
                return $false
            }
        }
        
        return $false
    }
    
    # Function to ensure NuGet provider is installed
    function Ensure-NuGetProvider {
        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-DFIRLog "Installing NuGet package provider..." "Info"
                
                # Try to install NuGet with retries
                Invoke-WithRetry -ScriptBlock {
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -MinimumVersion 2.8.5.201 -ErrorAction Stop | Out-Null
                } -MaxRetries 3 -OperationName "NuGet provider installation"
                
                # Verify installation
                if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                    throw "Failed to verify NuGet provider installation"
                }
                
                Write-DFIRLog "NuGet package provider installed successfully" "Info"
                
                # Register PSGallery if needed
                if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
                    Register-PSRepository -Default -ErrorAction SilentlyContinue
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
                }
            }
            else {
                Write-DFIRLog "NuGet package provider already installed" "Info"
            }
            
            return $true
        }
        catch {
            Write-DFIRLog "Error ensuring NuGet provider: $_" "Warning"
            return $false
        }
    }
    
    # Function to install PSSQLite module with verification
    function Install-PSSQLiteWithVerification {
        param (
            [switch]$Force
        )
        
        try {
            # Ensure NuGet is available first
            if (-not (Ensure-NuGetProvider)) {
                Write-DFIRLog "NuGet provider installation failed, cannot install PSSQLite" "Warning"
                return $false
            }
            
            Write-DFIRLog "Installing PSSQLite module..." "Info"
            
            # If force is specified, uninstall existing module first
            if ($Force) {
                try {
                    Uninstall-Module -Name PSSQLite -AllVersions -Force -ErrorAction SilentlyContinue
                    Remove-Module -Name PSSQLite -Force -ErrorAction SilentlyContinue
                    Write-DFIRLog "Removed existing PSSQLite module for clean installation" "Info"
                }
                catch {
                    Write-DFIRLog "Error removing existing module: $_" "Warning"
                    # Continue anyway
                }
            }
            
            # Try to install module with retries
            Invoke-WithRetry -ScriptBlock {
                Install-Module -Name PSSQLite -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck -ErrorAction Stop | Out-Null
            } -MaxRetries 3 -OperationName "PSSQLite module installation"
            
            # Wait for module to be fully installed
            Write-DFIRLog "Waiting for module installation to complete..." "Info"
            Wait-WithProgress -Seconds 5 -Activity "Finalizing module installation"
            
            # Verify the module files exist on disk
            $moduleFilesExist = $false
            foreach ($path in $modulePaths) {
                if (Test-Path -Path $path) {
                    Write-DFIRLog "PSSQLite module files found at: $path" "Info"
                    $moduleFilesExist = $true
                    break
                }
            }
            
            if (-not $moduleFilesExist) {
                throw "PSSQLite module installation completed but files not found on disk"
            }
            
            # Force re-import the module if it exists
            Remove-Module -Name PSSQLite -Force -ErrorAction SilentlyContinue
            Import-Module PSSQLite -Force -ErrorAction Stop
            
            # Check if the module is properly imported
            $moduleLoaded = Get-Module -Name PSSQLite -ErrorAction SilentlyContinue
            if (-not $moduleLoaded) {
                throw "PSSQLite module installation verified but module failed to import"
            }
            
            # Check if cmdlets from the module are available
            $null = Get-Command -Name Invoke-SqliteQuery -ErrorAction Stop
            
            Write-DFIRLog "PSSQLite module installed, imported and verified successfully" "Info"
            return $true
        }
        catch {
            Write-DFIRLog "Error installing PSSQLite module: $_" "Warning"
            return $false
        }
    }
    
    # Function to download file with verification and retries - using Invoke-WebRequest for compatibility
    function Download-FileWithRetry {
        param (
            [string]$Uri,
            [string]$OutFile,
            [int]$MaxRetries = 3,
            [int]$Timeout = 30,
            [switch]$UseBackupUri
        )
        
        # Define backup URLs for reliability
        $backupUris = @(
            "https://github.com/aspnet/Microsoft.Data.Sqlite/raw/main/src/libs/sqlite/x64/sqlite3.dll",
            "https://github.com/sqlitebrowser/sqlitebrowser/raw/master/src/sqlite3.c",
            "https://system.data.sqlite.org/downloads/1.0.118.0/sqlite-netFx-source-1.0.118.0.zip"
        )
        
        if ($UseBackupUri) {
            # Try a different backup URI
            $backupIndex = Get-Random -Minimum 0 -Maximum $backupUris.Count
            $Uri = $backupUris[$backupIndex]
            Write-DFIRLog "Using alternative download source: $Uri" "Info"
        }
        
        try {
            Write-DFIRLog "Downloading file from $Uri to $OutFile..." "Info"
            
            # Use TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Use Invoke-WebRequest with timeout parameter instead of WebClient
            $ProgressPreference = 'SilentlyContinue'  # Hide progress bar for faster downloads
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec $Timeout -ErrorAction Stop
            
            # Verify file was downloaded
            if (-not (Test-Path -Path $OutFile) -or (Get-Item -Path $OutFile).Length -eq 0) {
                throw "File download failed or file is empty"
            }
            
            Write-DFIRLog "File downloaded successfully to $OutFile" "Info"
            return $true
        }
        catch {
            Write-DFIRLog "Download failed: $_" "Warning"
            
            if ($MaxRetries -gt 0) {
                Write-DFIRLog "Retrying download with $MaxRetries attempts remaining..." "Info"
                
                if ($UseBackupUri -or (Get-Random -Minimum 1 -Maximum 3) -eq 1) {
                    # Try with backup URI sometimes
                    return Download-FileWithRetry -Uri $Uri -OutFile $OutFile -MaxRetries ($MaxRetries - 1) -Timeout $Timeout -UseBackupUri
                }
                else {
                    # Retry with same URI
                    return Download-FileWithRetry -Uri $Uri -OutFile $OutFile -MaxRetries ($MaxRetries - 1) -Timeout ($Timeout + 5)
                }
            }
            
            return $false
        }
    }
    
    # Function to verify and ensure .NET SQLite is available
    function Ensure-SQLiteDotNetAvailable {
        $dllPaths = @(
            # Try script directory first
            (Join-Path -Path $PSScriptRoot -ChildPath "System.Data.SQLite.dll"),
            # Try temp directory next
            (Join-Path -Path $env:TEMP -ChildPath "System.Data.SQLite.dll"),
            # Try program data location
            (Join-Path -Path $env:ProgramData -ChildPath "System.Data.SQLite.dll"),
            # Try Sentinel RSO path specifically
            "C:\ProgramData\Sentinel\Addons\SentinelRSO\Script\System.Data.SQLite.dll",
            # Try user profile location
            (Join-Path -Path $env:USERPROFILE -ChildPath "System.Data.SQLite.dll")
        )
        
        # First check if DLL already exists in any of the potential locations
        foreach ($dllPath in $dllPaths) {
            if (Test-Path -Path $dllPath) {
                try {
                    # Try to load the DLL to verify it works
                    Add-Type -Path $dllPath -ErrorAction Stop
                    Write-DFIRLog "SQLite .NET provider found and loaded from $dllPath" "Info"
                    return $dllPath
                }
                catch {
                    Write-DFIRLog "Found SQLite DLL at $dllPath but failed to load it: $_" "Warning"
                    # Continue to try other locations or download
                }
            }
        }
        
        # Determine where to save the downloaded DLL
        $savePath = $dllPaths[1]  # Default to temp directory
        
        # URLs to try
        $downloadUrls = @(
            "https://system.data.sqlite.org/downloads/1.0.118.0/sqlite-netFx46-static-binary-bundle-x64-2022-x64.zip",
            "https://github.com/SQLite-net/SQLite-net/raw/main/nuget/SQLite-net/lib/netstandard2.0/SQLite-net.dll",
            "https://github.com/aspnet/Microsoft.Data.Sqlite/raw/main/src/libs/sqlite/x64/sqlite3.dll"
        )
        
        # Try each URL
        foreach ($url in $downloadUrls) {
            $tempZipPath = "$env:TEMP\sqlite_temp_$(Get-Random).zip"
            
            if ($url.EndsWith(".zip")) {
                # For zip files, download and extract
                if (Download-FileWithRetry -Uri $url -OutFile $tempZipPath -MaxRetries 3 -Timeout 60) {
                    try {
                        # Extract the zip file
                        $extractPath = "$env:TEMP\sqlite_extract_$(Get-Random)"
                        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                        
                        # Use .NET to extract
                        Add-Type -AssemblyName System.IO.Compression.FileSystem
                        [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZipPath, $extractPath)
                        
                        # Find SQLite DLL in the extracted content
                        $extractedDll = Get-ChildItem -Path $extractPath -Recurse -Filter "System.Data.SQLite.dll" | Select-Object -First 1
                        
                        if ($extractedDll) {
                            # Copy to our save location
                            Copy-Item -Path $extractedDll.FullName -Destination $savePath -Force
                            Write-DFIRLog "Extracted SQLite DLL to $savePath" "Info"
                            
                            # Clean up temp files
                            Remove-FileWithRetry -Path $tempZipPath
                            Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                            
                            # Try to load the DLL
                            try {
                                Add-Type -Path $savePath -ErrorAction Stop
                                Write-DFIRLog "SQLite .NET provider downloaded, extracted and loaded successfully" "Info"
                                return $savePath
                            }
                            catch {
                                Write-DFIRLog "Error loading extracted SQLite DLL: $_" "Warning"
                                # Continue to try other URLs
                            }
                        }
                        else {
                            Write-DFIRLog "Could not find System.Data.SQLite.dll in extracted content" "Warning"
                            # Clean up and try next URL
                            Remove-FileWithRetry -Path $tempZipPath
                            Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        Write-DFIRLog "Error extracting ZIP file: $_" "Warning"
                        Remove-FileWithRetry -Path $tempZipPath
                    }
                }
            }
            else {
                # For direct DLL downloads
                if (Download-FileWithRetry -Uri $url -OutFile $savePath -MaxRetries 3 -Timeout 60) {
                    try {
                        # Try to load the DLL
                        Add-Type -Path $savePath -ErrorAction Stop
                        Write-DFIRLog "SQLite .NET provider downloaded and loaded successfully" "Info"
                        return $savePath
                    }
                    catch {
                        Write-DFIRLog "Error loading downloaded SQLite DLL: $_" "Warning"
                        # Continue to try other URLs
                    }
                }
            }
        }
        
        # If all downloads fail, try to use .NET embedded SQLite
        try {
            # Try to dynamically load SQLite from .NET
            Add-Type -TypeDefinition @"
using System;
using System.Data;
using System.Data.Common;
using Microsoft.Data.Sqlite;

public static class SQLiteHelper
{
    public static bool TestConnection(string dbPath)
    {
        try 
        {
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + dbPath + ";Mode=ReadOnly"))
            {
                connection.Open();
                return connection.State == ConnectionState.Open;
            }
        }
        catch 
        {
            return false;
        }
    }
}
"@ -ErrorAction Stop
            
            Write-DFIRLog "Using built-in Microsoft.Data.Sqlite provider instead" "Info"
            return ".NET"
        }
        catch {
            Write-DFIRLog "Failed to load embedded SQLite provider: $_" "Warning"
        }
        
        # Last resort: try to use PowerShell's own SQLite capabilities
        try {
            # Check if PowerShell can access SQLite via .NET Core
            $testScript = @"
try { 
    [Microsoft.Data.Sqlite.SqliteConnection] | Out-Null
    return $true 
} catch { 
    return $false 
}
"@
            $psHasSQLite = Invoke-Expression $testScript
            
            if ($psHasSQLite) {
                Write-DFIRLog "PowerShell has built-in SQLite support" "Info"
                return "PS"
            }
        }
        catch {
            Write-DFIRLog "PowerShell does not have built-in SQLite support" "Warning"
        }
        
        return $null
    }
    
    # Function to convert WebKit timestamp to DateTime
    function ConvertFrom-WebKitTimestamp {
        param (
            [Parameter(Mandatory = $true)]
            [Int64]$WebkitTimestamp
        )
        
        try {
            if ($WebkitTimestamp -eq 0) {
                return $null
            }
            
            # Convert to DateTime (WebKit timestamp is microseconds since Jan 1, 1601)
            $epochAdjust = New-Object DateTime(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            return $epochAdjust.AddMilliseconds($WebkitTimestamp / 1000)
        }
        catch {
            # Return current date if conversion fails
            return Get-Date
        }
    }
    
    # Function to create a temporary copy of a database file with retries
    function Get-TemporaryDatabaseCopy {
        param (
            [Parameter(Mandatory = $true)]
            [string]$SourcePath,
            [int]$MaxRetries = 3,
            [int]$WaitTime = 2
        )
        
        try {
            # Create a temporary file path with random name to avoid conflicts
            $tempDbPath = "$env:TEMP\dfir_temp_db_$(Get-Random).db"
            
            if (-not (Test-Path -Path $SourcePath)) {
                Write-DFIRLog "Database file not found: $SourcePath" "Warning"
                return $null
            }
            
            # Try to copy the file (it may be locked by the browser)
            $retryCount = 0
            $success = $false
            
            while (-not $success -and $retryCount -lt $MaxRetries) {
                try {
                    Copy-Item -Path $SourcePath -Destination $tempDbPath -Force -ErrorAction Stop
                    $success = $true
                }
                catch {
                    $retryCount++
                    
                    if ($retryCount -ge $MaxRetries) {
                        Write-DFIRLog "Failed to copy database after $MaxRetries attempts: $_" "Warning"
                        
                        # Try a different approach as last resort - use Volume Shadow Copy
                        try {
                            Write-DFIRLog "Attempting to create shadow copy of database..." "Info"
                            
                            # Create temp folder for shadow copy
                            $shadowFolder = "$env:TEMP\dfir_shadow_$(Get-Random)"
                            New-Item -Path $shadowFolder -ItemType Directory -Force | Out-Null
                            
                            # Use robocopy to try to copy the locked file
                            $robocopyArgs = @(
                                "`"$(Split-Path -Parent $SourcePath)`"",
                                "`"$shadowFolder`"",
                                "`"$(Split-Path -Leaf $SourcePath)`"",
                                "/B",  # Backup mode for locked files
                                "/R:3", # Retry 3 times
                                "/W:1", # Wait 1 second between retries
                                "/NP",  # No progress
                                "/NFL", # No file list
                                "/NDL"  # No directory list
                            )
                            
                            $robocopyResult = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -Wait -PassThru
                            
                            if ($robocopyResult.ExitCode -lt 8) {
                                # Robocopy successful (exit codes 0-7 indicate success with various warnings)
                                $shadowFile = Join-Path -Path $shadowFolder -ChildPath (Split-Path -Leaf $SourcePath)
                                
                                if (Test-Path -Path $shadowFile) {
                                    Copy-Item -Path $shadowFile -Destination $tempDbPath -Force -ErrorAction Stop
                                    Remove-Item -Path $shadowFolder -Recurse -Force -ErrorAction SilentlyContinue
                                    $success = $true
                                }
                                else {
                                    throw "Shadow copy succeeded but file not found"
                                }
                            }
                            else {
                                throw "Robocopy failed with exit code $($robocopyResult.ExitCode)"
                            }
                        }
                        catch {
                            Write-DFIRLog "Shadow copy attempt failed: $_" "Warning"
                            return $null
                        }
                    }
                    else {
                        Write-DFIRLog "Retrying database copy (Attempt $retryCount of $MaxRetries)..." "Info"
                        Start-Sleep -Seconds $WaitTime
                        $WaitTime *= 2  # Exponential backoff
                    }
                }
            }
            
            # Verify the copy worked and is readable
            if (Test-Path -Path $tempDbPath) {
                $fileInfo = Get-Item -Path $tempDbPath
                
                if ($fileInfo.Length -gt 0) {
                    return $tempDbPath
                }
                else {
                    Write-DFIRLog "Created database copy is empty" "Warning"
                    Remove-FileWithRetry -Path $tempDbPath
                    return $null
                }
            }
            
            return $null
        }
        catch {
            Write-DFIRLog "Error creating temporary database copy: $_" "Warning"
            return $null
        }
    }
    
    # Function to query browser history with various methods
    function Get-SQLiteBrowserHistory {
        param (
            [Parameter(Mandatory = $true)]
            [string]$DatabasePath,
            [Parameter(Mandatory = $false)]
            [int]$MaxEntries = 1000,
            [Parameter(Mandatory = $false)]
            [int]$MaxRetries = 2
        )
        
        $results = @()
        $methodsAttempted = @()
        
        # SQL query to extract browser history - same for all methods
        $query = @"
SELECT 
    urls.url as URL,
    urls.title as Title,
    urls.visit_count as VisitCount,
    MAX(visits.visit_time) as LastVisitTime
FROM urls
LEFT JOIN visits ON urls.id = visits.url
GROUP BY urls.url
ORDER BY LastVisitTime DESC
LIMIT $MaxEntries;
"@
        
        # Create a temporary copy of the database
        $tempDbPath = Get-TemporaryDatabaseCopy -SourcePath $DatabasePath -MaxRetries 3
        if ($null -eq $tempDbPath) {
            Write-DFIRLog "Failed to create a temporary copy of the database" "Warning"
            return $results
        }
        
        # Method 1: Try to use PSSQLite module (preferred method)
        if (Test-PSSQLiteModule) {
            try {
                Write-DFIRLog "Using PSSQLite module to query history" "Info"
                $methodsAttempted += "PSSQLite Module"
                
                $moduleResults = Invoke-WithRetry -ScriptBlock {
                    Invoke-SqliteQuery -DataSource $tempDbPath -Query $query -ErrorAction Stop
                } -MaxRetries $MaxRetries -OperationName "SQLite Query" -Silent
                
                $results = $moduleResults | ForEach-Object {
                    $lastVisitTime = if ($_.LastVisitTime) {
                        ConvertFrom-WebKitTimestamp -WebkitTimestamp $_.LastVisitTime
                    }
                    else {
                        Get-Date
                    }
                    
                    [PSCustomObject]@{
                        URL        = $_.URL
                        Title      = if ([string]::IsNullOrEmpty($_.Title)) { "No Title" } else { $_.Title }
                        VisitCount = $_.VisitCount
                        LastVisit  = $lastVisitTime.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                }
                
                # If we got results, return them
                if ($results.Count -gt 0) {
                    Write-DFIRLog "Successfully retrieved $($results.Count) history entries using PSSQLite module" "Info"
                    Remove-FileWithRetry -Path $tempDbPath
                    return $results
                }
                else {
                    Write-DFIRLog "PSSQLite query returned no results, trying fallback method" "Warning"
                }
            }
            catch {
                Write-DFIRLog "Error using PSSQLite module: $_" "Warning"
                # Continue to fallback method
            }
        }
        else {
            Write-DFIRLog "PSSQLite module not available, attempting to install" "Info"
            
            # Try to install the module first
            if (Install-PSSQLiteWithVerification -Force) {
                try {
                    Write-DFIRLog "Installed PSSQLite module, attempting to use it" "Info"
                    $methodsAttempted += "PSSQLite Module (Freshly Installed)"
                    
                    $moduleResults = Invoke-SqliteQuery -DataSource $tempDbPath -Query $query -ErrorAction Stop
                    
                    $results = $moduleResults | ForEach-Object {
                        $lastVisitTime = if ($_.LastVisitTime) {
                            ConvertFrom-WebKitTimestamp -WebkitTimestamp $_.LastVisitTime
                        }
                        else {
                            Get-Date
                        }
                        
                        [PSCustomObject]@{
                            URL        = $_.URL
                            Title      = if ([string]::IsNullOrEmpty($_.Title)) { "No Title" } else { $_.Title }
                            VisitCount = $_.VisitCount
                            LastVisit  = $lastVisitTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                    }
                    
                    # If we got results, return them
                    if ($results.Count -gt 0) {
                        Write-DFIRLog "Successfully retrieved $($results.Count) history entries using freshly installed PSSQLite module" "Info"
                        Remove-FileWithRetry -Path $tempDbPath
                        return $results
                    }
                    else {
                        Write-DFIRLog "PSSQLite query returned no results, trying fallback method" "Warning"
                    }
                }
                catch {
                    Write-DFIRLog "Error using freshly installed PSSQLite module: $_" "Warning"
                    # Continue to fallback method
                }
            }
            else {
                Write-DFIRLog "Failed to install PSSQLite module, trying fallback method" "Warning"
            }
        }
        
        # Method 2: Try to use .NET SQLite directly using fallback DLL
        $methodsAttempted += ".NET SQLite"
        Write-DFIRLog "Attempting to use .NET SQLite directly" "Info"
        
        $sqliteDllPath = Ensure-SQLiteDotNetAvailable
        
        if ($sqliteDllPath) {
            try {
                # If we got a string instead of a full path, it's a special case
                if ($sqliteDllPath -eq ".NET" -or $sqliteDllPath -eq "PS") {
                    # Using built-in .NET capabilities
                    Write-DFIRLog "Using built-in .NET SQLite capabilities" "Info"
                    
                    try {
                        # Try to use built-in method
                        $dbInfo = Get-Item $DatabasePath
                        
                        # Return minimal info about the history database itself
                        $results += [PSCustomObject]@{
                            URL        = "chrome://history or edge://history"
                            Title      = "Browser History (Access via browser interface)"
                            VisitCount = 1
                            LastVisit  = $dbInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        Write-DFIRLog "Generated fallback history entry using file info" "Warning"
                    }
                    catch {
                        Write-DFIRLog "Error using built-in .NET SQLite: $_" "Warning"
                    }
                }
                else {
                    # We have a specific DLL path to use
                    try {
                        # Try to load the DLL
                        Add-Type -Path $sqliteDllPath -ErrorAction Stop
                        
                        # Use the loaded DLL to query database
                        $connectionString = "Data Source=$tempDbPath;Version=3;Read Only=True;"
                        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                        $connection.Open()
                        $command = $connection.CreateCommand()
                        $command.CommandText = $query
                        $reader = $command.ExecuteReader()
                        $dataTable = New-Object System.Data.DataTable
                        $dataTable.Load($reader)
                        
                        foreach ($row in $dataTable.Rows) {
                            $lastVisitTime = if ($row["LastVisitTime"]) {
                                ConvertFrom-WebKitTimestamp -WebkitTimestamp ([Int64]$row["LastVisitTime"])
                            }
                            else {
                                Get-Date
                            }
                            
                            $results += [PSCustomObject]@{
                                URL        = $row["URL"]
                                Title      = if ([string]::IsNullOrEmpty($row["Title"])) { "No Title" } else { $row["Title"] }
                                VisitCount = $row["VisitCount"]
                                LastVisit  = $lastVisitTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        }
                        
                        $connection.Close()
                        
                        # If we got results, return them
                        if ($results.Count -gt 0) {
                            Write-DFIRLog "Successfully retrieved $($results.Count) history entries using .NET SQLite DLL" "Info"
                            Remove-FileWithRetry -Path $tempDbPath
                            return $results
                        }
                    }
                    catch {
                        Write-DFIRLog "Error using .NET SQLite DLL: $_" "Warning"
                    }
                }
            }
            catch {
                Write-DFIRLog "General error in .NET SQLite access: $_" "Warning"
            }
        }
        
        # Method 3: Last resort - use PowerShell with direct file access
        $methodsAttempted += "PowerShell Direct"
        Write-DFIRLog "Trying PowerShell direct access as last resort" "Info"
        
        try {
            # Get file info as minimal metadata
            $dbInfo = Get-Item $DatabasePath
            
            # Return minimal info about the history database itself
            $results += [PSCustomObject]@{
                URL        = "chrome://history or edge://history"
                Title      = "Browser History (Access via browser interface)"
                VisitCount = 1
                LastVisit  = $dbInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            Write-DFIRLog "Generated fallback history entry using file info" "Warning"
        }
        catch {
            Write-DFIRLog "Error using PowerShell direct access: $_" "Warning"
        }
        
        # Clean up temp database copy regardless of success
        if ($tempDbPath -and (Test-Path -Path $tempDbPath)) {
            Remove-FileWithRetry -Path $tempDbPath
        }
        
        # If we attempted multiple methods but still have no results, leave a diagnostic entry
        if ($results.Count -eq 0 -and $methodsAttempted.Count -gt 0) {
            $methodList = $methodsAttempted -join ", "
            $results += [PSCustomObject]@{
                URL        = "N/A"
                Title      = "Browser history extraction failed for all methods: $methodList"
                VisitCount = 0
                LastVisit  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
        
        return $results
    }
    
    # Try to install module first with verification
    if ($Force) {
        Write-DFIRLog "Forcing reinstallation of PSSQLite module (if exists)" "Info"
        Install-PSSQLiteWithVerification -Force | Out-Null
    }
    else {
        # Check if module needs to be installed
        if (-not (Test-PSSQLiteModule)) {
            Write-DFIRLog "PSSQLite module not properly loaded, attempting to install/import" "Info"
            Install-PSSQLiteWithVerification | Out-Null
        }
        else {
            Write-DFIRLog "PSSQLite module verified as working" "Info"
        }
    }
    
    # For Chrome browser - get browser history from SQLite database
    $chromeHistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    # Check if PrimaryUserLocalAppData is defined (in case this is used within another script)
    if (Get-Variable -Name PrimaryUserLocalAppData -ErrorAction SilentlyContinue) {
        $chromeHistoryPath = "$PrimaryUserLocalAppData\Google\Chrome\User Data\Default\History"
    }
    
    try {
        if (Test-Path -Path $chromeHistoryPath) {
            Write-DFIRLog "Extracting Chrome history..." "Info"
            $browserHistory.Chrome = Get-SQLiteBrowserHistory -DatabasePath $chromeHistoryPath -MaxEntries $MaxEntries
            Write-DFIRLog "Found $($browserHistory.Chrome.Count) Chrome history entries" "Info"
        }
        else {
            Write-DFIRLog "Chrome history database not found at $chromeHistoryPath" "Warning"
            
            # Try to find Chrome in Program Files (might be a different install location)
            $chromePaths = @(
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
                "${env:ProgramFiles(x86)}\Google\Chrome\User Data\Default\History",
                "$env:ProgramFiles\Google\Chrome\User Data\Default\History",
                "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
            )
            
            foreach ($path in $chromePaths) {
                if (Test-Path -Path $path) {
                    Write-DFIRLog "Found alternative Chrome history at $path" "Info"
                    $browserHistory.Chrome = Get-SQLiteBrowserHistory -DatabasePath $path -MaxEntries $MaxEntries
                    Write-DFIRLog "Found $($browserHistory.Chrome.Count) Chrome history entries from alternative location" "Info"
                    break
                }
            }
            
            if ($browserHistory.Chrome.Count -eq 0) {
                $browserHistory.Chrome = @([PSCustomObject]@{
                        URL        = "N/A"
                        Title      = "Chrome not installed or history not available"
                        VisitCount = 0
                        LastVisit  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    })
            }
        }
    }
    catch {
        Write-DFIRLog "Error collecting Chrome history: $_" "Warning"
        $browserHistory.Chrome = @([PSCustomObject]@{
                URL        = "Error"
                Title      = "Failed to collect Chrome history: $_"
                VisitCount = 0
                LastVisit  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            })
    }
    
    # For Edge browser - get browser history from SQLite database
    $edgeHistoryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    # Check if PrimaryUserLocalAppData is defined (in case this is used within another script)
    if (Get-Variable -Name PrimaryUserLocalAppData -ErrorAction SilentlyContinue) {
        $edgeHistoryPath = "$PrimaryUserLocalAppData\Microsoft\Edge\User Data\Default\History"
    }
    
    try {
        if (Test-Path -Path $edgeHistoryPath) {
            Write-DFIRLog "Extracting Edge history..." "Info"
            $browserHistory.Edge = Get-SQLiteBrowserHistory -DatabasePath $edgeHistoryPath -MaxEntries $MaxEntries
            Write-DFIRLog "Found $($browserHistory.Edge.Count) Edge history entries" "Info"
        }
        else {
            Write-DFIRLog "Edge history database not found at $edgeHistoryPath" "Warning"
            
            # Try to find Edge in Program Files (might be a different install location)
            $edgePaths = @(
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
                "${env:ProgramFiles(x86)}\Microsoft\Edge\User Data\Default\History",
                "$env:ProgramFiles\Microsoft\Edge\User Data\Default\History",
                "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
            )
            
            foreach ($path in $edgePaths) {
                if (Test-Path -Path $path) {
                    Write-DFIRLog "Found alternative Edge history at $path" "Info"
                    $browserHistory.Edge = Get-SQLiteBrowserHistory -DatabasePath $path -MaxEntries $MaxEntries
                    Write-DFIRLog "Found $($browserHistory.Edge.Count) Edge history entries from alternative location" "Info"
                    break
                }
            }
            
            if ($browserHistory.Edge.Count -eq 0) {
                $browserHistory.Edge = @([PSCustomObject]@{
                        URL        = "N/A"
                        Title      = "Edge not installed or history not available"
                        VisitCount = 0
                        LastVisit  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    })
            }
        }
    }
    catch {
        Write-DFIRLog "Error collecting Edge history: $_" "Warning"
        $browserHistory.Edge = @([PSCustomObject]@{
                URL        = "Error"
                Title      = "Failed to collect Edge history: $_"
                VisitCount = 0
                LastVisit  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            })
    }
    
    # Return the combined browser history
    return $browserHistory
}

function Get-DirectoryListings {
    Write-DFIRLog "Collecting directory listings..."
    
    $directoryInfo = @{}
    $directories = @(
        @{Name = "Windows"; Path = "C:\Windows"},
        @{Name = "WindowsPrefetch"; Path = "C:\Windows\Prefetch"},
        @{Name = "WindowsTemp"; Path = "C:\Windows\Temp"},
        @{Name = "ProgramFiles"; Path = "C:\Program Files"},
        @{Name = "ProgramFilesX86"; Path = "C:\Program Files (x86)"},
        @{Name = "ProgramData"; Path = "C:\ProgramData"},
        @{Name = "RecycleBin"; Path = "C:\`$Recycle.Bin"}  # Recycle Bin path
    )
    
    # User profile specific directories
    $userDirs = @(
        @{Name = "UserProfiles"; Path = "C:\Users"},
        @{Name = "UserDesktop"; Path = $PrimaryUserDesktop},
        @{Name = "UserDocuments"; Path = $PrimaryUserDocuments},
        @{Name = "UserDownloads"; Path = $PrimaryUserDownloads},
        @{Name = "UserRecent"; Path = "$PrimaryUserRoamingAppData\Microsoft\Windows\Recent"},
        @{Name = "UserAppDataLocal"; Path = $PrimaryUserLocalAppData},
        @{Name = "UserAppDataRoaming"; Path = $PrimaryUserRoamingAppData}
    )
    
    # Combine both lists
    $allDirectories = $directories + $userDirs
    
    # Collect information for each directory
    foreach ($dir in $allDirectories) {
        try {
            Write-DFIRLog "Collecting files for $($dir.Path)..." "Info"
            if (Test-Path -Path $dir.Path) {
                # Get directory listing
                $files = Get-ChildItem -Path $dir.Path -Force -ErrorAction SilentlyContinue | 
                         Select-Object Name, Length, CreationTime, LastWriteTime, LastAccessTime, Attributes, 
                                       @{Name="Type"; Expression={if ($_.PSIsContainer) {"Directory"} else {"File"}}}
                
                # Store in hashtable with directory name as key
                $directoryInfo[$dir.Name] = @{
                    Path = $dir.Path
                    Files = $files
                    Count = ($files | Measure-Object).Count
                    SizeTotal = ($files | Where-Object { !$_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
                }
            } else {
                $directoryInfo[$dir.Name] = @{
                    Path = $dir.Path
                    Files = @()
                    Count = 0
                    SizeTotal = 0
                    Error = "Path not found or access denied"
                }
                Write-DFIRLog "Path not found or access denied: $($dir.Path)" "Warning"
            }
        } catch {
            $directoryInfo[$dir.Name] = @{
                Path = $dir.Path
                Files = @()
                Count = 0
                SizeTotal = 0
                Error = $_.Exception.Message
            }
            Write-DFIRLog "Error collecting directory listing for $($dir.Path): $_" "Warning"
        }
    }
    
    return $directoryInfo
}

function Generate-HTMLReport {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    Write-DFIRLog "Generating HTML report..."
    
    # Create HTML content with CSS styling
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DFIR Analysis Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            width: 95%;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #333;
            color: #fff;
            padding: 20px;
            text-align: center;
        }
        .section {
            margin-bottom: 30px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .section-header {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            font-size: 1.2em;
            margin: 0;
        }
        .section-content {
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 17px;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: #ccc;
        }
        .tabcontent {
            display: none;
            padding: 6px 12px;
            border: 1px solid #ccc;
            border-top: none;
        }
        .warning {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px;
            margin-bottom: 5px;
        }
        .danger {
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 10px;
            margin-bottom: 5px;
        }
        
        /* Browser History Table Styles */
        .title-cell {
            max-width: 350px;
            position: relative;
            overflow: hidden;
        }
        .title-container {
            width: 100%;
            overflow-x: auto;
            white-space: nowrap;
            padding-bottom: 5px;
        }
        .url-cell {
            max-width: 400px;
            position: relative;
            overflow: hidden;
        }
        .url-container {
            width: 100%;
            overflow-x: auto;
            white-space: nowrap;
            padding-bottom: 5px;
        }
        /* Make browser history tables more readable */
        #chrome_history table, #edge_history table {
            table-layout: fixed;
        }
        #chrome_history th:first-child, #edge_history th:first-child {
            width: 150px; /* Date column width */
        }
        #chrome_history th:nth-child(2), #edge_history th:nth-child(2) {
            width: 250px; /* Title column width - increased from 200px */
        }
        #chrome_history th:last-child, #edge_history th:last-child {
            width: 80px; /* Visit count column width */
        }
    </style>
</head>
<body>
    <header>
        <h1>Incident Response Data Collection Report</h1>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </header>
    <div class="container">
"@

    # System Information Section
    $html += @"
        <div class="section">
            <h2 class="section-header">System Information</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'sysinfo')">Basic Info</button>
                    <button class="tablinks" onclick="openTab(event, 'netadapters')">Network Adapters</button>
                    <button class="tablinks" onclick="openTab(event, 'drivers')">Drivers</button>
                    <button class="tablinks" onclick="openTab(event, 'software')">Installed Software</button>
                    <button class="tablinks" onclick="openTab(event, 'updates')">Windows Updates</button>
                    <button class="tablinks" onclick="openTab(event, 'usbdevices')">USB Devices</button>
                </div>
                
                <div id="sysinfo" class="tabcontent">
                    <h3>System Information</h3>
                    <table>
                    <tr><td><strong>Computer Name:</strong></td><td>$($Data.SystemInfo.ComputerSystem.Name)</td></tr>
                    <tr><td><strong>Operating System:</strong></td><td>$($Data.SystemInfo.OperatingSystem.Caption) $($Data.SystemInfo.OperatingSystem.Version)</td></tr>
                    <tr><td><strong>OS Installation Date:</strong></td><td>$($Data.SystemInfo.OperatingSystem.InstallDate)</td></tr>
                    <tr><td><strong>Manufacturer:</strong></td><td>$($Data.SystemInfo.ComputerSystem.Manufacturer)</td></tr>
                    <tr><td><strong>Model:</strong></td><td>$($Data.SystemInfo.ComputerSystem.Model)</td></tr>
                    <tr><td><strong>BIOS Version:</strong></td><td>$($Data.SystemInfo.BIOS.Name)</td></tr>
                    <tr><td><strong>Processor:</strong></td><td>$($Data.SystemInfo.Processors[0].Name)</td></tr>
                    <tr><td><strong>Memory:</strong></td><td>$([math]::Round($Data.SystemInfo.ComputerSystem.TotalPhysicalMemory / 1GB, 2)) GB</td></tr>
                    <tr><td><strong>Last Boot Time:</strong></td><td>$($Data.SystemInfo.BootTime)</td></tr>
                    </table>
                </div>

                <div id="netadapters" class="tabcontent">
                    <h3>Network Adapters</h3>
                    <table>
                        <tr>
                            <th>Description</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Gateway</th>
                            <th>DNS Servers</th>
                        </tr>
"@

    # Add network adapter information
    foreach ($adapter in $Data.SystemInfo.NetworkAdapters) {
        $ipAddresses = if ($adapter.IPAddress) { ($adapter.IPAddress -join ", ") } else { "None" }
        $gateways = if ($adapter.DefaultIPGateway) { ($adapter.DefaultIPGateway -join ", ") } else { "None" }
        $dnsServers = if ($adapter.DNSServerSearchOrder) { ($adapter.DNSServerSearchOrder -join ", ") } else { "None" }
        $html += @"
                        <tr>
                            <td>$($adapter.Description)</td>
                            <td>$ipAddresses</td>
                            <td>$($adapter.MACAddress)</td>
                            <td>$gateways</td>
                            <td>$dnsServers</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="drivers" class="tabcontent">
                    <h3>Installed Drivers</h3>
                    <table>
                        <tr>
                            <th>Device Name</th>
                            <th>Manufacturer</th>
                            <th>Version</th>
                            <th>Date</th>
                            <th>Signed</th>
                            <th>Status</th>
                        </tr>
"@

    # Add driver information
    foreach ($driver in $Data.SystemInfo.Drivers) {
        $html += @"
                        <tr>
                            <td>$($driver.DeviceName)</td>
                            <td>$($driver.Manufacturer)</td>
                            <td>$($driver.DriverVersion)</td>
                            <td>$($driver.DriverDate)</td>
                            <td>$($driver.IsSigned)</td>
                            <td>$($driver.Status)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="software" class="tabcontent">
                    <h3>Installed Software</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Version</th>
                            <th>Publisher</th>
                            <th>Install Date</th>
                            <th>Architecture</th>
                        </tr>
"@

    # Add installed software information
    foreach ($app in $Data.SystemInfo.InstalledSoftware) {
        $html += @"
                        <tr>
                            <td>$($app.DisplayName)</td>
                            <td>$($app.DisplayVersion)</td>
                            <td>$($app.Publisher)</td>
                            <td>$($app.InstallDate)</td>
                            <td>$($app.Architecture)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="updates" class="tabcontent">
                    <h3>Windows Update History</h3>
                    <table>
                        <tr>
                            <th>Title</th>
                            <th>Date</th>
                            <th>Operation</th>
                            <th>Status</th>
                        </tr>
"@

    # Add Windows Update history information
    foreach ($update in $Data.SystemInfo.WindowsUpdateHistory) {
        $html += @"
                        <tr>
                            <td>$($update.Title)</td>
                            <td>$($update.Date)</td>
                            <td>$($update.Operation)</td>
                            <td>$($update.Status)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="usbdevices" class="tabcontent">
                    <h3>USB Storage History</h3>
                    <table>
                        <tr>
                            <th>Device Name</th>
                            <th>Device ID</th>
                        </tr>
"@

    # Add USB device information
    foreach ($usb in $Data.UsbInfo.USBHistory) {
        $html += @"
                        <tr>
                            <td>$($usb.FriendlyName)</td>
                            <td>$($usb.PSChildName)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
        </div>
"@

    # Network Connections Section
    $html += @"
        <div class="section">
            <h2 class="section-header">Network Connections</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'connections')">Active Connections</button>
                    <button class="tablinks" onclick="openTab(event, 'listening')">Listening Ports</button>
                    <button class="tablinks" onclick="openTab(event, 'smbshares')">SMB Shares</button>
                    <button class="tablinks" onclick="openTab(event, 'dnscache')">DNS Cache</button>
                </div>

                <div id="connections" class="tabcontent">
                    <h3>Active Network Connections</h3>
                    <table>
                        <tr>
                            <th>Protocol</th>
                            <th>Local Address</th>
                            <th>Foreign Address</th>
                            <th>State</th>
                            <th>Process</th>
                        </tr>
"@

    # Add connection information
    foreach ($conn in $Data.NetworkInfo.Connections) {
        $html += @"
                        <tr>
                            <td>$($conn.Protocol)</td>
                            <td>$($conn.LocalAddress)</td>
                            <td>$($conn.ForeignAddress)</td>
                            <td>$($conn.State)</td>
                            <td>$($conn.ProcessName) ($($conn.PID))</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="listening" class="tabcontent">
                    <h3>Listening Ports</h3>
                    <table>
                        <tr>
                            <th>Local Address</th>
                            <th>Local Port</th>
                            <th>Process</th>
                        </tr>
"@

    # Add listening ports information
    foreach ($port in $Data.NetworkInfo.ListeningPorts) {
        $html += @"
                        <tr>
                            <td>$($port.LocalAddress)</td>
                            <td>$($port.LocalPort)</td>
                            <td>$($port.ProcessName) ($($port.OwningProcess))</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="smbshares" class="tabcontent">
                    <h3>SMB Shares</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Path</th>
                            <th>Description</th>
                            <th>Access Rights</th>
                        </tr>
"@

    # Add SMB shares information
    foreach ($share in $Data.NetworkInfo.SMBShares) {
        $html += @"
                        <tr>
                            <td>$($share.Name)</td>
                            <td>$($share.Path)</td>
                            <td>$($share.Description)</td>
                            <td>$($share.AccessRights)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dnscache" class="tabcontent">
                    <h3>DNS Cache Entries</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Data</th>
                            <th>TTL</th>
                            <th>Type</th>
                        </tr>
"@

    # Add DNS cache information
    foreach ($entry in $Data.NetworkInfo.DNSCache) {
        $html += @"
                        <tr>
                            <td>$($entry.Name)</td>
                            <td>$($entry.Data)</td>
                            <td>$($entry.TimeToLive)</td>
                            <td>$($entry.Type)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
            </div>
        </div>
"@

    # Process Information Section
    $html += @"
        <div class="section">
            <h2 class="section-header">Process Information</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'processes')">Running Processes</button>
                    <button class="tablinks" onclick="openTab(event, 'services')">Services</button>
                    <button class="tablinks" onclick="openTab(event, 'tasks')">Scheduled Tasks</button>
                    <button class="tablinks" onclick="openTab(event, 'autoruns')">AutoRun Entries</button>
                    <button class="tablinks" onclick="openTab(event, 'startupitems')">Startup Items</button>
                </div>

                <div id="processes" class="tabcontent">
                    <h3>Running Processes</h3>
                    <table>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>Path</th>
                            <th>Parent PID</th>
                            <th>Start Time</th>
                        </tr>
"@

    # Add processes information
    foreach ($process in $Data.ProcessInfo.Processes) {
        $html += @"
                        <tr>
                            <td>$($process.Id)</td>
                            <td>$($process.ProcessName)</td>
                            <td>$($process.Path)</td>
                            <td>$($process.ParentProcessId)</td>
                            <td>$($process.StartTime)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="services" class="tabcontent">
                    <h3>Services</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Display Name</th>
                            <th>Status</th>
                            <th>Start Type</th>
                            <th>Path</th>
                        </tr>
"@

    # Add services information
    foreach ($service in $Data.ProcessInfo.Services) {
        $html += @"
                        <tr>
                            <td>$($service.Name)</td>
                            <td>$($service.DisplayName)</td>
                            <td>$($service.Status)</td>
                            <td>$($service.StartType)</td>
                            <td>$($service.Path)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="tasks" class="tabcontent">
                    <h3>Scheduled Tasks</h3>
                    <table>
                        <tr>
                            <th>Task Name</th>
                            <th>Path</th>
                            <th>State</th>
                            <th>Actions</th>
                            <th>User</th>
                        </tr>
"@

    # Add scheduled tasks information
    foreach ($task in $Data.TasksInfo.ScheduledTasks) {
        $html += @"
                        <tr>
                            <td>$($task.TaskName)</td>
                            <td>$($task.TaskPath)</td>
                            <td>$($task.State)</td>
                            <td>$($task.Actions)</td>
                            <td>$($task.Principal)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="autoruns" class="tabcontent">
                    <h3>AutoRun Entries</h3>
                    <table>
                        <tr>
                            <th>Location</th>
                            <th>Entry Name</th>
                            <th>Command</th>
                        </tr>
"@

    # Add autorun entries information
    foreach ($autorun in $Data.UserInfo.AutoRuns) {
        $html += @"
                        <tr>
                            <td>$($autorun.Location)</td>
                            <td>$($autorun.EntryName)</td>
                            <td>$($autorun.Command)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
                <div id="startupitems" class="tabcontent">
                    <h3>Startup Programs</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Target</th>
                            <th>Arguments</th>
                            <th>Type</th>
                        </tr>
"@

    # Add startup programs information
    foreach ($program in $Data.UserInfo.StartupPrograms) {
        $html += @"
                        <tr>
                            <td>$($program.Name)</td>
                            <td>$($program.Target)</td>
                            <td>$($program.Arguments)</td>
                            <td>$($program.Type)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
            </div>
        </div>
"@

    # User Information Section
    $html += @"
        <div class="section">
            <h2 class="section-header">User Information</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'users')">Local Users</button>
                    <button class="tablinks" onclick="openTab(event, 'activeusers')">Active Sessions</button>
                    <button class="tablinks" onclick="openTab(event, 'pshistory')">PowerShell History</button>
                    <button class="tablinks" onclick="openTab(event, 'rdpsessions')">RDP Sessions</button>
                </div>

                <div id="users" class="tabcontent">
                    <h3>Local Users</h3>
                    <table>
                        <tr>
                            <th>Username</th>
                            <th>Enabled</th>
                            <th>Password Required</th>
                            <th>Last Logon</th>
                        </tr>
"@

    # Add local users information
    foreach ($user in $Data.UserInfo.LocalUsers) {
        $html += @"
                        <tr>
                            <td>$($user.Name)</td>
                            <td>$($user.Enabled)</td>
                            <td>$($user.PasswordRequired)</td>
                            <td>$($user.LastLogon)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="activeusers" class="tabcontent">
                    <h3>Active User Sessions</h3>
                    <table>
                        <tr>
                            <th>Username</th>
                            <th>Session Name</th>
                            <th>State</th>
                            <th>Idle Time</th>
                            <th>Logon Time</th>
                        </tr>
"@

    # Add active users information
    foreach ($user in $Data.UserInfo.ActiveUsers) {
        $html += @"
                        <tr>
                            <td>$($user.Username)</td>
                            <td>$($user.SessionName)</td>
                            <td>$($user.State)</td>
                            <td>$($user.IdleTime)</td>
                            <td>$($user.LogonTime)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="pshistory" class="tabcontent">
                    <h3>PowerShell Command History</h3>
                    <table>
                        <tr>
                            <th>Command</th>
                        </tr>
"@

    # Add PowerShell history information
    foreach ($cmd in $Data.UserInfo.PowerShellHistory) {
        $html += @"
                        <tr>
                            <td>$($cmd.Command)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="rdpsessions" class="tabcontent">
                    <h3>RDP Session History</h3>
                    <table>
                        <tr>
                            <th>Time</th>
                            <th>Username</th>
                            <th>Action</th>
                            <th>Source IP</th>
                        </tr>
"@

    # Add RDP sessions information
    foreach ($session in $Data.UserInfo.RDPSessions) {
        $html += @"
                        <tr>
                            <td>$($session.Time)</td>
                            <td>$($session.Username)</td>
                            <td>$($session.Action)</td>
                            <td>$($session.SourceIP)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
            </div>
        </div>
"@

    # Directory Listings Section
    $html += @"
        <div class="section">
            <h2 class="section-header">Directory Listings</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'dir_windows')">Windows</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_prefetch')">Prefetch</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_wintemp')">Windows Temp</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_programfiles')">Program Files</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_programfilesx86')">Program Files (x86)</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_programdata')">ProgramData</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_recyclebin')">Recycle Bin</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_users')">Users</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_desktop')">Desktop</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_documents')">Documents</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_downloads')">Downloads</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_recent')">Recent Files</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_appdata_local')">AppData Local</button>
                    <button class="tablinks" onclick="openTab(event, 'dir_appdata_roaming')">AppData Roaming</button>
                </div>

                <div id="dir_windows" class="tabcontent">
                    <h3>Windows Directory ($($Data.DirectoryInfo["Windows"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["Windows"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["Windows"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["Windows"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_prefetch" class="tabcontent">
                    <h3>Prefetch Directory ($($Data.DirectoryInfo["WindowsPrefetch"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["WindowsPrefetch"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["WindowsPrefetch"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["WindowsPrefetch"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_wintemp" class="tabcontent">
                    <h3>Windows Temp Directory ($($Data.DirectoryInfo["WindowsTemp"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["WindowsTemp"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["WindowsTemp"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["WindowsTemp"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_programfiles" class="tabcontent">
                    <h3>Program Files Directory ($($Data.DirectoryInfo["ProgramFiles"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["ProgramFiles"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["ProgramFiles"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["ProgramFiles"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_programfilesx86" class="tabcontent">
                    <h3>Program Files (x86) Directory ($($Data.DirectoryInfo["ProgramFilesX86"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["ProgramFilesX86"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["ProgramFilesX86"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["ProgramFilesX86"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_programdata" class="tabcontent">
                    <h3>ProgramData Directory ($($Data.DirectoryInfo["ProgramData"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["ProgramData"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["ProgramData"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["ProgramData"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_recyclebin" class="tabcontent">
                    <h3>Recycle Bin ($($Data.DirectoryInfo["RecycleBin"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["RecycleBin"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["RecycleBin"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["RecycleBin"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_users" class="tabcontent">
                    <h3>Users Directory ($($Data.DirectoryInfo["UserProfiles"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserProfiles"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserProfiles"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserProfiles"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_desktop" class="tabcontent">
                    <h3>Desktop Directory ($($Data.DirectoryInfo["UserDesktop"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserDesktop"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserDesktop"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserDesktop"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_documents" class="tabcontent">
                    <h3>Documents Directory ($($Data.DirectoryInfo["UserDocuments"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserDocuments"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserDocuments"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserDocuments"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_downloads" class="tabcontent">
                    <h3>Downloads Directory ($($Data.DirectoryInfo["UserDownloads"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserDownloads"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserDownloads"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserDownloads"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_recent" class="tabcontent">
                    <h3>Recent Files ($($Data.DirectoryInfo["UserRecent"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserRecent"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserRecent"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserRecent"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_appdata_local" class="tabcontent">
                    <h3>AppData Local ($($Data.DirectoryInfo["UserAppDataLocal"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserAppDataLocal"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserAppDataLocal"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserAppDataLocal"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="dir_appdata_roaming" class="tabcontent">
                    <h3>AppData Roaming ($($Data.DirectoryInfo["UserAppDataRoaming"].Path))</h3>
                    <p>Item Count: $($Data.DirectoryInfo["UserAppDataRoaming"].Count) | 
                       Total Size: $([math]::Round($Data.DirectoryInfo["UserAppDataRoaming"].SizeTotal / 1MB, 2)) MB</p>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size (KB)</th>
                            <th>Created</th>
                            <th>Modified</th>
                            <th>Attributes</th>
                        </tr>
"@

    foreach ($file in $Data.DirectoryInfo["UserAppDataRoaming"].Files) {
        $sizeKB = if ($file.Length) { [math]::Round($file.Length / 1KB, 2) } else { "N/A" }
        $html += @"
                        <tr>
                            <td>$($file.Name)</td>
                            <td>$($file.Type)</td>
                            <td>$sizeKB</td>
                            <td>$($file.CreationTime)</td>
                            <td>$($file.LastWriteTime)</td>
                            <td>$($file.Attributes)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
                
            </div>
        </div>
"@

    # Browser History Section
    $html += @"
        <div class="section">
            <h2 class="section-header">Browser History</h2>
            <div class="section-content">
                <div class="tab">
                    <button class="tablinks" onclick="openTab(event, 'chrome_history')">Chrome</button>
                    <button class="tablinks" onclick="openTab(event, 'edge_history')">Edge</button>
                </div>

                <div id="chrome_history" class="tabcontent">
                    <h3>Google Chrome Browsing History</h3>
                    <p>Entry Count: $($Data.BrowserHistory.Chrome.Count)</p>
                    <table>
                        <tr>
                            <th>Last Visit Time</th>
                            <th>Title</th>
                            <th>URL</th>
                            <th>Visit Count</th>
                        </tr>
"@

    # Limit to top 1,000 entries, sorted by most recent date
    $chromeHistoryEntries = $Data.BrowserHistory.Chrome | 
                            Sort-Object -Property LastVisit -Descending | 
                            Select-Object -First 1000
    
    # Add Chrome history information
    foreach ($entry in $chromeHistoryEntries) {
        $html += @"
                        <tr>
                            <td>$($entry.LastVisit)</td>
                            <td class="title-cell"><div class="title-container">$($entry.Title)</div></td>
                            <td class="url-cell"><div class="url-container">$($entry.URL)</div></td>
                            <td>$($entry.VisitCount)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>

                <div id="edge_history" class="tabcontent">
                    <h3>Microsoft Edge Browsing History</h3>
                    <p>Entry Count: $($Data.BrowserHistory.Edge.Count)</p>
                    <table>
                        <tr>
                            <th>Last Visit Time</th>
                            <th>Title</th>
                            <th>URL</th>
                            <th>Visit Count</th>
                        </tr>
"@

    # Limit to top 1,000 entries, sorted by most recent date
    $edgeHistoryEntries = $Data.BrowserHistory.Edge | 
                          Sort-Object -Property LastVisit -Descending | 
                          Select-Object -First 1000
    
    # Add Edge history information
    foreach ($entry in $edgeHistoryEntries) {
        $html += @"
                        <tr>
                            <td>$($entry.LastVisit)</td>
                            <td class="title-cell">$($entry.Title)</td>
                            <td class="url-cell"><div class="url-container">$($entry.URL)</div></td>
                            <td>$($entry.VisitCount)</td>
                        </tr>
"@
    }

    $html += @"
                    </table>
                </div>
            </div>
        </div>
"@

    # Close the HTML document with JavaScript for tab functionality
    $html += @"
    </div>
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }

        // Initialize tabs by clicking the first tab button in each tab group
        document.addEventListener("DOMContentLoaded", function() {
            var tabGroups = document.getElementsByClassName("tab");
            for (var i = 0; i < tabGroups.length; i++) {
                var firstTab = tabGroups[i].getElementsByClassName("tablinks")[0];
                if (firstTab) {
                    firstTab.click();
                }
            }
        });
    </script>
</body>
</html>
"@

    # Write HTML to file
    $html | Out-File -FilePath $OutputPath -Encoding utf8
    
    return $OutputPath
}
#endregion

#region Main Execution
# Collect all data
Write-DFIRLog "Starting comprehensive data collection..."

# Gather all information using the collection functions
$allData = @{
    SystemInfo = Get-SystemInformation
    NetworkInfo = Get-NetworkInformation
    UserInfo = Get-UserInformation
    ProcessInfo = Get-ProcessInformation
    FileSystemInfo = Get-FileSystemInformation
    TasksInfo = Get-ScheduledTaskInfo
    UsbInfo = Get-UsbDeviceInfo
    DirectoryInfo = Get-DirectoryListings
    BrowserHistory = Get-BrowserHistory
}

# Generate the HTML report
$reportPath = Generate-HTMLReport -Data $allData -OutputPath $OutputPath

# Display completion message
Write-DFIRLog "DFIR collection complete!" "Info"
Write-DFIRLog "Report saved to: $reportPath" "Info"

# Open the report if requested
if ($OpenReport) {
    try {
        Write-DFIRLog "Opening report..." "Info"
        Start-Process $reportPath
    } catch {
        Write-DFIRLog "Could not automatically open the report. Please open it manually at: $reportPath" "Warning"
    }
}

Write-DFIRLog "Script execution completed." "Info"