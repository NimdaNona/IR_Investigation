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
    Write-DFIRLog "Collecting browser history..." "Info"
    
    $browserHistory = @{
        Chrome = @()
        Edge = @()
    }
    
    # Function to detect execution context (system account, administrative user, etc.)
    function Get-ExecutionContext {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $isSystem = $identity.User.Value -eq "S-1-5-18"  # System account SID
        
        Write-DFIRLog "Execution context: $($identity.Name) (Admin: $isAdmin, System: $isSystem)" "Info"
        
        return @{
            IsAdministrator = $isAdmin
            IsSystemAccount = $isSystem
            UserSID = $identity.User.Value
            UserName = $identity.Name
        }
    }
    
    # SentinelOne compatibility - Detect execution context
    $context = Get-ExecutionContext
    Write-Host "Starting browser history collection in context: $($context.UserName)"
    
    # Enhanced SQLite module installation and verification function
    function Install-SqliteModule {
        [CmdletBinding()]
        param(
            [int]$MaxRetries = 3,
            [int]$RetryDelaySeconds = 2
        )
        
        Write-Host "Starting PSSQLite module installation and verification"
        
        # Check if module is already available
        $moduleInstalled = $false
        $moduleImported = $false
        $moduleFunctional = $false
        $retryCount = 0
        $installScope = if ($context.IsSystemAccount) { "AllUsers" } else { "CurrentUser" }
        
        Write-Host "Checking if PSSQLite module is already installed..."
        
        # Check if module is installed
        if (Get-Module -ListAvailable -Name PSSQLite) {
            $moduleInstalled = $true
            Write-Host "PSSQLite module is already installed"
        }
        
        # Installation and verification loop
        while ((-not $moduleFunctional) -and ($retryCount -lt $MaxRetries)) {
            try {
                # If not installed, install the module
                if (-not $moduleInstalled) {
                    Write-Host "Installing PSSQLite module (Attempt $($retryCount + 1) of $MaxRetries)"
                    
                    # Install NuGet provider if needed
                    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                        Write-Host "Installing NuGet package provider..."
                        Install-PackageProvider -Name NuGet -Force -Scope $installScope | Out-Null
                        Write-Host "NuGet package provider installed successfully" -ForegroundColor Green
                    }
                    
                    # Install module with progress reporting
                    Write-Host "Installing PSSQLite module with scope $installScope..." -ForegroundColor Cyan
                    Install-Module -Name PSSQLite -Force -Scope $installScope -ErrorAction Stop | Out-Null
                    $moduleInstalled = $true
                    Write-Host "PSSQLite module installation completed" -ForegroundColor Green
                }
                
                # Try to import the module
                if (-not $moduleImported) {
                    Write-Host "Importing PSSQLite module..." -ForegroundColor Cyan
                    Import-Module PSSQLite -Force -ErrorAction Stop
                    $moduleImported = $true
                    Write-Host "PSSQLite module imported successfully" -ForegroundColor Green
                }
                
                # Verify module functionality by testing a command
                if ($moduleImported) {
                    Write-Host "Verifying PSSQLite module functionality..." -ForegroundColor Cyan
                    
                    # Check if required commands are available
                    $requiredCommands = @('Invoke-SqliteQuery', 'New-SqliteConnection')
                    $missingCommands = @()
                    
                    foreach ($command in $requiredCommands) {
                        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
                            $missingCommands += $command
                        }
                    }
                    
                    if ($missingCommands.Count -gt 0) {
                        Write-Host "Missing required commands: $($missingCommands -join ', ')" -ForegroundColor Yellow
                        throw "Required PSSQLite commands not available: $($missingCommands -join ', ')"
                    }
                    
                    $moduleFunctional = $true
                    Write-Host "PSSQLite module functionality verified successfully" -ForegroundColor Green
                }
                
            } catch {
                $retryCount++
                Write-Host "Error in module installation process: $_" -ForegroundColor Red
                
                if ($retryCount -lt $MaxRetries) {
                    $delayTime = $RetryDelaySeconds * $retryCount
                    Write-Host "Waiting $delayTime seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delayTime
                }
            }
        }
        
        # Return the status of module installation and functionality
        return $moduleFunctional
    }
    
    # Attempt to install and verify the PSSQLite module
    $psSqliteModuleFunctional = Install-SqliteModule -MaxRetries 3 -RetryDelaySeconds 2
    if (-not $psSqliteModuleFunctional) {
        Write-BrowserLog "Could not install or verify PSSQLite module after multiple attempts" "Warning"
        Write-Host "Will use fallback .NET SQLite access methods" -ForegroundColor Yellow
    } else {
        Write-Host "PSSQLite module is ready for use" -ForegroundColor Green
    }
    
    # Function to convert WebKit timestamp to DateTime
    function ConvertFrom-WebKitTimestamp {
        param (
            [Parameter(Mandatory = $true)]
            [Int64]$WebkitTimestamp
        )
        
        # Webkit timestamps are microseconds since Jan 1, 1601 UTC
        # Convert to DateTime
        try {
            if ($WebkitTimestamp -eq 0) {
                return $null
            }
            
            # Convert to DateTime (WebKit timestamp is microseconds since Jan 1, 1601)
            $epochAdjust = New-Object System.DateTime -ArgumentList 1601, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)
            return $epochAdjust.AddMilliseconds($WebkitTimestamp / 1000)
        } catch {
            # Return current date if conversion fails
            Get-Date
        }
    }
    
    # Function to create a temporary copy of a database file
    function Get-TemporaryDatabaseCopy {
        param (
            [Parameter(Mandatory = $true)]
            [string]$SourcePath
        )
        
        try {
            # Create a temporary file path
            $tempDbPath = "$env:TEMP\dfir_temp_db_$(Get-Random).db"
            
            if (Test-Path -Path $SourcePath) {
                # Try to copy the file (it may be locked by the browser)
                Copy-Item -Path $SourcePath -Destination $tempDbPath -Force -ErrorAction Stop
                return $tempDbPath
            } else {
                Write-DFIRLog "Database file not found: $SourcePath" "Warning"
                return $null
            }
        } catch {
            Write-DFIRLog "Error creating temporary database copy: $_" "Warning"
            return $null
        }
    }
    
    # Function to query browser history with PSSQLite
function Get-SQLiteBrowserHistory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,
        [Parameter(Mandatory = $false)]
        [int]$MaxEntries = 1000
    )
    $results = @()
    try {
        # Create a temporary copy of the database
        $tempDbPath = Get-TemporaryDatabaseCopy -SourcePath $DatabasePath
        if ($null -eq $tempDbPath) {
            return $results
        }
        # Use PSSQLite if available
        if (Get-Module -Name PSSQLite -ErrorAction SilentlyContinue) {
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
            $results = Invoke-SqliteQuery -DataSource $tempDbPath -Query $query -ErrorAction Stop | ForEach-Object {
                $lastVisitTime = if ($_.LastVisitTime) {
                    ConvertFrom-WebKitTimestamp -WebkitTimestamp $_.LastVisitTime
                } else {
                    Get-Date
                }
                [PSCustomObject]@{
                    URL        = $_.URL
                    Title      = if ([string]::IsNullOrEmpty($_.Title)) { "No Title" } else { $_.Title }
                    VisitCount = $_.VisitCount
                    LastVisit  = $lastVisitTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
        else {
            # Enhanced fallback method using .NET SQLite
            Write-Host "Starting enhanced .NET SQLite fallback method" -ForegroundColor Cyan
            
            # Function to download and verify SQLite DLL
            function Get-SqliteDll {
                [CmdletBinding()]
                param(
                    [int]$MaxRetries = 3,
                    [int]$RetryDelaySeconds = 2
                )
                
                Write-Host "Searching for SQLite DLL..." -ForegroundColor Cyan
                
                # Potential DLL locations
                $potentialPaths = @(
                    # Script directory
                    (Join-Path -Path $PSScriptRoot -ChildPath "System.Data.SQLite.dll"),
                    # Current directory
                    (Join-Path -Path (Get-Location) -ChildPath "System.Data.SQLite.dll"),
                    # Already in temp
                    (Join-Path -Path $env:TEMP -ChildPath "System.Data.SQLite.dll"),
                    # Common locations
                    "C:\Windows\System32\System.Data.SQLite.dll",
                    "$PrimaryUserLocalAppData\Programs\System.Data.SQLite.dll",
                    "$PrimaryUserLocalAppData\SQLite\System.Data.SQLite.dll"
                )
                
                # Check each potential location
                foreach ($path in $potentialPaths) {
                    if (Test-Path -Path $path) {
                        Write-Host "Found existing SQLite DLL at: $path" -ForegroundColor Green
                        return $path
                    }
                }
                
                # If not found, download
                Write-Host "SQLite DLL not found in any standard location. Will download." -ForegroundColor Yellow
                
                # Create download path in temp directory
                $downloadPath = Join-Path -Path $env:TEMP -ChildPath "System.Data.SQLite.dll"
                $urls = @(
                    "https://github.com/aspnet/Microsoft.Data.Sqlite/raw/main/src/libs/sqlite/x64/sqlite3.dll",
                    "https://www.sqlite.org/2024/sqlite-dll-win64-x64-3430000.zip" # Backup source if GitHub fails
                )
                
                $retryCount = 0
                $downloadSuccess = $false
                
                # Download with retry logic
                while (-not $downloadSuccess -and $retryCount -lt $MaxRetries) {
                    foreach ($url in $urls) {
                        try {
                            Write-Host "Downloading SQLite DLL from $url (Attempt $($retryCount + 1) of $MaxRetries)" -ForegroundColor Cyan
                            
                            if ($url -like "*.zip") {
                                # For ZIP files
                                $zipPath = Join-Path -Path $env:TEMP -ChildPath "sqlite_temp.zip"
                                $extractPath = Join-Path -Path $env:TEMP -ChildPath "sqlite_extract"
                                
                                # Download ZIP
                                Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
                                
                                # Create extraction directory if it doesn't exist
                                if (-not (Test-Path $extractPath)) {
                                    New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                                }
                                
                                # Extract ZIP
                                Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
                                
                                # Find SQLite DLL in extracted files
                                $extractedDll = Get-ChildItem -Path $extractPath -Recurse -Filter "*.dll" | 
                                               Where-Object { $_.Name -like "*sqlite*" } | 
                                               Select-Object -First 1
                                
                                if ($extractedDll) {
                                    # Copy to final location
                                    Copy-Item -Path $extractedDll.FullName -Destination $downloadPath -Force
                                    
                                    # Clean up
                                    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
                                    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                                    
                                    $downloadSuccess = $true
                                    Write-Host "Successfully downloaded and extracted SQLite DLL to $downloadPath" -ForegroundColor Green
                                    return $downloadPath
                                }
                            }
                            else {
                                # For direct DLL download
                                Invoke-WebRequest -Uri $url -OutFile $downloadPath -ErrorAction Stop
                                $downloadSuccess = $true
                                Write-Host "Successfully downloaded SQLite DLL to $downloadPath" -ForegroundColor Green
                                return $downloadPath
                            }
                        }
                        catch {
                            Write-Host "Failed to download SQLite DLL from ${url}: $_" -ForegroundColor Red
                            # Continue to next URL
                        }
                    }
                    
                    $retryCount++
                    if ($retryCount -lt $MaxRetries) {
                        $delayTime = $RetryDelaySeconds * $retryCount
                        Write-Host "Waiting $delayTime seconds before retry..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $delayTime
                    }
                }
                
                # If all download attempts failed
                if (-not $downloadSuccess) {
                    Write-Host "All attempts to download SQLite DLL failed" -ForegroundColor Red
                    return $null
                }
            }
            
            # Function to verify SQLite DLL functionality
            function Test-SqliteDll {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$DllPath
                )
                
                Write-Host "Verifying SQLite DLL functionality at $DllPath" -ForegroundColor Cyan
                
                try {
                    # Try to load the assembly
                    Add-Type -Path $DllPath -ErrorAction Stop
                    
                    # Create a test database in memory to verify functionality
                    $connectionString = "Data Source=:memory:;Version=3;"
                    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                    $connection.Open()
                    
                    # Create a test table and insert data
                    $command = $connection.CreateCommand()
                    $command.CommandText = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);
                                          INSERT INTO test (value) VALUES ('test');"
                    $command.ExecuteNonQuery() | Out-Null
                    
                    # Query the test data
                    $command.CommandText = "SELECT * FROM test;"
                    $reader = $command.ExecuteReader()
                    $result = $reader.Read()
                    $connection.Close()
                    
                    Write-Host "SQLite DLL functionality verified successfully" -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Host "SQLite DLL verification failed: $_" -ForegroundColor Red
                    return $false
                }
            }
            
            # Find or download the SQLite DLL
            $dllPath = Get-SqliteDll -MaxRetries 3 -RetryDelaySeconds 2
            $dllFunctional = $false
            
            if ($dllPath -and (Test-Path $dllPath)) {
                # Verify DLL functionality
                $dllFunctional = Test-SqliteDll -DllPath $dllPath
            }
            
            # If DLL not found or not functional, return empty results
            if (-not $dllFunctional) {
                Write-Host "Could not find or verify a working SQLite DLL. Returning empty results." -ForegroundColor Red
                
                if (Test-Path -Path $tempDbPath) {
                    Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
                }
                
                return $results
            }
            try {
                $connectionString = "Data Source=$tempDbPath;Version=3;Read Only=True;"
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                $connection.Open()
                $command = $connection.CreateCommand()
                $command.CommandText = @"
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
                $reader = $command.ExecuteReader()
                $dataTable = New-Object System.Data.DataTable
                $dataTable.Load($reader)
                foreach ($row in $dataTable.Rows) {
                    $lastVisitTime = if ($row["LastVisitTime"]) {
                        ConvertFrom-WebKitTimestamp -WebkitTimestamp ([Int64]$row["LastVisitTime"])
                    } else {
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
            } catch {
                Write-DFIRLog "Error using .NET SQLite: $_" "Warning"
                Write-DFIRLog "Attempting fallback to system tools for database access" "Info"
                $dbInfo = Get-Item $DatabasePath
                $results += [PSCustomObject]@{
                    URL        = "chrome://history or edge://history"
                    Title      = "Browser History (Access via browser interface)"
                    VisitCount = 1
                    LastVisit  = $dbInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
        if (Test-Path -Path $tempDbPath) {
            Remove-Item -Path $tempDbPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-DFIRLog "Error querying browser history: $_" "Warning"
    }
    return $results
}

    # For Chrome browser - get browser history from SQLite database
    $chromeHistoryPath = "$PrimaryUserLocalAppData\Google\Chrome\User Data\Default\History"
    try {
        if (Test-Path -Path $chromeHistoryPath) {
            Write-DFIRLog "Extracting Chrome history..." "Info"
            $browserHistory.Chrome = Get-SQLiteBrowserHistory -DatabasePath $chromeHistoryPath
            Write-DFIRLog "Found $($browserHistory.Chrome.Count) Chrome history entries" "Info"
        } else {
            Write-DFIRLog "Chrome history database not found" "Warning"
        }
    } catch {
        Write-DFIRLog "Error collecting Chrome history: $_" "Warning"
    }
    
    # For Edge browser - get browser history from SQLite database
    $edgeHistoryPath = "$PrimaryUserLocalAppData\Microsoft\Edge\User Data\Default\History"
    try {
        if (Test-Path -Path $edgeHistoryPath) {
            Write-DFIRLog "Extracting Edge history..." "Info"
            $browserHistory.Edge = Get-SQLiteBrowserHistory -DatabasePath $edgeHistoryPath
            Write-DFIRLog "Found $($browserHistory.Edge.Count) Edge history entries" "Info"
        } else {
            Write-DFIRLog "Edge history database not found" "Warning"
        }
    } catch {
        Write-DFIRLog "Error collecting Edge history: $_" "Warning"
    }
    
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
