<#
.SYNOPSIS
    Render the sample HTML report from invented observations.
.DESCRIPTION
    Loads only the v5 report formatter. No collection functions run.
#>
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'sample-report.html')
)

$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'IR_Data_Collection_v5.ps1'
$tokens = $null
$errors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0].Message }
$formatter = $scriptAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Generate-HTMLReport'
}, $false)
if (-not $formatter) { throw 'Could not find the v5 report formatter.' }

# The collector normally writes a log. The offline example only needs the renderer.
function Write-DFIRLog { param([string]$Message) Write-Verbose $Message }

$data = @{
    SystemInfo = @{
        ComputerSystem = @{ Name = 'DEMO-WS-017 (synthetic sample)'; Manufacturer = 'Example Systems'; Model = 'Training workstation'; TotalPhysicalMemory = 16GB }
        OperatingSystem = @{ Caption = 'Windows 11 Enterprise'; Version = '10.0.26100'; InstallDate = '2026-02-02 09:00' }
        BIOS = @{ Name = 'Example UEFI 1.0' }
        Processors = @(@{ Name = 'Example virtual CPU' })
        BootTime = '2026-04-17 07:50'
        NetworkAdapters = @(@{ Description = 'Lab Ethernet'; IPAddress = @('192.0.2.17'); MACAddress = '02:00:00:00:00:17'; DefaultIPGateway = @('192.0.2.1'); DNSServerSearchOrder = @('192.0.2.53') })
    }
    NetworkInfo = @{
        Connections = @(@{ Protocol = 'TCP'; LocalAddress = '192.0.2.17:50124'; ForeignAddress = '198.51.100.24:443'; State = 'Established'; ProcessName = 'msedge'; PID = 4240 })
        DNSCache = @(@{ Name = 'support.example'; Data = '198.51.100.24'; TimeToLive = 240; Type = 'A' })
    }
    ProcessInfo = @{
        Processes = @(@{ Id = 4240; ProcessName = 'msedge'; Path = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'; ParentProcessId = 1800; StartTime = '2026-04-17 09:10' })
    }
    UserInfo = @{
        LocalUsers = @(@{ Name = 'lab-analyst'; Enabled = $true; PasswordRequired = $true; LastLogon = '2026-04-17 08:05' })
        PowerShellHistory = @(@{ Command = 'Get-Date' })
    }
    TasksInfo = @{}
    UsbInfo = @{}
    DirectoryInfo = @{}
    BrowserHistory = @{
        Chrome = @()
        Edge = @(@{ LastVisit = '2026-04-17 09:12'; Title = 'Support & documentation <lab>'; URL = 'https://support.example/help'; VisitCount = 1 })
    }
}

$directories = @{
    Windows = 'C:\Windows'; WindowsPrefetch = 'C:\Windows\Prefetch'; WindowsTemp = 'C:\Windows\Temp'
    ProgramFiles = 'C:\Program Files'; ProgramFilesX86 = 'C:\Program Files (x86)'; ProgramData = 'C:\ProgramData'
    RecycleBin = 'C:\$Recycle.Bin'; UserProfiles = 'C:\Users'; UserDesktop = 'C:\Users\lab-analyst\Desktop'
    UserDocuments = 'C:\Users\lab-analyst\Documents'; UserDownloads = 'C:\Users\lab-analyst\Downloads'
    UserRecent = 'C:\Users\lab-analyst\AppData\Roaming\Microsoft\Windows\Recent'
    UserAppDataLocal = 'C:\Users\lab-analyst\AppData\Local'; UserAppDataRoaming = 'C:\Users\lab-analyst\AppData\Roaming'
}
foreach ($name in $directories.Keys) {
    $data.DirectoryInfo[$name] = @{ Path = $directories[$name]; Count = 0; SizeTotal = 0; Files = @() }
}
$data.DirectoryInfo.UserDownloads = @{
    Path = $directories.UserDownloads; Count = 1; SizeTotal = 2048
    Files = @(@{ Name = 'support-notes.txt'; Type = 'File'; Length = 2048; CreationTime = '2026-04-17 09:13'; LastWriteTime = '2026-04-17 09:13'; Attributes = 'Archive' })
}

$render = $formatter.Body.GetScriptBlock()
& $render -Data $data -OutputPath $OutputPath -GeneratedAt ([datetime]'2026-04-17T09:15:00')
