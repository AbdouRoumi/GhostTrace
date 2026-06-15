<#
.NOTES
    Author: E1b1g
    Version: 3.0.0 — Forensic-focused rewrite
    Requirements: Windows 10/11, PowerShell 5.1+, Administrator rights
    Optional tools (place in C:\Tools\):
        winpmem.exe  — RAM dump
        handle.exe   — mutex/named pipe enumeration (SysInternals)
        MFTECmd.exe  — MFT parsing
        PECmd.exe    — Prefetch parsing

.EXAMPLE
    .\MalwareForensicsCollector.ps1 -Label "baseline"
    .\MalwareForensicsCollector.ps1 -Label "post_WannaCry_v1"
#>

param(
    [string]$Label = "collection",
    [string]$OutputBase = "C:\ForensicsDataset",
    [string]$ToolsPath = "C:\Tools"
)

# ============================================================
# INIT
# ============================================================
$ESC = [char]0x1b
$C = @{
    Title   = "$ESC[36;1m"
    Success = "$ESC[32;1m"
    Warning = "$ESC[33;1m"
    Error   = "$ESC[31;1m"
    Info    = "$ESC[34;1m"
    Reset   = "$ESC[0m"
}

function Write-Log {
    param([string]$Msg, [string]$Level = "Info")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$($C[$Level])[$ts][$Level]$($C.Reset) $Msg"
    ($line -replace '\x1b\[[0-9;]*m', '') | Out-File $script:LogPath -Append -Encoding UTF8
    Write-Host $line
}

function Save-Raw {
    param([string]$Path, [scriptblock]$Block)
    try {
        $result = & $Block
        if ($null -ne $result) {
            if ($Path -match '\.csv$') {
                $result | Export-Csv $Path -NoTypeInformation -Encoding UTF8 -Force
            } else {
                $result | Out-File $Path -Encoding UTF8 -Force
            }
            Write-Log "Saved: $Path" "Success"
        } else {
            Write-Log "Empty: $Path" "Warning"
        }
    } catch {
        Write-Log "FAILED: $Path — $_" "Error"
    }
}

function Copy-LockedFile {
    param([string]$Source, [string]$Dest)
    try {
        # Use VSS to copy locked files (registry hives, WMI repo etc.)
        $vol = Split-Path $Source -Qualifier
        $shadow = (Get-WmiObject -List Win32_ShadowCopy).Create($vol + "\", "ClientAccessible")
        $sc = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
        $shadowPath = $sc.DeviceObject + "\" + ($Source -replace [regex]::Escape($vol + "\"), "")
        Copy-Item $shadowPath $Dest -Force -ErrorAction Stop
        $sc.Delete()
        Write-Log "VSS copy: $Source -> $Dest" "Success"
        return $true
    } catch {
        # Fallback: raw copy attempt
        try {
            [System.IO.File]::Copy($Source, $Dest, $true)
            Write-Log "Raw copy: $Source -> $Dest" "Success"
            return $true
        } catch {
            Write-Log "Copy failed: $Source — $_" "Error"
            return $false
        }
    }
}

# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "$($C.Error)[!] Must run as Administrator.$($C.Reset)"
    exit 1
}

# Output structure
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = "$OutputBase\${Label}_$ts"
$Dirs = @(
    "P1_Volatile\RAM", "P1_Volatile\Processes", "P1_Volatile\Network", "P1_Volatile\Pipes",
    "P2_SemiVolatile\EVTX", "P2_SemiVolatile\WMI",
    "P3_NonVolatile\RegistryHives", "P3_NonVolatile\Prefetch",
    "P3_NonVolatile\MFT", "P3_NonVolatile\Shimcache"
)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
foreach ($d in $Dirs) { New-Item -ItemType Directory "$OutDir\$d" -Force | Out-Null }
$script:LogPath = "$OutDir\forensics_collection.log"
New-Item -ItemType File $script:LogPath -Force | Out-Null

Write-Log "=== MALWARE FORENSICS COLLECTOR v3.0 ===" "Title"
Write-Log "Label: $Label | Output: $OutDir" "Info"
Write-Log "Host: $env:COMPUTERNAME | User: $env:USERNAME" "Info"

# ============================================================
# PRIORITY 1 — VOLATILE
# Collect immediately — changes every second
# ============================================================
Write-Log "=== PRIORITY 1: VOLATILE ARTIFACTS ===" "Title"

# --- 1.1 RAM DUMP ---
Write-Log "--- [1/10] RAM DUMP ---" "Title"
$winpmem = "$ToolsPath\winpmem.exe"
if (Test-Path $winpmem) {
    $dumpPath = "$OutDir\P1_Volatile\RAM\memdump_$ts.raw"
    Write-Log "Starting RAM dump with winpmem..." "Info"
    try {
        & $winpmem $dumpPath
        Write-Log "RAM dump saved: $dumpPath" "Success"
    } catch {
        Write-Log "winpmem failed: $_" "Error"
    }
} else {
    Write-Log "winpmem.exe not found in $ToolsPath — RAM dump SKIPPED" "Warning"
    @"
[!] RAM DUMP REQUIRED — winpmem not found.

Options:
  1. winpmem (recommended, free):
     Download: https://github.com/Velocidex/WinPmem/releases
     Run: winpmem.exe $OutDir\P1_Volatile\RAM\memdump.raw

  2. FTK Imager (GUI):
     File > Capture Memory > Save to $OutDir\P1_Volatile\RAM\

  3. DumpIt:
     DumpIt.exe /O $OutDir\P1_Volatile\RAM\memdump.raw

  CRITICAL: Do this BEFORE any other action on the system.
"@ | Out-File "$OutDir\P1_Volatile\RAM\RAM_DUMP_REQUIRED.txt"
}

# --- 1.2 RUNNING PROCESSES ---
Write-Log "--- [2/10] RUNNING PROCESSES ---" "Title"

# Full process list with parent, command line, owner, hash
Save-Raw "$OutDir\P1_Volatile\Processes\processes_full.csv" {
    Get-WmiObject Win32_Process | ForEach-Object {
        $owner = $_.GetOwner()
        $hash = if ($_.ExecutablePath -and (Test-Path $_.ExecutablePath)) {
            (Get-FileHash $_.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        } else { "N/A" }
        [PSCustomObject]@{
            PID             = $_.ProcessId
            ParentPID       = $_.ParentProcessId
            Name            = $_.Name
            ExecutablePath  = $_.ExecutablePath
            CommandLine     = $_.CommandLine
            Owner           = "$($owner.Domain)\$($owner.User)"
            CreationDate    = $_.CreationDate
            SHA256          = $hash
            WorkingSetKB    = [math]::Round($_.WorkingSetSize / 1KB, 0)
        }
    }
}

# Process tree (parent-child relationships)
Save-Raw "$OutDir\P1_Volatile\Processes\process_tree.txt" {
    $procs = Get-WmiObject Win32_Process
    $lookup = @{}
    foreach ($p in $procs) { $lookup[$p.ProcessId] = $p.Name }
    $procs | ForEach-Object {
        $parentName = if ($lookup[$_.ParentProcessId]) { $lookup[$_.ParentProcessId] } else { "UNKNOWN" }
        "$parentName($($_.ParentProcessId)) --> $($_.Name)($($_.ProcessId)) | $($_.CommandLine)"
    }
}

# Loaded DLLs (injection detection — unsigned DLLs in system processes)
Save-Raw "$OutDir\P1_Volatile\Processes\loaded_dlls.csv" {
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            $proc.Modules | ForEach-Object {
                [PSCustomObject]@{
                    PID         = $proc.Id
                    ProcessName = $proc.Name
                    DLLPath     = $_.FileName
                    Company     = $_.FileVersionInfo.CompanyName
                    Version     = $_.FileVersionInfo.FileVersion
                    Signed      = (Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue).Status
                }
            }
        } catch {}
    }
}

# --- 1.3 NETWORK STATE ---
Write-Log "--- [3/10] NETWORK STATE ---" "Title"

Save-Raw "$OutDir\P1_Volatile\Network\connections.csv" {
    Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        $conn = $_
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress    = $conn.LocalAddress
            LocalPort       = $conn.LocalPort
            RemoteAddress   = $conn.RemoteAddress
            RemotePort      = $conn.RemotePort
            State           = $conn.State
            PID             = $conn.OwningProcess
            ProcessName     = $proc.Name
            ProcessPath     = $proc.Path
        }
    }
}

Save-Raw "$OutDir\P1_Volatile\Network\udp_connections.csv" {
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            PID          = $_.OwningProcess
            ProcessName  = $proc.Name
        }
    }
}

Save-Raw "$OutDir\P1_Volatile\Network\dns_cache.csv" {
    Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data
}

Save-Raw "$OutDir\P1_Volatile\Network\arp_cache.txt" { arp -a }
Save-Raw "$OutDir\P1_Volatile\Network\routing_table.txt" { route print }

# PCAP reminder
@"
[!] NETWORK CAPTURE — Start BEFORE malware execution.

Commands:
  Wireshark GUI: start capture on all interfaces before running malware

  tshark (CLI):
  tshark -i <interface> -w $OutDir\P1_Volatile\Network\capture.pcap

  tcpdump:
  tcpdump -i any -w $OutDir\P1_Volatile\Network\capture.pcap

Why critical: C2 beaconing, DNS queries, data exfiltration only visible here.
Especially important for fileless malware that leaves nothing on disk.
"@ | Out-File "$OutDir\P1_Volatile\Network\PCAP_REQUIRED.txt"

# --- 1.4 NAMED PIPES & MUTEXES ---
Write-Log "--- [4/10] NAMED PIPES & MUTEXES ---" "Title"

# Named pipes — fileless malware and C2 frameworks (Cobalt Strike) use these
Save-Raw "$OutDir\P1_Volatile\Pipes\named_pipes.txt" {
    try { [System.IO.Directory]::GetFiles('\\.\pipe\') } catch { "Could not enumerate pipes: $_" }
}

# handle.exe for proper mutex enumeration
$handleExe = "$ToolsPath\handle.exe"
if (Test-Path $handleExe) {
    try {
        & $handleExe -a -t mutant -nobanner 2>$null |
            Out-File "$OutDir\P1_Volatile\Pipes\mutexes.txt" -Encoding UTF8 -Force
        Write-Log "Mutexes collected via handle.exe" "Success"

        & $handleExe -a -t pipe -nobanner 2>$null |
            Out-File "$OutDir\P1_Volatile\Pipes\pipes_handle.txt" -Encoding UTF8 -Force
        Write-Log "Pipes collected via handle.exe" "Success"
    } catch {
        Write-Log "handle.exe error: $_" "Error"
    }
} else {
    Write-Log "handle.exe not found — mutex enumeration limited" "Warning"
    "[!] Place handle.exe from SysInternals in $ToolsPath for full mutex/pipe enumeration.`nDownload: https://learn.microsoft.com/en-us/sysinternals/downloads/handle" |
        Out-File "$OutDir\P1_Volatile\Pipes\HANDLE_REQUIRED.txt"
}

# ============================================================
# PRIORITY 2 — SEMI-VOLATILE
# Stable during session but lost on reboot
# ============================================================
Write-Log "=== PRIORITY 2: SEMI-VOLATILE ARTIFACTS ===" "Title"

# --- 2.1 RAW EVTX FILES ---
Write-Log "--- [5/10] RAW EVENT LOGS (EVTX) ---" "Title"

# Copy raw EVTX files — parsers like Hayabusa/Chainsaw work on these directly
$evtxFiles = @{
    "Security"                                          = "Security.evtx"
    "System"                                            = "System.evtx"
    "Application"                                       = "Application.evtx"
    "Microsoft-Windows-Sysmon/Operational"              = "Sysmon.evtx"
    "Microsoft-Windows-PowerShell/Operational"          = "PowerShell_Operational.evtx"
    "Windows PowerShell"                                = "PowerShell_Classic.evtx"
    "Microsoft-Windows-WMI-Activity/Operational"        = "WMI_Activity.evtx"
    "Microsoft-Windows-TaskScheduler/Operational"       = "TaskScheduler.evtx"
    "Microsoft-Windows-Bits-Client/Operational"         = "BITS_Client.evtx"
    "Microsoft-Windows-Windows Defender/Operational"    = "Defender.evtx"
    "Microsoft-Windows-DNS-Client/Operational"          = "DNS_Client.evtx"
}

$evtxSourceDir = "$env:SystemRoot\System32\winevt\Logs"
foreach ($logName in $evtxFiles.Keys) {
    $destName = $evtxFiles[$logName]
    $destPath = "$OutDir\P2_SemiVolatile\EVTX\$destName"
    try {
        # Get physical file path from log name
        $logInfo = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($logInfo -and $logInfo.LogFilePath) {
            $sourcePath = $logInfo.LogFilePath -replace '%SystemRoot%', $env:SystemRoot
            Copy-LockedFile -Source $sourcePath -Dest $destPath | Out-Null
        } else {
            Write-Log "Log not found or not enabled: $logName" "Warning"
        }
    } catch {
        Write-Log "EVTX copy failed: $logName — $_" "Error"
    }
}

# Key event IDs to extract as CSV for quick analysis
Write-Log "Extracting key event IDs..." "Info"
$keyEvents = @(
    @{ Log="Security"; IDs=@(4624,4625,4648,4688,4698,4702,4720,4726,7045); File="key_security_events.csv" },
    @{ Log="System";   IDs=@(7045,7036,104,1102);                            File="key_system_events.csv" },
    @{ Log="Microsoft-Windows-Sysmon/Operational"; IDs=@(1,2,3,5,6,7,8,10,11,12,13,15,17,18,22,23,25); File="key_sysmon_events.csv" }
)
foreach ($e in $keyEvents) {
    Save-Raw "$OutDir\P2_SemiVolatile\EVTX\$($e.File)" {
        $filter = @{ LogName=$e.Log; Id=$e.IDs }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    }
}

# PowerShell transcript files
Write-Log "Collecting PowerShell transcripts..." "Info"
$transcriptPaths = @(
    "$env:USERPROFILE\Documents",
    "$env:SystemRoot\System32",
    "C:\Transcripts",
    "$env:APPDATA\Microsoft\Windows\PowerShell"
)
foreach ($tp in $transcriptPaths) {
    if (Test-Path $tp) {
        Get-ChildItem $tp -Filter "PowerShell_transcript*.txt" -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                Copy-Item $_.FullName "$OutDir\P2_SemiVolatile\EVTX\$($_.Name)" -Force -ErrorAction SilentlyContinue
            }
    }
}

# PSReadLine history
$psrl = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psrl) {
    Copy-Item $psrl "$OutDir\P2_SemiVolatile\EVTX\PSReadLine_history.txt" -Force
    Write-Log "PSReadLine history copied" "Success"
}

# --- 2.2 WMI REPOSITORY ---
Write-Log "--- [6/10] WMI REPOSITORY ---" "Title"

# Raw WMI repository files — contains persistent event subscriptions
$wmiRepoPath = "$env:SystemRoot\System32\wbem\Repository"
$wmiFiles = @("OBJECTS.DATA", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP", "INDEX.BTR")
foreach ($wf in $wmiFiles) {
    $src = "$wmiRepoPath\$wf"
    if (Test-Path $src) {
        Copy-LockedFile -Source $src -Dest "$OutDir\P2_SemiVolatile\WMI\$wf" | Out-Null
    }
}

# WMI persistence query (live)
Save-Raw "$OutDir\P2_SemiVolatile\WMI\wmi_event_filters.csv" {
    Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
        Select-Object Name, Query, QueryLanguage, EventNamespace
}
Save-Raw "$OutDir\P2_SemiVolatile\WMI\wmi_event_consumers.csv" {
    Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue |
        Select-Object Name, CommandLineTemplate, ScriptText, ScriptingEngine, ScriptFileName
}
Save-Raw "$OutDir\P2_SemiVolatile\WMI\wmi_bindings.csv" {
    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object Filter, Consumer, CreatorSID
}

# ============================================================
# PRIORITY 3 — NON-VOLATILE
# Survives reboot — but collect before Deep Freeze restores
# ============================================================
Write-Log "=== PRIORITY 3: NON-VOLATILE ARTIFACTS ===" "Title"

# --- 3.1 RAW REGISTRY HIVES ---
Write-Log "--- [7/10] RAW REGISTRY HIVES ---" "Title"

# Copy raw hive files — needed for shimcache, amcache, BAM, full timeline
$hives = @{
    "SYSTEM"     = "$env:SystemRoot\System32\config\SYSTEM"
    "SOFTWARE"   = "$env:SystemRoot\System32\config\SOFTWARE"
    "SAM"        = "$env:SystemRoot\System32\config\SAM"
    "SECURITY"   = "$env:SystemRoot\System32\config\SECURITY"
    "NTUSER_DAT" = "$env:USERPROFILE\NTUSER.DAT"
    "UsrClass"   = "$env:LOCALAPPDATA\Microsoft\Windows\UsrClass.dat"
}

foreach ($name in $hives.Keys) {
    Copy-LockedFile -Source $hives[$name] -Dest "$OutDir\P3_NonVolatile\RegistryHives\$name" | Out-Null
}

# Key persistence keys (live query for quick review)
$persistKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKCU:\Software\Classes\CLSID"
)
foreach ($key in $persistKeys) {
    $safe = $key -replace '[:\\]', '_'
    Save-Raw "$OutDir\P3_NonVolatile\RegistryHives\live_$safe.txt" {
        Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Format-List
    }
}

# Scheduled tasks (persistence)
Save-Raw "$OutDir\P3_NonVolatile\RegistryHives\scheduled_tasks.csv" {
    Get-ScheduledTask | ForEach-Object {
        try {
            $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction Stop
            [PSCustomObject]@{
                Name        = $_.TaskName
                Path        = $_.TaskPath
                State       = $_.State
                Author      = $_.Author
                LastRun     = $info.LastRunTime
                NextRun     = $info.NextRunTime
                Actions     = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | "
                Triggers    = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join " | "
            }
        } catch {}
    }
}

# Services
Save-Raw "$OutDir\P3_NonVolatile\RegistryHives\services.csv" {
    Get-WmiObject Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
        Sort-Object StartMode, State
}

# --- 3.2 PREFETCH FILES ---
Write-Log "--- [8/10] PREFETCH FILES ---" "Title"

$prefetchDir = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchDir) {
    # List with metadata
    Save-Raw "$OutDir\P3_NonVolatile\Prefetch\prefetch_list.csv" {
        Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object Name, CreationTime, LastWriteTime, Length
    }
    # Copy raw .pf files (needed for PECmd)
    try {
        Copy-Item "$prefetchDir\*.pf" "$OutDir\P3_NonVolatile\Prefetch\" -Force -ErrorAction SilentlyContinue
        Write-Log "Prefetch .pf files copied" "Success"
    } catch {
        Write-Log "Prefetch copy error: $_" "Error"
    }
    # PECmd reminder
    $pecmd = "$ToolsPath\PECmd.exe"
    if (Test-Path $pecmd) {
        try {
            & $pecmd -d "$OutDir\P3_NonVolatile\Prefetch\" --csv "$OutDir\P3_NonVolatile\Prefetch\" --csvf prefetch_parsed.csv -q 2>$null
            Write-Log "PECmd parsed prefetch files" "Success"
        } catch {
            Write-Log "PECmd error: $_" "Error"
        }
    } else {
        "[!] Run PECmd for parsed output:`nPECmd.exe -d $OutDir\P3_NonVolatile\Prefetch\ --csv $OutDir\P3_NonVolatile\Prefetch\ --csvf prefetch_parsed.csv" |
            Out-File "$OutDir\P3_NonVolatile\Prefetch\PECMD_REMINDER.txt"
    }
} else {
    Write-Log "Prefetch directory not found — may be disabled" "Warning"
}

# --- 3.3 MFT + USN JOURNAL ---
Write-Log "--- [9/10] MFT + USN JOURNAL ---" "Title"

# USN Journal info
try {
    fsutil usn queryjournal C: | Out-File "$OutDir\P3_NonVolatile\MFT\usn_journal_info.txt" -Encoding UTF8 -Force
    Write-Log "USN Journal info exported" "Success"
} catch {
    Write-Log "USN Journal error: $_" "Error"
}

# MFTECmd auto-run if available
$mftecmd = "$ToolsPath\MFTECmd.exe"
$mftPath = "C:\`$MFT"
if (Test-Path $mftecmd) {
    try {
        & $mftecmd -f $mftPath --csv "$OutDir\P3_NonVolatile\MFT\" --csvf mft_parsed.csv -q 2>$null
        Write-Log "MFTECmd parsed MFT" "Success"
    } catch {
        Write-Log "MFTECmd error: $_" "Error"
    }
} else {
    @"
[!] MFTECmd not found. Run manually:
    MFTECmd.exe -f C:\`$MFT --csv $OutDir\P3_NonVolatile\MFT\ --csvf mft_parsed.csv

Download MFTECmd: https://ericzimmerman.github.io/#!index.md

Why critical: Complete filesystem timeline including deleted files.
Malware can delete files but MFT entries persist.
"@ | Out-File "$OutDir\P3_NonVolatile\MFT\MFTECMD_REQUIRED.txt"
    Write-Log "MFTECmd not found — MFT parse skipped" "Warning"
}

# --- 3.4 AMCACHE + SHIMCACHE ---
Write-Log "--- [10/10] AMCACHE + SHIMCACHE ---" "Title"

# Amcache.hve — execution history, SHA1 of every executed binary
$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $amcachePath) {
    Copy-LockedFile -Source $amcachePath -Dest "$OutDir\P3_NonVolatile\Shimcache\Amcache.hve" | Out-Null
} else {
    Write-Log "Amcache.hve not found" "Warning"
}

# Shimcache (AppCompatCache) — raw registry export
try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" `
        "$OutDir\P3_NonVolatile\Shimcache\AppCompatCache.reg" /y 2>$null
    Write-Log "AppCompatCache (Shimcache) exported" "Success"
} catch {
    Write-Log "Shimcache export error: $_" "Error"
}

# BAM/DAM (Background Activity Monitor) — execution timestamps even for deleted files
try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" `
        "$OutDir\P3_NonVolatile\Shimcache\BAM.reg" /y 2>$null
    Write-Log "BAM exported" "Success"
} catch {
    Write-Log "BAM export error (may not exist on this OS): $_" "Warning"
}

# ============================================================
# ANTI-FORENSIC INDICATORS (bonus — fast check)
# ============================================================
Write-Log "=== ANTI-FORENSIC INDICATORS ===" "Title"

# Event log clearing
Save-Raw "$OutDir\anti_forensic_indicators.csv" {
    $events = @()
    try { $events += Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -ErrorAction SilentlyContinue }
    catch {}
    try { $events += Get-WinEvent -LogName System -FilterXPath "*[System[EventID=104]]" -ErrorAction SilentlyContinue }
    catch {}
    $events | Select-Object TimeCreated, Id, Message
}

# VSS deletion (ransomware fingerprint)
vssadmin list shadows 2>$null | Out-File "$OutDir\vss_snapshots.txt" -Encoding UTF8 -Force
Write-Log "VSS snapshot state saved" "Success"

# ============================================================
# METADATA
# ============================================================
[PSCustomObject]@{
    Label           = $Label
    Timestamp       = $ts
    Hostname        = $env:COMPUTERNAME
    OS              = (Get-WmiObject Win32_OperatingSystem).Caption
    CollectorVer    = "3.0.0"
    OutputDir       = $OutDir
    RAMDump         = (Test-Path "$OutDir\P1_Volatile\RAM\*.raw")
    SysmonPresent   = ($null -ne (Get-Service Sysmon -ErrorAction SilentlyContinue))
    ToolsFound      = @{
        winpmem  = (Test-Path "$ToolsPath\winpmem.exe")
        handle   = (Test-Path "$ToolsPath\handle.exe")
        MFTECmd  = (Test-Path "$ToolsPath\MFTECmd.exe")
        PECmd    = (Test-Path "$ToolsPath\PECmd.exe")
    }
} | ConvertTo-Json | Out-File "$OutDir\metadata.json" -Encoding UTF8 -Force

# ============================================================
# ARCHIVE
# ============================================================
Write-Log "=== ARCHIVING ===" "Title"
try {
    $zipPath = "$OutDir.zip"
    Compress-Archive -Path "$OutDir\*" -DestinationPath $zipPath -Force
    Write-Log "Archive: $zipPath" "Success"
} catch {
    Write-Log "Archive error: $_" "Error"
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "$($C.Title)╔══════════════════════════════════════════╗$($C.Reset)"
Write-Host "$($C.Title)║   COLLECTION COMPLETE — SUMMARY          ║$($C.Reset)"
Write-Host "$($C.Title)╚══════════════════════════════════════════╝$($C.Reset)"
Write-Host ""
Write-Host "$($C.Success)[P1] RAM dump        → $OutDir\P1_Volatile\RAM\$($C.Reset)"
Write-Host "$($C.Success)[P1] Processes        → $OutDir\P1_Volatile\Processes\$($C.Reset)"
Write-Host "$($C.Success)[P1] Network state    → $OutDir\P1_Volatile\Network\$($C.Reset)"
Write-Host "$($C.Success)[P1] Pipes/Mutexes    → $OutDir\P1_Volatile\Pipes\$($C.Reset)"
Write-Host "$($C.Success)[P2] EVTX logs        → $OutDir\P2_SemiVolatile\EVTX\$($C.Reset)"
Write-Host "$($C.Success)[P2] WMI repository   → $OutDir\P2_SemiVolatile\WMI\$($C.Reset)"
Write-Host "$($C.Success)[P3] Registry hives   → $OutDir\P3_NonVolatile\RegistryHives\$($C.Reset)"
Write-Host "$($C.Success)[P3] Prefetch         → $OutDir\P3_NonVolatile\Prefetch\$($C.Reset)"
Write-Host "$($C.Success)[P3] MFT + USN        → $OutDir\P3_NonVolatile\MFT\$($C.Reset)"
Write-Host "$($C.Success)[P3] Amcache/Shimcache → $OutDir\P3_NonVolatile\Shimcache\$($C.Reset)"
Write-Host ""
Write-Host "$($C.Warning)[!] MANUAL STEPS:$($C.Reset)"
Write-Host "  • PCAP      → Start Wireshark BEFORE malware execution"
Write-Host "  • RAM dump  → Place winpmem.exe in $ToolsPath if not done"
Write-Host "  • MFT       → Run MFTECmd.exe (see MFT\MFTECMD_REQUIRED.txt)"
Write-Host "  • Mutexes   → Place handle.exe in $ToolsPath"
Write-Host ""
Write-Host "$($C.Info)Usage:$($C.Reset)"
Write-Host "  Baseline : .\MalwareForensicsCollector.ps1 -Label baseline"
Write-Host "  Post-exec: .\MalwareForensicsCollector.ps1 -Label post_FamilyName_variant"
Write-Host ""
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
