#description: FSLogix health check (v2). Scores an FSLogix installation against Microsoft's documented best practice. Produces a weighted health score, HTML report and machine-readable JSON. Read-only by default; -Remediate applies an allow-listed set of safe registry corrections.
#execution mode: Individual
#tags: FSLogix, AVD, Health Check, Profile Container

<#
    FSLogix Health Check v2
    -----------------------
    Reference implementation for a native FSLogix health check in
    Nerdio Manager for Enterprise.

    Design goals over v1:
      * Every rule is data, not inline code, so the rule set can be reviewed,
        versioned and surfaced in a product UI without reading PowerShell.
      * Machine-readable JSON output so a fleet run can be aggregated into a
        single pool-level view. HTML is a rendering of that JSON, not the
        source of truth.
      * A weighted health score, so "12 warnings" becomes a number an
        operations dashboard can trend.
      * Non-interactive by design. Remediation is an explicit switch with an
        allow-list and -WhatIf support, never a console prompt.
      * No single check can abort the run.

    Sources (all Microsoft Learn, verified 1 September 2026):
      Prerequisites / antivirus exclusions
        https://learn.microsoft.com/fslogix/overview-prerequisites
      Configuration Setting Reference
        https://learn.microsoft.com/fslogix/reference-configuration-settings
      Configuration examples (the recommended-value tables this scores against)
        https://learn.microsoft.com/fslogix/concepts-configuration-examples
      Status / Reason code tables
        https://learn.microsoft.com/fslogix/troubleshooting-error-codes
      Local include and exclude groups
        https://learn.microsoft.com/fslogix/concepts-include-exclude-groups
      Release notes
        https://learn.microsoft.com/fslogix/overview-release-notes

    Compatibility: Windows PowerShell 5.1. No external modules. No here-strings
    (the NME scripted-action delivery wrapper re-serializes them), no em-dash,
    no Unicode arrows.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Directory for the HTML report. A UNC path lets a whole host pool write to one place.
    [string]$ReportPath,

    # Directory for the JSON result document. Defaults alongside the HTML report.
    [string]$JsonPath,

    # Skip the HTML rendering and emit JSON only. Useful for fleet runs.
    [switch]$JsonOnly,

    # Apply the allow-listed registry corrections. Honours -WhatIf.
    [switch]$Remediate,

    # Restrict remediation to these check IDs. Empty means every allow-listed fix.
    [string[]]$RemediateOnly = @(),

    # Enumerate profile containers on the share and report size against SizeInMBs.
    # Off by default because it walks the share.
    [switch]$ScanContainers,

    # Hard cap on containers enumerated when -ScanContainers is used.
    [int]$MaxContainersToScan = 500,

    # Minimum acceptable FSLogix version. Update this as Microsoft ships releases.
    # 3.26.126.19110 is FSLogix 26.01 CU1, published 10 February 2026.
    [string]$MinimumFSLogixVersion = '3.26.126.19110',

    # Suppress the console table. The JSON and HTML are still produced.
    [switch]$Quiet
)

# Deliberately NOT 'Stop'. Every check owns its own error handling; one bad
# check must never cost the operator the whole report.
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:SchemaVersion = '2.0'
$script:StartedUtc    = (Get-Date).ToUniversalTime()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

$RK_PROFILES  = 'HKLM:\SOFTWARE\FSLogix\Profiles'
$RK_ODFC      = 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC'
$RK_APPS      = 'HKLM:\SOFTWARE\FSLogix\Apps'
$RK_CCD_SVC   = 'HKLM:\SYSTEM\CurrentControlSet\Services\frxccd\Parameters'
$RK_CCDS_SVC  = 'HKLM:\SYSTEM\CurrentControlSet\Services\frxccds\Parameters'
$RK_PROFLIST  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$RK_KERBEROS  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'

$DOC_SETTINGS = 'https://learn.microsoft.com/fslogix/reference-configuration-settings'
$DOC_EXAMPLES = 'https://learn.microsoft.com/fslogix/concepts-configuration-examples'
$DOC_PREREQ   = 'https://learn.microsoft.com/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions'
$DOC_CODES    = 'https://learn.microsoft.com/fslogix/troubleshooting-error-codes'
$DOC_GROUPS   = 'https://learn.microsoft.com/fslogix/concepts-include-exclude-groups'
$DOC_PERMS    = 'https://learn.microsoft.com/fslogix/how-to-configure-storage-permissions'
$DOC_RELEASE  = 'https://learn.microsoft.com/fslogix/overview-release-notes'

# Severity drives the health score. Weight is arbitrary but consistent.
$script:SeverityWeight = @{
    'Critical' = 10
    'High'     = 6
    'Medium'   = 3
    'Low'      = 1
    'Info'     = 0
}

# FSLogix Status codes. Source: troubleshooting-error-codes.
$script:StatusCodes = @{
    0   = 'STATUS_SUCCESS - success'
    1   = 'ERROR - cannot load user profile'
    2   = 'ERROR_VIRT_DLL - virtual disk API not available on this platform'
    3   = 'ERROR_GET_USER - cannot retrieve the user security identifier'
    4   = 'ERROR_HANDLE_ODFC - error setting up the Office 365 container'
    5   = 'ERROR_SECURITY - cannot retrieve security information'
    6   = 'ERROR_VHD_PATH - cannot retrieve the virtual disk location'
    7   = 'ERROR_CREATE_DIR - cannot create destination folders'
    8   = 'ERROR_IMPERSONATION - cannot impersonate the user'
    9   = 'ERROR_CREATE_VHD - cannot create the virtual disk'
    10  = 'ERROR_CLOSE_HANDLE - cannot release the virtual disk'
    11  = 'ERROR_OPEN_VHD - cannot open the virtual disk'
    12  = 'ERROR_ATTACH_VHD - cannot attach to the virtual disk'
    13  = 'ERROR_GET_PHYSICAL_PATH - cannot retrieve virtual disk physical information'
    14  = 'ERROR_OPEN_DEVICE - cannot open the virtual disk volume'
    15  = 'ERROR_INIT_DISK - cannot initialise the virtual disk'
    16  = 'ERROR_GET_VOL_GUID - cannot retrieve the virtual disk identifier'
    17  = 'ERROR_FORMAT_VOL - error while formatting the virtual disk'
    18  = 'ERROR_GET_PROFILE_DIR - cannot retrieve the profile directory'
    19  = 'ERROR_SET_MOUNT_POINT - cannot set up the directory mount point'
    20  = 'ERROR_REG_IMPORT - cannot import registry information'
    21  = 'ERROR_CHK_GRP_MEMBERSHIP - cannot retrieve the user group'
    22  = 'ERROR_HANDLE_PROFILE - error handling the profile'
    23  = 'ERROR_PROFILE_SUBFOLDER_REDIRECTION - cannot set up folder redirections'
    24  = 'ERROR_CREATE_EVENT - unable to create event'
    25  = 'ERROR_PER_SESSION_VHD - maximum sessions reached'
    26  = 'ERROR_DETACH_VHD - cannot detach the virtual disk at the provided location'
    27  = 'ERROR_FIND_VHD - cannot find the virtual disk at the provided location'
    28  = 'ERROR_NO_SESSION_CONFIG - no user session config found'
    100 = 'STATUS_WAITING_FOR_PROFILE_DIR_SET - waiting for the Windows Profile Service'
    200 = 'STATUS_IN_PROGRESS - setup in progress'
    300 = 'STATUS_ALREADY_ATTACHED - profile already attached (differencing disks only)'
}
$script:StatusNormal = @(0, 100, 200, 300)

# FSLogix Reason codes. Source: troubleshooting-error-codes.
$script:ReasonCodes = @{
    0 = 'REASON_PROFILE_ATTACHED - the container is attached'
    1 = 'REASON_NOT_IN_WHITE_LIST - user is not a member of the include group'
    2 = 'REASON_IN_BLACK_LIST - user is a member of the exclude group'
    3 = 'REASON_LOCAL_PROFILE_EXISTS - a local profile for this user exists on this system'
    4 = 'REASON_SHORT_SID - not an appropriate user type'
    5 = 'REASON_UNSET - reason initialised to empty state'
    6 = 'REASON_COMPONENT_NOT_ENABLED - component not enabled in product key (legacy)'
    7 = 'REASON_WINDOWS_TEMP_PROFILE - profile is a Windows temporary profile'
    8 = 'REASON_NOT_WVD_SESSION - session is not an Azure Virtual Desktop session'
    9 = 'REASON_FAILED_TO_LOAD_PROFILE - profile load failed'
}

# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------

$script:Results     = New-Object System.Collections.Generic.List[object]
$script:FixesApplied = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string]$Evidence = '',
        [string]$Recommendation = '',
        [string]$Reference = '',
        # Allow-listed fix descriptor: @{ Path=''; Name=''; Value=''; Type='DWord|String' }
        [hashtable]$Fix = $null
    )

    $obj = [PSCustomObject]@{
        Id             = $Id
        Category       = $Category
        Name           = $Name
        Status         = $Status
        Severity       = $Severity
        Weight         = $script:SeverityWeight[$Severity]
        Detail         = $Detail
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Reference      = $Reference
        Fixable        = [bool]$Fix
        Fix            = $Fix
        FixApplied     = $false
        FixError       = ''
    }
    $script:Results.Add($obj) | Out-Null

    if ($Fix -and $Status -ne 'PASS' -and $Remediate) {
        Invoke-AllowListedFix -Result $obj
    }

    if (-not $Quiet) {
        $colour = 'Gray'
        if ($Status -eq 'PASS') { $colour = 'Green' }
        if ($Status -eq 'WARN') { $colour = 'Yellow' }
        if ($Status -eq 'FAIL') { $colour = 'Red' }
        Write-Host ("[{0,-4}] {1,-9} {2,-16} {3}" -f $Status, $Severity, $Category, $Name) -ForegroundColor $colour
        Write-Host ("         {0}" -f $Detail) -ForegroundColor DarkGray
        if ($Recommendation -and $Status -ne 'PASS') {
            Write-Host ("         Fix: {0}" -f $Recommendation) -ForegroundColor Cyan
        }
    }
}

function Invoke-AllowListedFix {
    param($Result)

    if ($RemediateOnly.Count -gt 0 -and ($RemediateOnly -notcontains $Result.Id)) {
        return
    }

    $fix = $Result.Fix

    # Fixes carrying a Kind are not single registry values. They are applied by
    # their own handler later in the script, so skip them here. Without this
    # guard the registry handler would run against an empty path.
    if ($fix.ContainsKey('Kind')) { return }

    $target = "{0}\{1} = {2}" -f $fix.Path, $fix.Name, $fix.Value

    if (-not $PSCmdlet.ShouldProcess($target, "Set FSLogix registry value ($($Result.Id))")) {
        return
    }

    try {
        if (-not (Test-Path $fix.Path)) {
            New-Item -Path $fix.Path -Force | Out-Null
        }
        New-ItemProperty -Path $fix.Path -Name $fix.Name -Value $fix.Value `
            -PropertyType $fix.Type -Force -ErrorAction Stop | Out-Null
        $Result.FixApplied = $true
        $script:FixesApplied.Add([PSCustomObject]@{
            Id    = $Result.Id
            Path  = $fix.Path
            Name  = $fix.Name
            Value = $fix.Value
        }) | Out-Null
        if (-not $Quiet) { Write-Host ("         Applied: {0}" -f $target) -ForegroundColor Green }
    } catch {
        $Result.FixError = $_.Exception.Message
        if (-not $Quiet) { Write-Host ("         Fix failed: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    }
}

function Invoke-Check {
    # Runs a check body and converts an unhandled failure into one INFO row
    # rather than losing the report.
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    try {
        & $Body
    } catch {
        Add-Check -Id $Id -Category $Category -Name $Name -Status 'INFO' -Severity 'Info' `
            -Detail "Check could not complete on this host." `
            -Evidence $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    try {
        if (-not (Test-Path $Path)) { return $Default }
        # Read the whole key and look for the value, rather than asking for a
        # named value that may not exist. -ErrorAction SilentlyContinue hides
        # the message but still writes a record to $Error for every unset
        # value, which buries any genuine error in the transcript.
        $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $Default }
        $prop = $item.PSObject.Properties[$Name]
        if ($null -eq $prop) { return $Default }
        $val = $prop.Value
        if ($null -eq $val) { return $Default }
        return $val
    } catch {
        return $Default
    }
}

function ConvertTo-FlatString {
    # VHDLocations and CCDLocations may be REG_SZ or REG_MULTI_SZ.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [array]) { return (($Value | Where-Object { $_ }) -join ';') }
    return [string]$Value
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text
    $t = $t.Replace('&', '&amp;')
    $t = $t.Replace('<', '&lt;')
    $t = $t.Replace('>', '&gt;')
    $t = $t.Replace('"', '&quot;')
    return $t
}

function Test-TcpPort {
    # Test-NetConnection has no timeout and can block for 20 seconds or more.
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [int]$Port = 445,
        [int]$TimeoutMs = 5000
    )
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async  = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $ok     = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        if ($client) { $client.Close() }
    }
}

function Get-FirstStoragePath {
    param([string]$Locations)
    if (-not $Locations) { return '' }
    $first = ($Locations -split ';')[0]
    # Cloud Cache entries look like: type=smb,name="X",connectionString=\\server\share
    if ($first -match 'connectionString=(.+)$') {
        return $Matches[1].Trim('"')
    }
    return $first
}

function Compare-Version {
    # Returns -1, 0 or 1. Tolerates non-numeric or short version strings.
    param([string]$Left, [string]$Right)
    try {
        $l = [version]$Left
        $r = [version]$Right
        return $l.CompareTo($r)
    } catch {
        return 0
    }
}

# Data-driven recommended-value comparison used for the simple registry rules.
function Test-RecommendedSetting {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)]$Recommended,
        [Parameter(Mandatory = $true)]$MicrosoftDefault,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Why,
        [ValidateSet('DWord', 'String')][string]$Type = 'DWord',
        [switch]$CaseInsensitiveString,
        [switch]$NoFix,
        [string]$Reference = $DOC_EXAMPLES
    )

    $current = Get-RegValue -Path $Key -Name $ValueName -Default $null
    $isSet   = $null -ne $current
    $effective = if ($isSet) { $current } else { $MicrosoftDefault }

    $match = $false
    if ($CaseInsensitiveString) {
        $match = ([string]$effective).ToLower() -eq ([string]$Recommended).ToLower()
    } else {
        $match = ([string]$effective) -eq ([string]$Recommended)
    }

    $source = if ($isSet) { 'explicitly set' } else { 'not set, using the Microsoft default' }
    $evidence = "{0}\{1} = {2} ({3})" -f $Key, $ValueName, $effective, $source

    if ($match) {
        Add-Check -Id $Id -Category $Category -Name $ValueName -Status 'PASS' -Severity $Severity `
            -Detail "$ValueName is $effective, which matches Microsoft's recommended value." `
            -Evidence $evidence -Reference $Reference
        return
    }

    $fix = $null
    if (-not $NoFix) {
        $fix = @{ Path = $Key; Name = $ValueName; Value = $Recommended; Type = $Type }
    }

    $status = if ($Severity -eq 'Critical' -or $Severity -eq 'High') { 'FAIL' } else { 'WARN' }

    Add-Check -Id $Id -Category $Category -Name $ValueName -Status $status -Severity $Severity `
        -Detail "$ValueName is $effective. Microsoft recommends $Recommended. $Why" `
        -Evidence $evidence `
        -Recommendation "Set $ValueName to $Recommended at $Key." `
        -Reference $Reference -Fix $fix
}

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

$defaultOutDir = 'C:\ProgramData\FSLogixHealthCheck'
$stamp         = Get-Date -Format 'yyyyMMdd-HHmmss'

if (-not $ReportPath) { $ReportPath = $defaultOutDir }
if (-not $JsonPath)   { $JsonPath   = $ReportPath }

foreach ($d in @($ReportPath, $JsonPath)) {
    try {
        if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    } catch {
        Write-Warning "Could not create output directory $d : $($_.Exception.Message)"
    }
}

$htmlFile = Join-Path $ReportPath ("FSLogix-HealthCheck-{0}-{1}.html" -f $env:COMPUTERNAME, $stamp)
$jsonFile = Join-Path $JsonPath   ("FSLogix-HealthCheck-{0}-{1}.json" -f $env:COMPUTERNAME, $stamp)

if (-not $Quiet) {
    Write-Host ""
    Write-Host ("FSLogix Health Check v{0} - {1} - {2}" -f $script:SchemaVersion, $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 0. Host context
# ---------------------------------------------------------------------------

$hostContext = [ordered]@{
    ComputerName   = $env:COMPUTERNAME
    OSCaption      = ''
    OSVersion      = ''
    IsMultiSession = $false
    IsAvdHost      = $false
    EntraJoined    = $false
    DomainJoined   = $false
    SystemDriveFreeGB = 0
}

Invoke-Check -Id 'HOST-OS' -Category 'Host' -Name 'Operating system' -Body {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $hostContext.OSCaption = $os.Caption
    $hostContext.OSVersion = $os.Version
    $hostContext.IsMultiSession = ($os.Caption -match 'multi-session')

    $sysDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction SilentlyContinue
    if ($sysDrive) {
        $hostContext.SystemDriveFreeGB = [math]::Round($sysDrive.FreeSpace / 1GB, 1)
    }

    Add-Check -Id 'HOST-OS' -Category 'Host' -Name 'Operating system' -Status 'INFO' -Severity 'Info' `
        -Detail "$($os.Caption) build $($os.Version)." `
        -Evidence ("Multi-session: {0}. System drive free: {1} GB." -f $hostContext.IsMultiSession, $hostContext.SystemDriveFreeGB)
}

Invoke-Check -Id 'HOST-JOIN' -Category 'Host' -Name 'Device join state' -Body {
    $dsreg = & dsregcmd /status 2>$null
    foreach ($line in $dsreg) {
        if ($line -match 'AzureAdJoined\s*:\s*YES') { $hostContext.EntraJoined = $true }
        if ($line -match 'DomainJoined\s*:\s*YES')  { $hostContext.DomainJoined = $true }
    }
    $desc = 'Workgroup / unknown'
    if ($hostContext.EntraJoined -and $hostContext.DomainJoined) { $desc = 'Hybrid joined (domain and Entra)' }
    elseif ($hostContext.EntraJoined) { $desc = 'Entra joined (cloud only)' }
    elseif ($hostContext.DomainJoined) { $desc = 'Active Directory domain joined' }

    Add-Check -Id 'HOST-JOIN' -Category 'Host' -Name 'Device join state' -Status 'INFO' -Severity 'Info' `
        -Detail "$desc. Join state changes which storage authentication path applies." `
        -Evidence ("AzureAdJoined={0}; DomainJoined={1}" -f $hostContext.EntraJoined, $hostContext.DomainJoined)
}

Invoke-Check -Id 'HOST-AVD' -Category 'Host' -Name 'AVD agent present' -Body {
    $hostContext.IsAvdHost = [bool](Get-Service -Name 'RDAgentBootLoader' -ErrorAction SilentlyContinue)
    Add-Check -Id 'HOST-AVD' -Category 'Host' -Name 'AVD agent present' -Status 'INFO' -Severity 'Info' `
        -Detail $(if ($hostContext.IsAvdHost) { 'RDAgentBootLoader is present, so this is an AVD session host.' } else { 'No AVD agent found. Treating this as RDS or a standalone multi-user host.' })
}

Invoke-Check -Id 'HOST-SYSFREE' -Category 'Host' -Name 'System drive free space' -Body {
    $freeGB = $hostContext.SystemDriveFreeGB
    if ($freeGB -le 0) {
        Add-Check -Id 'HOST-SYSFREE' -Category 'Host' -Name 'System drive free space' -Status 'INFO' -Severity 'Info' `
            -Detail 'Free space on the system drive could not be read.'
    } elseif ($freeGB -lt 5) {
        Add-Check -Id 'HOST-SYSFREE' -Category 'Host' -Name 'System drive free space' -Status 'FAIL' -Severity 'High' `
            -Detail "Only $freeGB GB free on $($env:SystemDrive). FSLogix needs local space for the local_%username% redirect folder, difference disks and, with Cloud Cache, the local cache VHD(X)." `
            -Recommendation 'Free space on the system drive or grow the OS disk.'
    } elseif ($freeGB -lt 15) {
        Add-Check -Id 'HOST-SYSFREE' -Category 'Host' -Name 'System drive free space' -Status 'WARN' -Severity 'Medium' `
            -Detail "$freeGB GB free on $($env:SystemDrive). Tight for a multi-session host."
    } else {
        Add-Check -Id 'HOST-SYSFREE' -Category 'Host' -Name 'System drive free space' -Status 'PASS' -Severity 'Medium' `
            -Detail "$freeGB GB free on $($env:SystemDrive)."
    }
}

# ---------------------------------------------------------------------------
# 1. Installation
# ---------------------------------------------------------------------------

$fslogixInstalled = Test-Path $RK_APPS
$fslogixVersion   = 'unknown'

if (-not $fslogixInstalled) {
    Add-Check -Id 'INST-PRESENT' -Category 'Install' -Name 'FSLogix installed' -Status 'FAIL' -Severity 'Critical' `
        -Detail "No FSLogix installation found at $RK_APPS. Every other check is skipped." `
        -Recommendation 'Install FSLogix from https://aka.ms/fslogix-latest.' -Reference $DOC_RELEASE
} else {
    $fslogixVersion = ConvertTo-FlatString (Get-RegValue -Path $RK_APPS -Name 'InstallVersion' -Default 'unknown')
    $installPath    = ConvertTo-FlatString (Get-RegValue -Path $RK_APPS -Name 'InstallPath' -Default '')

    Add-Check -Id 'INST-PRESENT' -Category 'Install' -Name 'FSLogix installed' -Status 'PASS' -Severity 'Critical' `
        -Detail "FSLogix is installed." -Evidence "Version $fslogixVersion at $installPath"

    Invoke-Check -Id 'INST-VERSION' -Category 'Install' -Name 'Agent version' -Body {
        $cmp = Compare-Version -Left $fslogixVersion -Right $MinimumFSLogixVersion
        if ($fslogixVersion -eq 'unknown') {
            Add-Check -Id 'INST-VERSION' -Category 'Install' -Name 'Agent version' -Status 'INFO' -Severity 'Info' `
                -Detail 'The installed version could not be read from the registry.'
        } elseif ($cmp -lt 0) {
            Add-Check -Id 'INST-VERSION' -Category 'Install' -Name 'Agent version' -Status 'WARN' -Severity 'Medium' `
                -Detail "Installed version $fslogixVersion is older than the configured baseline $MinimumFSLogixVersion. Microsoft requires the latest version before it will accept a support case." `
                -Evidence 'This check compares against the -MinimumFSLogixVersion parameter, not a live query of Microsoft. Keep that baseline current.' `
                -Recommendation 'Upgrade FSLogix from https://aka.ms/fslogix-latest.' -Reference $DOC_RELEASE
        } else {
            Add-Check -Id 'INST-VERSION' -Category 'Install' -Name 'Agent version' -Status 'PASS' -Severity 'Medium' `
                -Detail "Installed version $fslogixVersion meets or exceeds the configured baseline $MinimumFSLogixVersion." -Reference $DOC_RELEASE
        }
    }
}

# ---------------------------------------------------------------------------
# Everything below requires FSLogix to be installed.
# ---------------------------------------------------------------------------

$vhdLocations   = ''
$ccdLocations   = ''
$usingCloudCache = $false
$storageRoot    = ''

if ($fslogixInstalled) {

    # -----------------------------------------------------------------------
    # 2. Core configuration
    # -----------------------------------------------------------------------

    Invoke-Check -Id 'CFG-ENABLED' -Category 'Configuration' -Name 'Profile Container enabled' -Body {
        $enabled = Get-RegValue -Path $RK_PROFILES -Name 'Enabled' -Default 0
        if ([int]$enabled -eq 1) {
            Add-Check -Id 'CFG-ENABLED' -Category 'Configuration' -Name 'Profile Container enabled' -Status 'PASS' -Severity 'Critical' `
                -Detail 'Enabled = 1. Profile Container is active.' -Evidence "$RK_PROFILES\Enabled = 1"
        } else {
            Add-Check -Id 'CFG-ENABLED' -Category 'Configuration' -Name 'Profile Container enabled' -Status 'FAIL' -Severity 'Critical' `
                -Detail "Enabled is $enabled, not 1. Profile Container is not active on this host, so users are getting local profiles." `
                -Evidence "$RK_PROFILES\Enabled = $enabled" `
                -Recommendation 'Set Enabled to 1.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'Enabled'; Value = 1; Type = 'DWord' }
        }
    }

    Invoke-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Body {
        $vhdLocations = ConvertTo-FlatString (Get-RegValue -Path $RK_PROFILES -Name 'VHDLocations' -Default '')
        $ccdLocations = ConvertTo-FlatString (Get-RegValue -Path $RK_PROFILES -Name 'CCDLocations' -Default '')
        $script:vhdLocations = $vhdLocations
        $script:ccdLocations = $ccdLocations
        $script:usingCloudCache = [bool]$ccdLocations

        if ($vhdLocations -and $ccdLocations) {
            Add-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Status 'FAIL' -Severity 'Critical' `
                -Detail 'Both VHDLocations and CCDLocations are set. Microsoft states these must not both be present. FSLogix behaviour is undefined.' `
                -Evidence "VHDLocations: $vhdLocations | CCDLocations: $ccdLocations" `
                -Recommendation 'Remove whichever value does not match the intended mode.' -Reference $DOC_SETTINGS
        } elseif (-not $vhdLocations -and -not $ccdLocations) {
            Add-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Status 'FAIL' -Severity 'Critical' `
                -Detail 'Neither VHDLocations nor CCDLocations is set. FSLogix has nowhere to store the profile container.' `
                -Recommendation 'Set VHDLocations (standard) or CCDLocations (Cloud Cache).' -Reference $DOC_SETTINGS
        } elseif ($script:usingCloudCache) {
            $providerCount = @($ccdLocations -split ';' | Where-Object { $_ -match 'type=' }).Count
            $sev = 'PASS'
            $msg = "Cloud Cache mode with $providerCount storage provider(s)."
            if ($providerCount -lt 2) {
                $sev = 'WARN'
                $msg = "Cloud Cache mode with only $providerCount storage provider. Cloud Cache exists to replicate across providers; a single provider adds the local-cache complexity without the resilience it is there to buy."
            }
            Add-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Status $sev -Severity 'High' `
                -Detail $msg -Evidence "CCDLocations: $ccdLocations" -Reference $DOC_EXAMPLES
        } else {
            $pathCount = @($vhdLocations -split ';' | Where-Object { $_ }).Count
            if ($pathCount -gt 1) {
                Add-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Status 'WARN' -Severity 'Medium' `
                    -Detail "Standard mode with $pathCount VHDLocations entries. Microsoft warns that multiple entries do NOT provide resilience: a user who can reach more than one location may create a second profile in the wrong place. Object-specific settings are the supported way to split users across shares." `
                    -Evidence "VHDLocations: $vhdLocations" `
                    -Recommendation 'Use ObjectSpecific settings per user or group SID instead of multiple VHDLocations entries.' -Reference $DOC_EXAMPLES
            } else {
                Add-Check -Id 'CFG-STORAGEMODE' -Category 'Configuration' -Name 'Storage location mode' -Status 'PASS' -Severity 'High' `
                    -Detail 'Standard mode with a single VHDLocations path.' -Evidence "VHDLocations: $vhdLocations"
            }
        }
    }

    $vhdLocations    = $script:vhdLocations
    $ccdLocations    = $script:ccdLocations
    $usingCloudCache = $script:usingCloudCache
    # Note: a bare "(if ...)" is NOT a valid argument expression in Windows
    # PowerShell 5.1 - it parses, then fails at runtime with "the term 'if' is
    # not recognized". Assign first.
    $activeLocations = $vhdLocations
    if ($usingCloudCache) { $activeLocations = $ccdLocations }
    $storageRoot = Get-FirstStoragePath $activeLocations

    # Recommended-value rules straight from Microsoft's configuration examples.
    Invoke-Check -Id 'CFG-VOLUMETYPE' -Category 'Configuration' -Name 'VolumeType' -Body {
        Test-RecommendedSetting -Id 'CFG-VOLUMETYPE' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'VolumeType' -Recommended 'VHDX' -MicrosoftDefault 'VHD' -Type 'String' -CaseInsensitiveString `
            -Severity 'Medium' `
            -Why 'VHDX supports larger containers and is markedly more resistant to corruption. This only affects containers created after the change; existing VHD containers are unaffected.'
    }

    Invoke-Check -Id 'CFG-DELETELOCAL' -Category 'Configuration' -Name 'DeleteLocalProfileWhenVHDShouldApply' -Body {
        $v = Get-RegValue -Path $RK_PROFILES -Name 'DeleteLocalProfileWhenVHDShouldApply' -Default 0
        if ([int]$v -eq 1) {
            Add-Check -Id 'CFG-DELETELOCAL' -Category 'Configuration' -Name 'DeleteLocalProfileWhenVHDShouldApply' -Status 'PASS' -Severity 'High' `
                -Detail 'Set to 1, which is Microsoft s recommended value. A stale local profile cannot silently win over the container.' `
                -Evidence "$RK_PROFILES\DeleteLocalProfileWhenVHDShouldApply = 1" -Reference $DOC_EXAMPLES
        } else {
            # Deliberately NOT auto-fixable. Enabling this permanently deletes local profiles.
            Add-Check -Id 'CFG-DELETELOCAL' -Category 'Configuration' -Name 'DeleteLocalProfileWhenVHDShouldApply' -Status 'WARN' -Severity 'High' `
                -Detail "Set to $v. Microsoft recommends 1. When a local profile already exists for a user, FSLogix uses it instead of the container, which is the usual cause of a 'my changes did not roam' ticket." `
                -Evidence 'Not auto-remediated by design: enabling this permanently deletes the matching local profile at next sign-in.' `
                -Recommendation 'Confirm no user depends on a local profile on this host, then set the value to 1.' -Reference $DOC_EXAMPLES
        }
    }

    Invoke-Check -Id 'CFG-FLIPFLOP' -Category 'Configuration' -Name 'FlipFlopProfileDirectoryName' -Body {
        Test-RecommendedSetting -Id 'CFG-FLIPFLOP' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'FlipFlopProfileDirectoryName' -Recommended 1 -MicrosoftDefault 0 -Severity 'Low' `
            -Why 'Names the container folder username_SID instead of SID_username, which makes the share readable to a human during an incident.'
    }

    Invoke-Check -Id 'CFG-LOCKEDRETRYCOUNT' -Category 'Configuration' -Name 'LockedRetryCount' -Body {
        Test-RecommendedSetting -Id 'CFG-LOCKEDRETRYCOUNT' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'LockedRetryCount' -Recommended 3 -MicrosoftDefault 12 -Severity 'Medium' `
            -Why 'The default of 12 makes a locked container fail slowly. The user sits at a hanging sign-in instead of getting a clear failure.'
    }

    Invoke-Check -Id 'CFG-LOCKEDRETRYINTERVAL' -Category 'Configuration' -Name 'LockedRetryInterval' -Body {
        Test-RecommendedSetting -Id 'CFG-LOCKEDRETRYINTERVAL' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'LockedRetryInterval' -Recommended 15 -MicrosoftDefault 15 -Severity 'Low' `
            -Why 'Paired with LockedRetryCount to keep a locked-container failure fast and predictable.'
    }

    Invoke-Check -Id 'CFG-REATTACHCOUNT' -Category 'Configuration' -Name 'ReAttachRetryCount' -Body {
        Test-RecommendedSetting -Id 'CFG-REATTACHCOUNT' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'ReAttachRetryCount' -Recommended 3 -MicrosoftDefault 60 -Severity 'Medium' `
            -Why 'The default of 60 retries keeps a broken session alive for many minutes after the container has gone.'
    }

    Invoke-Check -Id 'CFG-REATTACHINTERVAL' -Category 'Configuration' -Name 'ReAttachIntervalSeconds' -Body {
        Test-RecommendedSetting -Id 'CFG-REATTACHINTERVAL' -Category 'Configuration' -Key $RK_PROFILES `
            -ValueName 'ReAttachIntervalSeconds' -Recommended 15 -MicrosoftDefault 10 -Severity 'Low' `
            -Why 'Paired with ReAttachRetryCount for a predictable reattach window.'
    }

    Invoke-Check -Id 'CFG-PREVENTFAILURE' -Category 'Configuration' -Name 'PreventLoginWithFailure' -Body {
        $v = Get-RegValue -Path $RK_PROFILES -Name 'PreventLoginWithFailure' -Default 0
        if ([int]$v -eq 1) {
            Add-Check -Id 'CFG-PREVENTFAILURE' -Category 'Configuration' -Name 'PreventLoginWithFailure' -Status 'PASS' -Severity 'High' `
                -Detail 'Set to 1. A container that fails to attach stops the sign-in with a clear message instead of silently degrading.' -Reference $DOC_SETTINGS
        } else {
            Add-Check -Id 'CFG-PREVENTFAILURE' -Category 'Configuration' -Name 'PreventLoginWithFailure' -Status 'WARN' -Severity 'High' `
                -Detail "Set to $v (Microsoft default). When the container fails to attach the user signs in anyway with a profile that will not save. The data loss is discovered later, by the user." `
                -Evidence 'Consider this alongside PreventLoginWithTempProfile. Turning either on is a deliberate policy decision: users are blocked rather than silently degraded.' `
                -Recommendation 'Set PreventLoginWithFailure to 1 once your service desk is ready for the blocked-sign-in call.' `
                -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'PreventLoginWithFailure'; Value = 1; Type = 'DWord' }
        }
    }

    Invoke-Check -Id 'CFG-PREVENTTEMP' -Category 'Configuration' -Name 'PreventLoginWithTempProfile' -Body {
        $v = Get-RegValue -Path $RK_PROFILES -Name 'PreventLoginWithTempProfile' -Default 0
        if ([int]$v -eq 1) {
            Add-Check -Id 'CFG-PREVENTTEMP' -Category 'Configuration' -Name 'PreventLoginWithTempProfile' -Status 'PASS' -Severity 'High' `
                -Detail 'Set to 1. A temporary profile stops the sign-in rather than handing the user a disposable desktop.' -Reference $DOC_SETTINGS
        } else {
            Add-Check -Id 'CFG-PREVENTTEMP' -Category 'Configuration' -Name 'PreventLoginWithTempProfile' -Status 'WARN' -Severity 'High' `
                -Detail "Set to $v (Microsoft default). Users land on a Windows temporary profile and lose everything at sign-out, usually without noticing until the next day." `
                -Recommendation 'Set PreventLoginWithTempProfile to 1.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'PreventLoginWithTempProfile'; Value = 1; Type = 'DWord' }
        }
    }

    Invoke-Check -Id 'CFG-SIZEINMBS' -Category 'Configuration' -Name 'SizeInMBs' -Body {
        $v = Get-RegValue -Path $RK_PROFILES -Name 'SizeInMBs' -Default 30000
        $set = $null -ne (Get-RegValue -Path $RK_PROFILES -Name 'SizeInMBs' -Default $null)
        $src = if ($set) { 'explicitly set' } else { 'not set, using the Microsoft default of 30000' }
        if ([int]$v -lt 5000) {
            Add-Check -Id 'CFG-SIZEINMBS' -Category 'Configuration' -Name 'SizeInMBs' -Status 'WARN' -Severity 'Medium' `
                -Detail "SizeInMBs is $v MB. That is small for a profile container, and the ceiling can be raised later but never lowered." `
                -Evidence "$RK_PROFILES\SizeInMBs = $v ($src)" `
                -Recommendation 'Raise SizeInMBs to 30000 (30 GB), the Microsoft default.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'SizeInMBs'; Value = 30000; Type = 'DWord' }
        } else {
            Add-Check -Id 'CFG-SIZEINMBS' -Category 'Configuration' -Name 'SizeInMBs' -Status 'PASS' -Severity 'Medium' `
                -Detail "SizeInMBs is $v MB." -Evidence "$RK_PROFILES\SizeInMBs = $v ($src)"
        }
    }

    Invoke-Check -Id 'CFG-ISDYNAMIC' -Category 'Configuration' -Name 'IsDynamic' -Body {
        $v = Get-RegValue -Path $RK_PROFILES -Name 'IsDynamic' -Default 1
        if ([int]$v -eq 1) {
            Add-Check -Id 'CFG-ISDYNAMIC' -Category 'Configuration' -Name 'IsDynamic' -Status 'PASS' -Severity 'Medium' `
                -Detail 'IsDynamic is 1. Containers consume only the space they use, up to SizeInMBs.'
        } else {
            Add-Check -Id 'CFG-ISDYNAMIC' -Category 'Configuration' -Name 'IsDynamic' -Status 'WARN' -Severity 'Medium' `
                -Detail "IsDynamic is $v, so every container is fully allocated at SizeInMBs on the share. With a 30 GB ceiling that is 30 GB of storage billed per user from day one." `
                -Recommendation 'Set IsDynamic to 1 unless a fixed allocation is a deliberate storage decision.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'IsDynamic'; Value = 1; Type = 'DWord' }
        }
    }

    Invoke-Check -Id 'CFG-PROFILETYPE' -Category 'Configuration' -Name 'ProfileType' -Body {
        $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'ProfileType' -Default 0)
        if ($v -eq 0) {
            Add-Check -Id 'CFG-PROFILETYPE' -Category 'Configuration' -Name 'ProfileType' -Status 'PASS' -Severity 'Medium' `
                -Detail 'ProfileType is 0 (normal). Single connection per container, which is the Microsoft default and recommendation.'
        } elseif ($hostContext.IsAvdHost) {
            Add-Check -Id 'CFG-PROFILETYPE' -Category 'Configuration' -Name 'ProfileType' -Status 'WARN' -Severity 'High' `
                -Detail "ProfileType is $v (concurrent-capable) on a host running the AVD agent. Microsoft states AVD does not support multiple connections within the same host pool, so this buys nothing here and can mask genuine multi-session faults." `
                -Recommendation 'Set ProfileType to 0 unless this host is deliberately part of a multi-connection design outside AVD.' -Reference $DOC_EXAMPLES
        } else {
            Add-Check -Id 'CFG-PROFILETYPE' -Category 'Configuration' -Name 'ProfileType' -Status 'INFO' -Severity 'Info' `
                -Detail "ProfileType is $v (concurrent-capable). Every session sharing the container must use a matching ProfileType. OneDrive does not support concurrent connections to the same profile under any circumstances." -Reference $DOC_SETTINGS
        }
    }

    Invoke-Check -Id 'CFG-ROAMIDENTITY' -Category 'Configuration' -Name 'RoamIdentity' -Body {
        $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'RoamIdentity' -Default 0)
        if ($v -eq 0) {
            Add-Check -Id 'CFG-ROAMIDENTITY' -Category 'Configuration' -Name 'RoamIdentity' -Status 'PASS' -Severity 'Medium' `
                -Detail 'RoamIdentity is 0, the Microsoft default.'
        } elseif ($hostContext.EntraJoined -and -not $hostContext.DomainJoined) {
            Add-Check -Id 'CFG-ROAMIDENTITY' -Category 'Configuration' -Name 'RoamIdentity' -Status 'FAIL' -Severity 'High' `
                -Detail 'RoamIdentity is 1 on a host that is Entra joined and not domain joined. Identity roaming conflicts with cloud token handling on this join type.' `
                -Recommendation 'Set RoamIdentity to 0.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'RoamIdentity'; Value = 0; Type = 'DWord' }
        } else {
            Add-Check -Id 'CFG-ROAMIDENTITY' -Category 'Configuration' -Name 'RoamIdentity' -Status 'WARN' -Severity 'Medium' `
                -Detail 'RoamIdentity is 1. Confirm this is deliberate.' -Reference $DOC_SETTINGS
        }
    }

    Invoke-Check -Id 'CFG-ROAMSEARCH' -Category 'Configuration' -Name 'RoamSearch' -Body {
        $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'RoamSearch' -Default 0)
        if ($v -eq 0) {
            Add-Check -Id 'CFG-ROAMSEARCH' -Category 'Configuration' -Name 'RoamSearch' -Status 'PASS' -Severity 'Low' `
                -Detail 'RoamSearch is 0. Microsoft states search roaming is no longer necessary on Windows Server 2019 1809 and later, or Windows 10 and 11 multi-session.'
        } else {
            Add-Check -Id 'CFG-ROAMSEARCH' -Category 'Configuration' -Name 'RoamSearch' -Status 'WARN' -Severity 'Low' `
                -Detail "RoamSearch is $v. On current Windows builds this is unnecessary and adds container size and sign-out time." `
                -Recommendation 'Set RoamSearch to 0 on supported Windows builds.' -Reference $DOC_SETTINGS `
                -Fix @{ Path = $RK_PROFILES; Name = 'RoamSearch'; Value = 0; Type = 'DWord' }
        }
    }

    Invoke-Check -Id 'CFG-COMPUTEROBJECT' -Category 'Configuration' -Name 'AccessNetworkAsComputerObject' -Body {
        $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'AccessNetworkAsComputerObject' -Default 0)
        if ($v -eq 1) {
            Add-Check -Id 'CFG-COMPUTEROBJECT' -Category 'Configuration' -Name 'AccessNetworkAsComputerObject' -Status 'WARN' -Severity 'High' `
                -Detail 'Set to 1. Microsoft flags this as a security risk: the machine account can reach every container on the storage provider, not only the signed-in user s own.' `
                -Recommendation 'Use user-level permissions unless the storage provider genuinely cannot support them.' -Reference $DOC_SETTINGS
        } else {
            Add-Check -Id 'CFG-COMPUTEROBJECT' -Category 'Configuration' -Name 'AccessNetworkAsComputerObject' -Status 'PASS' -Severity 'High' `
                -Detail 'Set to 0. Containers are accessed with user-level permissions.'
        }
    }

    Invoke-Check -Id 'CFG-OBJECTSPECIFIC' -Category 'Configuration' -Name 'Object-specific overrides' -Body {
        $osKey = Join-Path $RK_PROFILES 'ObjectSpecific'
        if (-not (Test-Path $osKey)) {
            Add-Check -Id 'CFG-OBJECTSPECIFIC' -Category 'Configuration' -Name 'Object-specific overrides' -Status 'PASS' -Severity 'Medium' `
                -Detail 'No ObjectSpecific overrides. Every check above reflects the effective setting for all users on this host.'
            return
        }
        $subs = @(Get-ChildItem -Path $osKey -ErrorAction SilentlyContinue)
        if ($subs.Count -eq 0) {
            Add-Check -Id 'CFG-OBJECTSPECIFIC' -Category 'Configuration' -Name 'Object-specific overrides' -Status 'PASS' -Severity 'Medium' `
                -Detail 'The ObjectSpecific key exists but contains no SID overrides.'
            return
        }
        $lines = @()
        foreach ($s in $subs) {
            $props = @()
            try {
                $p = Get-ItemProperty -Path $s.PSPath -ErrorAction SilentlyContinue
                foreach ($n in ($p.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
                    $props += ("{0}={1}" -f $n, (ConvertTo-FlatString $p.$n))
                }
            } catch { }
            $lines += ("{0}: {1}" -f $s.PSChildName, ($props -join ', '))
        }
        Add-Check -Id 'CFG-OBJECTSPECIFIC' -Category 'Configuration' -Name 'Object-specific overrides' -Status 'WARN' -Severity 'Medium' `
            -Detail "$($subs.Count) ObjectSpecific SID override(s) are present. Machine-level values reported by the other checks are NOT the effective settings for those users." `
            -Evidence ($lines -join ' | ') `
            -Recommendation 'Review each override against the machine-level configuration.' -Reference $DOC_EXAMPLES
    }

    Invoke-Check -Id 'CFG-REDIRXML' -Category 'Configuration' -Name 'RedirXMLSourceFolder' -Body {
        $folder = ConvertTo-FlatString (Get-RegValue -Path $RK_PROFILES -Name 'RedirXMLSourceFolder' -Default '')
        if (-not $folder) {
            Add-Check -Id 'CFG-REDIRXML' -Category 'Configuration' -Name 'RedirXMLSourceFolder' -Status 'PASS' -Severity 'Low' `
                -Detail 'No custom redirections.xml configured. Microsoft s advice is that fewer redirections is better.'
            return
        }
        $xml = Join-Path $folder 'redirections.xml'
        if (Test-Path $xml) {
            $valid = $true
            $err = ''
            try { [xml](Get-Content -Path $xml -Raw -ErrorAction Stop) | Out-Null } catch { $valid = $false; $err = $_.Exception.Message }
            if ($valid) {
                Add-Check -Id 'CFG-REDIRXML' -Category 'Configuration' -Name 'RedirXMLSourceFolder' -Status 'PASS' -Severity 'Medium' `
                    -Detail 'redirections.xml is present at the configured source folder and parses as valid XML.' -Evidence $xml
            } else {
                Add-Check -Id 'CFG-REDIRXML' -Category 'Configuration' -Name 'RedirXMLSourceFolder' -Status 'FAIL' -Severity 'High' `
                    -Detail 'redirections.xml is present but is not valid XML. FSLogix cannot apply it.' -Evidence "$xml : $err" `
                    -Recommendation 'Correct the XML at the source folder.' -Reference 'https://learn.microsoft.com/fslogix/concepts-redirections-xml'
            }
        } else {
            Add-Check -Id 'CFG-REDIRXML' -Category 'Configuration' -Name 'RedirXMLSourceFolder' -Status 'FAIL' -Severity 'High' `
                -Detail 'RedirXMLSourceFolder is set but no redirections.xml exists at that path, or this host cannot read it.' `
                -Evidence "Expected: $xml" `
                -Recommendation 'Publish redirections.xml to the source folder, or clear RedirXMLSourceFolder.' -Reference $DOC_SETTINGS
        }
    }

    Invoke-Check -Id 'CFG-ODFC' -Category 'Configuration' -Name 'ODFC container' -Body {
        $odfc = [int](Get-RegValue -Path $RK_ODFC -Name 'Enabled' -Default 0)
        if ($odfc -eq 1) {
            Add-Check -Id 'CFG-ODFC' -Category 'Configuration' -Name 'ODFC container' -Status 'WARN' -Severity 'Medium' `
                -Detail 'The ODFC (Office) container is enabled alongside Profile Container. Microsoft states the recommended configuration is a single container holding both profile and Office content. A second container doubles the attach operations at sign-in.' `
                -Evidence "$RK_ODFC\Enabled = 1" `
                -Recommendation 'Confirm a separate ODFC container is a deliberate requirement, for example a second roaming-profile product managing the same scope.' `
                -Reference 'https://learn.microsoft.com/fslogix/concepts-container-types'
        } else {
            Add-Check -Id 'CFG-ODFC' -Category 'Configuration' -Name 'ODFC container' -Status 'PASS' -Severity 'Medium' `
                -Detail 'ODFC container is not enabled. Profile and Office data share a single container, which is Microsoft s recommended configuration.'
        }
    }

    # -----------------------------------------------------------------------
    # 3. Cloud Cache
    # -----------------------------------------------------------------------

    if ($usingCloudCache) {

        Invoke-Check -Id 'CCD-DIRSEPARATION' -Category 'Cloud Cache' -Name 'Cache and proxy directory separation' -Body {
            $cacheDir = ConvertTo-FlatString (Get-RegValue -Path $RK_CCD_SVC  -Name 'CacheDirectory' -Default 'C:\ProgramData\FSLogix\Cache')
            $proxyDir = ConvertTo-FlatString (Get-RegValue -Path $RK_CCDS_SVC -Name 'ProxyDirectory' -Default 'C:\ProgramData\FSLogix\Proxy')
            if ($cacheDir.TrimEnd('\') -ieq $proxyDir.TrimEnd('\')) {
                Add-Check -Id 'CCD-DIRSEPARATION' -Category 'Cloud Cache' -Name 'Cache and proxy directory separation' -Status 'FAIL' -Severity 'Critical' `
                    -Detail 'CacheDirectory and ProxyDirectory resolve to the same path. Microsoft states these must not match: the cache file and the proxy file share a name and will collide.' `
                    -Evidence "CacheDirectory: $cacheDir | ProxyDirectory: $proxyDir" `
                    -Recommendation 'Point ProxyDirectory at a different folder.' -Reference $DOC_SETTINGS
            } else {
                Add-Check -Id 'CCD-DIRSEPARATION' -Category 'Cloud Cache' -Name 'Cache and proxy directory separation' -Status 'PASS' -Severity 'Critical' `
                    -Detail 'CacheDirectory and ProxyDirectory are different paths.' `
                    -Evidence "CacheDirectory: $cacheDir | ProxyDirectory: $proxyDir"
            }
        }

        Invoke-Check -Id 'CCD-CACHEFREE' -Category 'Cloud Cache' -Name 'Cache volume free space' -Body {
            $cacheDir = ConvertTo-FlatString (Get-RegValue -Path $RK_CCD_SVC -Name 'CacheDirectory' -Default 'C:\ProgramData\FSLogix\Cache')
            $root = [System.IO.Path]::GetPathRoot($cacheDir)
            $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($root.TrimEnd('\'))'" -ErrorAction SilentlyContinue
            if (-not $disk) {
                Add-Check -Id 'CCD-CACHEFREE' -Category 'Cloud Cache' -Name 'Cache volume free space' -Status 'INFO' -Severity 'Info' `
                    -Detail "Free space on the Cloud Cache volume ($root) could not be read."
                return
            }
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
            $status = 'PASS'
            if ($freeGB -lt 10) { $status = 'WARN' }
            if ($freeGB -lt 5)  { $status = 'FAIL' }
            Add-Check -Id 'CCD-CACHEFREE' -Category 'Cloud Cache' -Name 'Cache volume free space' -Status $status -Severity 'High' `
                -Detail "$freeGB GB free on $root. Every concurrent user holds a local cache VHD(X) here; the volume must be fast and must not fill." `
                -Evidence "CacheDirectory: $cacheDir" `
                -Recommendation 'Place the Cloud Cache on high-performance local storage with headroom for peak concurrency.' -Reference $DOC_SETTINGS
        }

        Invoke-Check -Id 'CCD-CLEARCACHE' -Category 'Cloud Cache' -Name 'ClearCacheOnLogoff' -Body {
            Test-RecommendedSetting -Id 'CCD-CLEARCACHE' -Category 'Cloud Cache' -Key $RK_PROFILES `
                -ValueName 'ClearCacheOnLogoff' -Recommended 1 -MicrosoftDefault 0 -Severity 'High' `
                -Why 'On pooled desktops the local cache VHD(X) is left behind at sign-out. It consumes local disk and holds user data on a host the user has left.'
        }

        Invoke-Check -Id 'CCD-HEALTHYREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForRegister' -Body {
            $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'HealthyProvidersRequiredForRegister' -Default 0)
            if ($v -ge 1) {
                Add-Check -Id 'CCD-HEALTHYREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForRegister' -Status 'PASS' -Severity 'High' `
                    -Detail "Set to $v. A sign-in is refused unless at least $v storage provider is healthy." -Reference $DOC_EXAMPLES
            } else {
                Add-Check -Id 'CCD-HEALTHYREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForRegister' -Status 'WARN' -Severity 'High' `
                    -Detail 'Set to 0 (Microsoft default). Users sign in even when NO Cloud Cache provider is reachable. Their work lands only in the local cache, and if no provider recovers before sign-out the sign-out is blocked indefinitely.' `
                    -Recommendation 'Set to 1, and pair it with PreventLoginWithFailure so the user gets a clear message rather than a hang.' `
                    -Reference $DOC_EXAMPLES `
                    -Fix @{ Path = $RK_PROFILES; Name = 'HealthyProvidersRequiredForRegister'; Value = 1; Type = 'DWord' }
            }
        }

        Invoke-Check -Id 'CCD-HEALTHYUNREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForUnregister' -Body {
            $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'HealthyProvidersRequiredForUnregister' -Default 1)
            if ($v -eq 0) {
                Add-Check -Id 'CCD-HEALTHYUNREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForUnregister' -Status 'FAIL' -Severity 'Critical' `
                    -Detail 'Set to 0. Microsoft explicitly advises against this: CcdUnregisterTimeout and ClearCacheOnForcedUnregister stop working, and session data held only in the local cache can be permanently deleted at sign-out.' `
                    -Recommendation 'Set to 1 or higher.' -Reference $DOC_SETTINGS `
                    -Fix @{ Path = $RK_PROFILES; Name = 'HealthyProvidersRequiredForUnregister'; Value = 1; Type = 'DWord' }
            } else {
                Add-Check -Id 'CCD-HEALTHYUNREGISTER' -Category 'Cloud Cache' -Name 'HealthyProvidersRequiredForUnregister' -Status 'PASS' -Severity 'Critical' `
                    -Detail "Set to $v. Sign-out waits for a healthy provider before discarding the local cache."
            }
        }

        Invoke-Check -Id 'CCD-UNREGTIMEOUT' -Category 'Cloud Cache' -Name 'CcdUnregisterTimeout' -Body {
            $v = [int](Get-RegValue -Path $RK_PROFILES -Name 'CcdUnregisterTimeout' -Default 0)
            if ($v -eq 0) {
                Add-Check -Id 'CCD-UNREGTIMEOUT' -Category 'Cloud Cache' -Name 'CcdUnregisterTimeout' -Status 'WARN' -Severity 'Medium' `
                    -Detail 'Set to 0 (Microsoft default). If the required number of healthy providers is not met, the sign-out is held indefinitely and the session host cannot drain.' `
                    -Recommendation 'Set a bounded timeout in seconds, and decide deliberately what ClearCacheOnForcedUnregister should do when it expires.' -Reference $DOC_SETTINGS
            } else {
                Add-Check -Id 'CCD-UNREGTIMEOUT' -Category 'Cloud Cache' -Name 'CcdUnregisterTimeout' -Status 'PASS' -Severity 'Medium' `
                    -Detail "Set to $v seconds. Sign-out is bounded."
            }
        }
    }

    # -----------------------------------------------------------------------
    # 4. Antivirus exclusions
    # -----------------------------------------------------------------------

    Invoke-Check -Id 'AV-ENGINE' -Category 'Antivirus' -Name 'Active antivirus engine' -Body {
        $products = @()
        try {
            $products = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        } catch { }
        if ($products.Count -gt 0) {
            Add-Check -Id 'AV-ENGINE' -Category 'Antivirus' -Name 'Active antivirus engine' -Status 'INFO' -Severity 'Info' `
                -Detail "Registered antivirus product(s): $(($products | ForEach-Object { $_.displayName }) -join ', ')." `
                -Evidence 'Only Windows Defender exposes its exclusion list to this host. Any other engine must be checked in its own console.'
        } else {
            Add-Check -Id 'AV-ENGINE' -Category 'Antivirus' -Name 'Active antivirus engine' -Status 'INFO' -Severity 'Info' `
                -Detail 'No antivirus product registered in Security Center. This is normal on Windows Server.'
        }
    }

    Invoke-Check -Id 'AV-EXCLUSIONS' -Category 'Antivirus' -Name 'Defender exclusions' -Body {
        if (-not (Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'AV-EXCLUSIONS' -Category 'Antivirus' -Name 'Defender exclusions' -Status 'INFO' -Severity 'Info' `
                -Detail 'Windows Defender is not present on this host, so its exclusion list cannot be read.' `
                -Recommendation 'Apply Microsoft s full documented FSLogix exclusion list in whichever antivirus console is in use.' -Reference $DOC_PREREQ
            return
        }

        $mp = Get-MpPreference -ErrorAction Stop
        $exclProcesses = @(); if ($mp.ExclusionProcess) { $exclProcesses = @($mp.ExclusionProcess) }
        $exclPaths     = @(); if ($mp.ExclusionPath)    { $exclPaths     = @($mp.ExclusionPath) }

        # Full documented list. Source: overview-prerequisites.
        $expectedProcesses = @('frxsvc.exe', 'frxccds.exe')

        $expectedPaths = @(
            'C:\Program Files\FSLogix\Apps\',
            'C:\ProgramData\FSLogix\',
            'C:\Users\%username%\AppData\Local\FSLogix\',
            '%TEMP%\*\*.VHD',
            '%TEMP%\*\*.VHDX',
            '%WINDIR%\TEMP\*\*.VHD',
            '%WINDIR%\TEMP\*\*.VHDX'
        )
        # Driver files live under the Apps folder, which the folder exclusion covers,
        # but Microsoft lists them explicitly so they are reported explicitly.
        $expectedDrivers = @('frxdrv.sys', 'frxdrvvt.sys', 'frxccd.sys')

        if ($usingCloudCache) {
            $expectedPaths += '%ProgramData%\FSLogix\Cache\*'
            $expectedPaths += '%ProgramData%\FSLogix\Proxy\*'
        }

        # Share-side container patterns for whichever storage path is configured.
        $sharePathsToCover = @()
        $rawLocations = if ($usingCloudCache) { $ccdLocations } else { $vhdLocations }
        foreach ($seg in ($rawLocations -split ';')) {
            $p = Get-FirstStoragePath $seg
            if ($p -and $p -match '^\\\\') { $sharePathsToCover += $p.TrimEnd('\') }
        }

        function Test-ExclusionCovered {
            param([string]$Needle, [string[]]$Haystack)
            $n = $Needle.TrimEnd('\').ToLower()
            foreach ($h in $Haystack) {
                $hh = $h.TrimEnd('\').ToLower()
                if ($hh -eq $n) { return $true }
                # A folder exclusion covers everything beneath it.
                if ($n.StartsWith($hh + '\')) { return $true }
            }
            return $false
        }

        $missingProcesses = @()
        foreach ($p in $expectedProcesses) {
            if (-not (Test-ExclusionCovered -Needle $p -Haystack ($exclProcesses + $exclPaths))) { $missingProcesses += $p }
        }

        $missingPaths = @()
        foreach ($p in $expectedPaths) {
            if (-not (Test-ExclusionCovered -Needle $p -Haystack $exclPaths)) { $missingPaths += $p }
        }

        $missingShares = @()
        foreach ($s in $sharePathsToCover) {
            if (-not (Test-ExclusionCovered -Needle $s -Haystack $exclPaths)) { $missingShares += $s }
        }

        $missingDrivers = @()
        foreach ($d in $expectedDrivers) {
            if (-not (Test-ExclusionCovered -Needle $d -Haystack ($exclProcesses + $exclPaths))) { $missingDrivers += $d }
        }

        $allMissing = @($missingProcesses + $missingDrivers + $missingPaths + $missingShares)

        if ($allMissing.Count -eq 0) {
            Add-Check -Id 'AV-EXCLUSIONS' -Category 'Antivirus' -Name 'Defender exclusions' -Status 'PASS' -Severity 'Critical' `
                -Detail 'Every item on Microsoft s documented FSLogix exclusion list is covered by a Defender exclusion.' -Reference $DOC_PREREQ
        } else {
            $sev = if ($missingProcesses.Count -gt 0 -or $missingShares.Count -gt 0) { 'FAIL' } else { 'WARN' }
            Add-Check -Id 'AV-EXCLUSIONS' -Category 'Antivirus' -Name 'Defender exclusions' -Status $sev -Severity 'Critical' `
                -Detail "$($allMissing.Count) documented exclusion(s) are missing. Microsoft s own troubleshooting guidance names antivirus scanning as one of the most common causes of container corruption." `
                -Evidence ("Missing: " + ($allMissing -join '; ')) `
                -Recommendation 'Add the missing process, driver, folder and share exclusions. Re-run with -Remediate to add them automatically.' `
                -Reference $DOC_PREREQ `
                -Fix @{ Kind = 'DefenderExclusions'; Processes = ($missingProcesses + $missingDrivers); Paths = ($missingPaths + $missingShares) }
        }
    }

    Invoke-Check -Id 'AV-FILESERVER' -Category 'Antivirus' -Name 'Storage-side exclusions' -Body {
        Add-Check -Id 'AV-FILESERVER' -Category 'Antivirus' -Name 'Storage-side exclusions' -Status 'INFO' -Severity 'Info' `
            -Detail 'This check covers the session host only. Where containers sit on a Windows file server, the same VHD(X), .lock, .meta and .metadata exclusions must be applied to the antivirus protecting that server. A host-side pass does not prove the share is safe.' `
            -Reference $DOC_PREREQ
    }

    # -----------------------------------------------------------------------
    # 5. Storage
    # -----------------------------------------------------------------------

    if ($storageRoot -and $storageRoot -match '^\\\\([^\\]+)\\') {
        $storageServer = $Matches[1]
        $isAzureFiles  = $storageServer -match '\.file\.core\.windows\.net$'
        $portOpen      = $false

        Invoke-Check -Id 'STG-REACH' -Category 'Storage' -Name 'Share reachability (SMB 445)' -Body {
            $script:portOpen = Test-TcpPort -ComputerName $storageServer -Port 445 -TimeoutMs 5000
            if ($script:portOpen) {
                Add-Check -Id 'STG-REACH' -Category 'Storage' -Name 'Share reachability (SMB 445)' -Status 'PASS' -Severity 'Critical' `
                    -Detail "$storageServer answers on TCP 445." -Evidence $storageRoot
            } else {
                Add-Check -Id 'STG-REACH' -Category 'Storage' -Name 'Share reachability (SMB 445)' -Status 'FAIL' -Severity 'Critical' `
                    -Detail "$storageServer does not answer on TCP 445 within 5 seconds. No container can attach from this host." `
                    -Evidence $storageRoot `
                    -Recommendation 'Check DNS, routing, NSG or firewall rules, and any private endpoint configuration. This is network scope, not FSLogix scope.'
            }
        }
        $portOpen = $script:portOpen

        if ($portOpen) {

            Invoke-Check -Id 'STG-WRITE' -Category 'Storage' -Name 'Share write access' -Body {
                $testFile = Join-Path $storageRoot ("HealthCheck_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
                try {
                    [System.IO.File]::WriteAllText($testFile, 'fslogix health check')
                    Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
                    Add-Check -Id 'STG-WRITE' -Category 'Storage' -Name 'Share write access' -Status 'PASS' -Severity 'Critical' `
                        -Detail 'A test file was created and removed on the container share using the identity this check runs as.' `
                        -Evidence 'Note: a scripted action runs as SYSTEM (the computer account), so this proves computer-account access, not user access.'
                } catch {
                    Add-Check -Id 'STG-WRITE' -Category 'Storage' -Name 'Share write access' -Status 'FAIL' -Severity 'Critical' `
                        -Detail 'The share is reachable but this host cannot write to it. Reachability and write access are different faults.' `
                        -Evidence $_.Exception.Message `
                        -Recommendation 'Review share-level permissions (Azure RBAC role Storage File Data SMB Share Contributor for Azure Files) and NTFS ACLs.' `
                        -Reference $DOC_PERMS
                }
            }

            Invoke-Check -Id 'STG-FREESPACE' -Category 'Storage' -Name 'Container share free space' -Body {
                $fso   = New-Object -ComObject Scripting.FileSystemObject
                $drive = $null
                try {
                    $drive = $fso.GetDrive($storageRoot)
                } catch {
                    Add-Check -Id 'STG-FREESPACE' -Category 'Storage' -Name 'Container share free space' -Status 'INFO' -Severity 'Info' `
                        -Detail 'Free space on the container share could not be read from this host. The server answers on port 445, so the share name or the permissions are the likely cause.' `
                        -Evidence ("{0}: {1}" -f $storageRoot, $_.Exception.Message)
                    return
                }
                $freeGB  = [math]::Round($drive.FreeSpace / 1GB, 1)
                $totalGB = [math]::Round($drive.TotalSize / 1GB, 1)
                $pctFree = 0
                if ($totalGB -gt 0) { $pctFree = [math]::Round(($freeGB / $totalGB) * 100, 1) }

                $status = 'PASS'
                if ($freeGB -lt 2 -or $pctFree -lt 30) { $status = 'WARN' }
                if ($freeGB -lt 0.5 -or $pctFree -lt 10) { $status = 'FAIL' }

                Add-Check -Id 'STG-FREESPACE' -Category 'Storage' -Name 'Container share free space' -Status $status -Severity 'High' `
                    -Detail "$freeGB GB free of $totalGB GB ($pctFree per cent). A full container share produces sign-in failures across the whole pool at once." `
                    -Evidence $storageRoot `
                    -Recommendation 'Grow the share, or reclaim space with container compaction and removal of containers for leavers.'
            }

            if ($isAzureFiles) {
                Invoke-Check -Id 'STG-KERBEROS' -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Body {
                    $enc = Get-RegValue -Path $RK_KERBEROS -Name 'SupportedEncryptionTypes' -Default $null
                    if ($null -eq $enc) {
                        Add-Check -Id 'STG-KERBEROS' -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'WARN' -Severity 'High' `
                            -Detail 'SupportedEncryptionTypes is not set, so this host uses the operating system default, which can still permit RC4. Microsoft is changing the default Kerberos encryption type from RC4 to AES-SHA1 in the April 2026 Windows Server update. Shares not upgraded to AES-SHA1 may lose access.' `
                            -Recommendation 'Confirm both the storage account and this host support AES-SHA1 before that update is installed.' `
                            -Reference 'https://learn.microsoft.com/fslogix/overview-release-notes'
                        return
                    }
                    $hasRc4 = (([int]$enc -band 4) -ne 0)
                    $hasAes = ((([int]$enc -band 8) -ne 0) -or (([int]$enc -band 16) -ne 0))
                    if ($hasAes) {
                        Add-Check -Id 'STG-KERBEROS' -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'PASS' -Severity 'High' `
                            -Detail "SupportedEncryptionTypes is $enc, which includes AES." -Evidence "RC4 also permitted: $hasRc4"
                    } else {
                        Add-Check -Id 'STG-KERBEROS' -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'FAIL' -Severity 'High' `
                            -Detail "SupportedEncryptionTypes is $enc, which permits RC4 and no AES. The April 2026 Windows Server Kerberos hardening update will break access to this share." `
                            -Recommendation 'Move the host and the storage account to AES-SHA1 before installing that update.'
                    }
                }

                if ($hostContext.EntraJoined -and -not $hostContext.DomainJoined) {
                    Invoke-Check -Id 'STG-ENTRAKERB' -Category 'Storage' -Name 'Entra Kerberos client settings' -Body {
                        $cloudKerb = Get-RegValue -Path $RK_KERBEROS -Name 'CloudKerberosTicketRetrievalEnabled' -Default 0
                        $loadCred  = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\AzureADAccount' -Name 'LoadCredKeyFromProfile' -Default 0
                        $missing = @()
                        if ([int]$cloudKerb -ne 1) { $missing += 'CloudKerberosTicketRetrievalEnabled' }
                        if ([int]$loadCred  -ne 1) { $missing += 'LoadCredKeyFromProfile' }

                        if ($missing.Count -eq 0) {
                            Add-Check -Id 'STG-ENTRAKERB' -Category 'Storage' -Name 'Entra Kerberos client settings' -Status 'PASS' -Severity 'Critical' `
                                -Detail 'Both client-side settings Microsoft requires for Entra Kerberos against Azure Files are set.'
                        } else {
                            Add-Check -Id 'STG-ENTRAKERB' -Category 'Storage' -Name 'Entra Kerberos client settings' -Status 'FAIL' -Severity 'Critical' `
                                -Detail "This host is Entra joined and uses Azure Files, but $($missing -join ' and ') is not set to 1. Microsoft documents both as required. Without LoadCredKeyFromProfile the credential keys in Credential Manager do not follow the roaming profile." `
                                -Evidence "CloudKerberosTicketRetrievalEnabled=$cloudKerb; LoadCredKeyFromProfile=$loadCred" `
                                -Recommendation 'Set both values to 1 via Intune settings catalog, Group Policy or the registry.' `
                                -Reference 'https://learn.microsoft.com/fslogix/how-to-configure-profile-container-entra-id-hybrid'
                        }
                    }
                }
            }

            if ($ScanContainers) {
                Invoke-Check -Id 'STG-CONTAINERS' -Category 'Storage' -Name 'Container size against ceiling' -Body {
                    $ceilingMB = [int](Get-RegValue -Path $RK_PROFILES -Name 'SizeInMBs' -Default 30000)
                    $all = @(Get-ChildItem -Path $storageRoot -Include '*.vhdx', '*.vhd' -Recurse -File -Force -ErrorAction SilentlyContinue |
                             Select-Object -First $MaxContainersToScan)
                    if ($all.Count -eq 0) {
                        Add-Check -Id 'STG-CONTAINERS' -Category 'Storage' -Name 'Container size against ceiling' -Status 'INFO' -Severity 'Info' `
                            -Detail 'No container files were enumerated on the share from this host.'
                        return
                    }
                    $near = @($all | Where-Object { ($_.Length / 1MB) -gt ($ceilingMB * 0.9) })
                    $capNote = ''
                    if ($all.Count -ge $MaxContainersToScan) {
                        $capNote = " Enumeration stopped at the -MaxContainersToScan limit of $MaxContainersToScan, so this is a sample, not the whole share."
                    }
                    if ($near.Count -gt 0) {
                        Add-Check -Id 'STG-CONTAINERS' -Category 'Storage' -Name 'Container size against ceiling' -Status 'WARN' -Severity 'Medium' `
                            -Detail "$($near.Count) of $($all.Count) containers scanned are above 90 per cent of the $ceilingMB MB ceiling. A user whose container hits the ceiling gets errors, not a warning.$capNote" `
                            -Evidence (($near | Select-Object -First 10 | ForEach-Object { "{0} ({1} MB)" -f $_.Name, [math]::Round($_.Length / 1MB) }) -join '; ') `
                            -Recommendation 'Raise SizeInMBs, or reduce container contents with redirections.xml and compaction.'
                    } else {
                        Add-Check -Id 'STG-CONTAINERS' -Category 'Storage' -Name 'Container size against ceiling' -Status 'PASS' -Severity 'Medium' `
                            -Detail "$($all.Count) containers scanned; none is above 90 per cent of the $ceilingMB MB ceiling.$capNote"
                    }
                }
            }

            if (-not $usingCloudCache) {
                Invoke-Check -Id 'STG-LOCKFILES' -Category 'Storage' -Name 'Lock files on the share' -Body {
                    # Prove the path can be enumerated first. Without this, an
                    # unreadable share returns zero files and is reported as a
                    # clean PASS, which is worse than no check at all.
                    if (-not (Test-Path -LiteralPath $storageRoot)) {
                        Add-Check -Id 'STG-LOCKFILES' -Category 'Storage' -Name 'Lock files on the share' -Status 'INFO' -Severity 'Info' `
                            -Detail 'The container share could not be enumerated from this host, so no lock-file conclusion can be drawn.' `
                            -Evidence $storageRoot
                        return
                    }
                    $locks = @(Get-ChildItem -Path $storageRoot -Filter '*.lock' -Recurse -File -Force -ErrorAction SilentlyContinue |
                               Select-Object -First 200)
                    if ($locks.Count -eq 0) {
                        Add-Check -Id 'STG-LOCKFILES' -Category 'Storage' -Name 'Lock files on the share' -Status 'PASS' -Severity 'Medium' `
                            -Detail 'No .lock files found on the container share.'
                    } else {
                        $stale = @($locks | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-24) })
                        Add-Check -Id 'STG-LOCKFILES' -Category 'Storage' -Name 'Lock files on the share' -Status 'WARN' -Severity 'Medium' `
                            -Detail "$($locks.Count) .lock file(s) present, of which $($stale.Count) have not been written to in over 24 hours. A lock with no live session is the usual cause of a 'container in use' sign-in failure." `
                            -Evidence (($stale | Select-Object -First 10 | ForEach-Object { "{0} (last write {1:yyyy-MM-dd HH:mm})" -f $_.Name, $_.LastWriteTime }) -join '; ') `
                            -Recommendation 'Confirm no session holds the container before removing any lock file. Enumeration is capped at 200 files.'
                    }
                }
            }
        }
    } elseif ($storageRoot) {
        Add-Check -Id 'STG-REACH' -Category 'Storage' -Name 'Share reachability (SMB 445)' -Status 'INFO' -Severity 'Info' `
            -Detail "No UNC server name could be parsed from the configured storage location, so the reachability and write tests were skipped. This is expected for an Azure page blob Cloud Cache provider." `
            -Evidence $storageRoot
    }

    # -----------------------------------------------------------------------
    # 6. Services and drivers
    # -----------------------------------------------------------------------

    $expectedServices = @('frxsvc')
    if ($usingCloudCache) { $expectedServices += 'frxccds' }

    foreach ($svcName in $expectedServices) {
        Invoke-Check -Id ("SVC-" + $svcName.ToUpper()) -Category 'Services' -Name "$svcName service" -Body {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            if (-not $svc) {
                Add-Check -Id ("SVC-" + $svcName.ToUpper()) -Category 'Services' -Name "$svcName service" -Status 'FAIL' -Severity 'Critical' `
                    -Detail "The $svcName service is not present on this host." `
                    -Recommendation 'Reinstall FSLogix.'
            } elseif ($svc.State -ne 'Running') {
                Add-Check -Id ("SVC-" + $svcName.ToUpper()) -Category 'Services' -Name "$svcName service" -Status 'FAIL' -Severity 'Critical' `
                    -Detail "The $svcName service state is $($svc.State), not Running. Containers cannot attach." `
                    -Evidence "StartMode: $($svc.StartMode)" `
                    -Recommendation "Start the $svcName service and confirm its start mode is Auto."
            } elseif ($svc.StartMode -ne 'Auto') {
                Add-Check -Id ("SVC-" + $svcName.ToUpper()) -Category 'Services' -Name "$svcName service" -Status 'WARN' -Severity 'High' `
                    -Detail "The $svcName service is running but its start mode is $($svc.StartMode). It will not come back after a reboot." `
                    -Recommendation "Set the $svcName service start mode to Auto."
            } else {
                Add-Check -Id ("SVC-" + $svcName.ToUpper()) -Category 'Services' -Name "$svcName service" -Status 'PASS' -Severity 'Critical' `
                    -Detail "Running, start mode Auto."
            }
        }
    }

    Invoke-Check -Id 'SVC-MINIFILTERS' -Category 'Services' -Name 'Minifilter drivers' -Body {
        $out = & fltmc filters 2>$null
        $loaded = @()
        foreach ($line in $out) {
            $t = ($line -split '\s+') | Where-Object { $_ }
            if ($t.Count -ge 1 -and $t[0] -notmatch '^-+$' -and $t[0] -ne 'Filter') {
                $loaded += $t[0]
            }
        }

        # Exact name match. 'frxdrv' is a prefix of 'frxdrvvt', so a substring
        # test reports frxdrv as present when only frxdrvvt is loaded.
        function Test-FilterLoaded {
            param([string]$Name, [string[]]$Loaded)
            foreach ($l in $Loaded) { if ($l -ieq $Name) { return $true } }
            return $false
        }

        $frxdrv   = Test-FilterLoaded -Name 'frxdrv'   -Loaded $loaded
        $frxdrvvt = Test-FilterLoaded -Name 'frxdrvvt' -Loaded $loaded
        $frxccd   = Test-FilterLoaded -Name 'frxccd'   -Loaded $loaded

        $required = @()
        if (-not $frxdrv) { $required += 'frxdrv' }
        if ($usingCloudCache -and -not $frxccd) { $required += 'frxccd' }

        if ($required.Count -gt 0) {
            Add-Check -Id 'SVC-MINIFILTERS' -Category 'Services' -Name 'Minifilter drivers' -Status 'FAIL' -Severity 'Critical' `
                -Detail "Required FSLogix minifilter(s) not loaded: $($required -join ', '). Container attach and redirection cannot work." `
                -Evidence ("Loaded filters: " + ($loaded -join ', ')) `
                -Recommendation 'Reboot the host. If the filter still does not load, reinstall FSLogix.'
        } else {
            Add-Check -Id 'SVC-MINIFILTERS' -Category 'Services' -Name 'Minifilter drivers' -Status 'PASS' -Severity 'Critical' `
                -Detail 'The required FSLogix minifilters are loaded.' `
                -Evidence ("frxdrv={0}; frxdrvvt={1}; frxccd={2}" -f $frxdrv, $frxdrvvt, $frxccd)
        }
    }

    # -----------------------------------------------------------------------
    # 7. Include and exclude groups
    # -----------------------------------------------------------------------

    Invoke-Check -Id 'GRP-INCLUDEEXCLUDE' -Category 'Groups' -Name 'FSLogix local groups' -Body {
        # Enumerate by prefix rather than hard-coding the four names, so a
        # rename or a localised build does not produce a false negative.
        $groups = @()
        try {
            $groups = @([ADSI]"WinNT://$env:COMPUTERNAME" | ForEach-Object { $_.Children } |
                        Where-Object { $_.SchemaClassName -eq 'group' -and $_.Name -like 'FSLogix*' })
        } catch { }

        if ($groups.Count -eq 0) {
            Add-Check -Id 'GRP-INCLUDEEXCLUDE' -Category 'Groups' -Name 'FSLogix local groups' -Status 'INFO' -Severity 'Info' `
                -Detail 'No local groups whose name begins with FSLogix were found, or they could not be enumerated on this host.' -Reference $DOC_GROUPS
            return
        }

        $findings = @()
        $problems = @()
        foreach ($g in $groups) {
            $name = [string]$g.Name
            $members = @()
            try {
                $members = @($g.psbase.Invoke('Members') | ForEach-Object {
                    $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
                })
            } catch { }
            $memberText = if ($members.Count -eq 0) { '(empty)' } else { $members -join ', ' }
            $findings += ("{0}: {1}" -f $name, $memberText)

            if ($name -like '*Include*' -and $members.Count -eq 0) {
                $problems += "$name is empty. Microsoft ships the include groups containing Everyone; an empty include group means NO user is processed by FSLogix on this host."
            }
            if ($name -like '*Exclude*' -and $members.Count -gt 0) {
                $problems += "$name has members ($memberText). Those accounts are deliberately skipped by FSLogix and will use local profiles."
            }
        }

        if ($problems.Count -gt 0) {
            Add-Check -Id 'GRP-INCLUDEEXCLUDE' -Category 'Groups' -Name 'FSLogix local groups' -Status 'WARN' -Severity 'High' `
                -Detail ($problems -join ' ') `
                -Evidence ($findings -join ' | ') `
                -Recommendation 'Confirm the membership is intentional. Microsoft names these groups as the first thing to check when a container fails to attach or a user lands on a temporary profile.' `
                -Reference $DOC_GROUPS
        } else {
            Add-Check -Id 'GRP-INCLUDEEXCLUDE' -Category 'Groups' -Name 'FSLogix local groups' -Status 'PASS' -Severity 'High' `
                -Detail 'Include and exclude group membership matches the shipped defaults.' `
                -Evidence ($findings -join ' | ') -Reference $DOC_GROUPS
        }
    }

    # -----------------------------------------------------------------------
    # 8. Runtime state
    # -----------------------------------------------------------------------

    Invoke-Check -Id 'RUN-SESSIONS' -Category 'Runtime' -Name 'Session attach status' -Body {
        $sessKey = Join-Path $RK_PROFILES 'Sessions'
        if (-not (Test-Path $sessKey)) {
            Add-Check -Id 'RUN-SESSIONS' -Category 'Runtime' -Name 'Session attach status' -Status 'INFO' -Severity 'Info' `
                -Detail 'No FSLogix session data on this host. Expected when no user has signed in since the last restart.' -Reference $DOC_CODES
            return
        }

        $sessions = @(Get-ChildItem -Path $sessKey -ErrorAction SilentlyContinue)
        if ($sessions.Count -eq 0) {
            Add-Check -Id 'RUN-SESSIONS' -Category 'Runtime' -Name 'Session attach status' -Status 'INFO' -Severity 'Info' `
                -Detail 'The Sessions key exists but holds no user sessions.' -Reference $DOC_CODES
            return
        }

        $bad  = @()
        $good = 0
        foreach ($s in $sessions) {
            $sid    = $s.PSChildName
            $status = Get-RegValue -Path $s.PSPath -Name 'Status' -Default $null
            $reason = Get-RegValue -Path $s.PSPath -Name 'Reason' -Default $null
            $errNum = Get-RegValue -Path $s.PSPath -Name 'Error'  -Default $null

            $account = $sid
            try {
                $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            } catch { }

            $statusText = 'unknown status'
            if ($null -ne $status -and $script:StatusCodes.ContainsKey([int]$status)) {
                $statusText = $script:StatusCodes[[int]$status]
            } elseif ($null -ne $status) {
                $statusText = "status $status (not in Microsoft's published table)"
            }

            $reasonText = ''
            if ($null -ne $reason -and $script:ReasonCodes.ContainsKey([int]$reason)) {
                $reasonText = ' Reason: ' + $script:ReasonCodes[[int]$reason]
            }

            $errText = ''
            if ($null -ne $errNum -and [int]$errNum -ne 0) {
                $errText = (" Windows error {0} (0x{0:X8})." -f [int]$errNum)
            }

            if ($null -ne $status -and ($script:StatusNormal -contains [int]$status) -and [int]$status -eq 0) {
                $good++
            } else {
                $bad += ("{0}: {1}.{2}{3}" -f $account, $statusText, $reasonText, $errText)
            }
        }

        if ($bad.Count -eq 0) {
            Add-Check -Id 'RUN-SESSIONS' -Category 'Runtime' -Name 'Session attach status' -Status 'PASS' -Severity 'High' `
                -Detail "$good session(s) recorded, all with Status 0 (success)." -Reference $DOC_CODES
        } else {
            Add-Check -Id 'RUN-SESSIONS' -Category 'Runtime' -Name 'Session attach status' -Status 'FAIL' -Severity 'High' `
                -Detail "$($bad.Count) session(s) are not in a success state, $good are." `
                -Evidence ($bad -join ' | ') `
                -Recommendation 'Decode any Windows error code with NET HELPMSG or the System Error Codes reference.' `
                -Reference $DOC_CODES
        }
    }

    Invoke-Check -Id 'RUN-TEMPPROFILES' -Category 'Runtime' -Name 'Temporary and orphaned profiles' -Body {
        $entries = @(Get-ChildItem -Path $RK_PROFLIST -ErrorAction SilentlyContinue)
        $bakKeys = @($entries | Where-Object { $_.PSChildName -like '*.bak' })
        $tempDir = Test-Path 'C:\Users\TEMP'

        $issues = @()
        if ($bakKeys.Count -gt 0) {
            $issues += "$($bakKeys.Count) ProfileList key(s) ending .bak. Windows renames a profile key to .bak when it cannot load the original, which is the fingerprint of a temporary-profile event."
        }
        if ($tempDir) {
            $issues += 'C:\Users\TEMP exists, which Windows creates when a user is given a temporary profile.'
        }

        if ($issues.Count -eq 0) {
            Add-Check -Id 'RUN-TEMPPROFILES' -Category 'Runtime' -Name 'Temporary and orphaned profiles' -Status 'PASS' -Severity 'High' `
                -Detail 'No .bak ProfileList keys and no C:\Users\TEMP folder. No sign of a temporary-profile event on this host.'
        } else {
            Add-Check -Id 'RUN-TEMPPROFILES' -Category 'Runtime' -Name 'Temporary and orphaned profiles' -Status 'WARN' -Severity 'High' `
                -Detail ($issues -join ' ') `
                -Evidence (($bakKeys | Select-Object -First 10 | ForEach-Object { $_.PSChildName }) -join '; ') `
                -Recommendation 'Investigate the affected users. Enabling PreventLoginWithTempProfile turns this silent failure into a visible one.' `
                -Reference 'https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles'
        }
    }

    Invoke-Check -Id 'RUN-LOCALPROFILES' -Category 'Runtime' -Name 'Local profiles on a container host' -Body {
        $sysProfiles = @('Administrator', 'Public', 'Default', 'Default User', 'All Users', 'TEMP')
        $local = @(Get-ChildItem -Path 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
                   Where-Object { $sysProfiles -notcontains $_.Name -and $_.Name -notlike 'local_*' })
        if ($local.Count -eq 0) {
            Add-Check -Id 'RUN-LOCALPROFILES' -Category 'Runtime' -Name 'Local profiles on a container host' -Status 'PASS' -Severity 'Medium' `
                -Detail 'No unexpected local profile folders under C:\Users.'
        } else {
            Add-Check -Id 'RUN-LOCALPROFILES' -Category 'Runtime' -Name 'Local profiles on a container host' -Status 'WARN' -Severity 'Medium' `
                -Detail "$($local.Count) local profile folder(s) exist under C:\Users. With DeleteLocalProfileWhenVHDShouldApply at 0, FSLogix uses an existing local profile in preference to the container, so these users are not roaming." `
                -Evidence (($local | Select-Object -First 15 | ForEach-Object { $_.Name }) -join '; ') `
                -Recommendation 'Confirm each folder belongs to a service or admin account that is deliberately excluded, and remove the rest.'
        }
    }

    Invoke-Check -Id 'RUN-EVENTLOG' -Category 'Runtime' -Name 'FSLogix event log errors (7 days)' -Body {
        $logs = @('Microsoft-FSLogix-Apps/Admin', 'Microsoft-FSLogix-Apps/Operational')
        $since = (Get-Date).AddDays(-7)
        $errors = @()
        foreach ($logName in $logs) {
            try {
                # -Ignore, not -SilentlyContinue: a log with no matching events
                # still writes an error record under SilentlyContinue.
                $filter = @{ LogName = $logName; Level = 2; StartTime = $since }
                $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Ignore)
                foreach ($e in $events) { $errors += $e }
            } catch { }
        }

        if ($errors.Count -eq 0) {
            Add-Check -Id 'RUN-EVENTLOG' -Category 'Runtime' -Name 'FSLogix event log errors (7 days)' -Status 'PASS' -Severity 'Medium' `
                -Detail 'No Error-level events in the FSLogix Apps logs in the last 7 days.'
            return
        }

        $byId = $errors | Group-Object Id | Sort-Object Count -Descending
        $summary = ($byId | Select-Object -First 5 | ForEach-Object { "Event {0} x{1}" -f $_.Name, $_.Count }) -join '; '
        $sample  = ($errors | Select-Object -First 3 | ForEach-Object { "[{0:yyyy-MM-dd HH:mm}] {1}: {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }) -join ' | '

        Add-Check -Id 'RUN-EVENTLOG' -Category 'Runtime' -Name 'FSLogix event log errors (7 days)' -Status 'WARN' -Severity 'Medium' `
            -Detail "$($errors.Count) Error-level event(s) in the last 7 days, grouped as: $summary." `
            -Evidence $sample `
            -Recommendation 'Review the highest-count event ID first; a repeating error on a session host is usually one root cause, not many.'
    }

    Invoke-Check -Id 'RUN-LOGGING' -Category 'Runtime' -Name 'FSLogix text logging' -Body {
        $loggingKey = 'HKLM:\SOFTWARE\FSLogix\Logging'
        $enabled = Get-RegValue -Path $loggingKey -Name 'LoggingEnabled' -Default $null
        $logDir  = ConvertTo-FlatString (Get-RegValue -Path $loggingKey -Name 'LogDir' -Default 'C:\ProgramData\FSLogix\Logs')
        if ($null -ne $enabled -and [int]$enabled -eq 0) {
            Add-Check -Id 'RUN-LOGGING' -Category 'Runtime' -Name 'FSLogix text logging' -Status 'WARN' -Severity 'Medium' `
                -Detail 'LoggingEnabled is 0. The text logs are the only place FSLogix records the detail needed to diagnose a failed attach, and Microsoft support asks for them first.' `
                -Recommendation 'Leave FSLogix logging at its default enabled state.' -Reference $DOC_SETTINGS
        } else {
            Add-Check -Id 'RUN-LOGGING' -Category 'Runtime' -Name 'FSLogix text logging' -Status 'PASS' -Severity 'Medium' `
                -Detail 'FSLogix text logging is enabled.' -Evidence "LogDir: $logDir"
        }
    }
}

# ---------------------------------------------------------------------------
# Defender exclusion remediation (handled separately: not a single reg value)
# ---------------------------------------------------------------------------

if ($Remediate) {
    $avResult = $script:Results | Where-Object { $_.Id -eq 'AV-EXCLUSIONS' -and $_.Fixable -and -not $_.FixApplied } | Select-Object -First 1
    if ($avResult -and $avResult.Fix.Kind -eq 'DefenderExclusions') {
        if ($RemediateOnly.Count -eq 0 -or $RemediateOnly -contains 'AV-EXCLUSIONS') {
            $procList = @($avResult.Fix.Processes)
            $pathList = @($avResult.Fix.Paths)
            if ($PSCmdlet.ShouldProcess("Windows Defender", "Add $($procList.Count) process and $($pathList.Count) path exclusions")) {
                try {
                    foreach ($p in $procList) { Add-MpPreference -ExclusionProcess $p -ErrorAction Stop }
                    foreach ($p in $pathList) { Add-MpPreference -ExclusionPath    $p -ErrorAction Stop }
                    $avResult.FixApplied = $true
                    $script:FixesApplied.Add([PSCustomObject]@{
                        Id    = 'AV-EXCLUSIONS'
                        Path  = 'Windows Defender'
                        Name  = 'Exclusions'
                        Value = (($procList + $pathList) -join '; ')
                    }) | Out-Null
                    if (-not $Quiet) { Write-Host "         Applied: Defender exclusions" -ForegroundColor Green }
                } catch {
                    $avResult.FixError = $_.Exception.Message
                    if (-not $Quiet) { Write-Host ("         Defender exclusion fix failed: {0}" -f $_.Exception.Message) -ForegroundColor Red }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Score and summary
# ---------------------------------------------------------------------------

$passCount = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$infoCount = @($script:Results | Where-Object { $_.Status -eq 'INFO' }).Count

# Score: a PASS earns its full weight, a WARN half, a FAIL nothing.
# INFO rows carry weight 0 and are excluded.
$scored     = @($script:Results | Where-Object { $_.Weight -gt 0 -and $_.Status -ne 'INFO' })
$totalWeight = 0
$earned      = 0.0
foreach ($r in $scored) {
    $totalWeight += $r.Weight
    if ($r.Status -eq 'PASS') { $earned += $r.Weight }
    elseif ($r.Status -eq 'WARN') { $earned += ($r.Weight * 0.5) }
}
$healthScore = 0
if ($totalWeight -gt 0) { $healthScore = [math]::Round(100.0 * $earned / $totalWeight, 1) }

$grade = 'Critical'
if ($healthScore -ge 95) { $grade = 'Healthy' }
elseif ($healthScore -ge 85) { $grade = 'Good' }
elseif ($healthScore -ge 70) { $grade = 'Needs attention' }
elseif ($healthScore -ge 50) { $grade = 'At risk' }

$criticalFails = @($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' })

if (-not $Quiet) {
    Write-Host ""
    Write-Host "=================================================================================" -ForegroundColor Cyan
    Write-Host ("Health score: {0} / 100  ({1})" -f $healthScore, $grade) -ForegroundColor Cyan
    Write-Host ("{0} pass, {1} warn, {2} fail, {3} info" -f $passCount, $warnCount, $failCount, $infoCount) -ForegroundColor Cyan
    if ($criticalFails.Count -gt 0) {
        Write-Host ("{0} CRITICAL failure(s): {1}" -f $criticalFails.Count, (($criticalFails | ForEach-Object { $_.Id }) -join ', ')) -ForegroundColor Red
    }
    Write-Host "=================================================================================" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# JSON document (the source of truth for any aggregation)
# ---------------------------------------------------------------------------

# Build the collection members first. Windows PowerShell 5.1 throws
# "Argument types do not match" when a script block appears inside an
# [ordered] hashtable literal, so nothing below may contain a { } block.
$criticalFailIds = @()
foreach ($c in $criticalFails) { $criticalFailIds += $c.Id }

$fslogixMode = 'Unconfigured'
if ($usingCloudCache) { $fslogixMode = 'CloudCache' }
elseif ($vhdLocations) { $fslogixMode = 'Standard' }

$checkArray = New-Object System.Collections.Generic.List[object]
foreach ($r in $script:Results) {
    $checkArray.Add([ordered]@{
        id             = $r.Id
        category       = $r.Category
        name           = $r.Name
        status         = $r.Status
        severity       = $r.Severity
        weight         = $r.Weight
        detail         = $r.Detail
        evidence       = $r.Evidence
        recommendation = $r.Recommendation
        reference      = $r.Reference
        fixable        = $r.Fixable
        fixApplied     = $r.FixApplied
        fixError       = $r.FixError
    }) | Out-Null
}

# Windows PowerShell 5.1 throws "Argument types do not match" when one
# [ordered] hashtable literal is nested directly inside another. Build each
# block into its own variable first and reference it.
$hostBlock = [ordered]@{
    computerName      = $hostContext.ComputerName
    osCaption         = $hostContext.OSCaption
    osVersion         = $hostContext.OSVersion
    isMultiSession    = $hostContext.IsMultiSession
    isAvdHost         = $hostContext.IsAvdHost
    entraJoined       = $hostContext.EntraJoined
    domainJoined      = $hostContext.DomainJoined
    systemDriveFreeGB = $hostContext.SystemDriveFreeGB
}

$fslogixBlock = [ordered]@{
    installed       = $fslogixInstalled
    version         = $fslogixVersion
    baselineVersion = $MinimumFSLogixVersion
    mode            = $fslogixMode
    storageRoot     = $storageRoot
}

$summaryBlock = [ordered]@{
    healthScore   = $healthScore
    grade         = $grade
    pass          = $passCount
    warn          = $warnCount
    fail          = $failCount
    info          = $infoCount
    criticalFails = $criticalFailIds
}

# .ToArray(), not @(...): under Windows PowerShell 5.1, wrapping a generic
# List in @() inside an [ordered] hashtable literal throws "Argument types
# do not match" when the list is empty.
$remediationBlock = [ordered]@{
    requested = $Remediate.IsPresent
    applied   = $script:FixesApplied.ToArray()
}

$document = [ordered]@{
    schemaVersion = $script:SchemaVersion
    generatedUtc  = $script:StartedUtc.ToString('o')
    durationMs    = [int]((Get-Date).ToUniversalTime() - $script:StartedUtc).TotalMilliseconds
    host          = $hostBlock
    fslogix       = $fslogixBlock
    summary       = $summaryBlock
    remediation   = $remediationBlock
    checks        = $checkArray.ToArray()
}

try {
    $json = $document | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($jsonFile, $json)
    if (-not $Quiet) { Write-Host ("JSON result: {0}" -f $jsonFile) -ForegroundColor Cyan }
} catch {
    Write-Warning "Could not write JSON to $jsonFile : $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

if (-not $JsonOnly) {

    $sb = New-Object System.Text.StringBuilder
    function Add-Line { param([string]$Text) [void]$sb.AppendLine($Text) }

    $scoreColour = '#c62828'
    if ($healthScore -ge 95) { $scoreColour = '#2e7d32' }
    elseif ($healthScore -ge 85) { $scoreColour = '#558b2f' }
    elseif ($healthScore -ge 70) { $scoreColour = '#b8860b' }
    elseif ($healthScore -ge 50) { $scoreColour = '#e65100' }

    Add-Line '<!DOCTYPE html>'
    Add-Line '<html lang="en">'
    Add-Line '<head>'
    Add-Line '<meta charset="utf-8">'
    Add-Line '<meta name="viewport" content="width=device-width, initial-scale=1">'
    Add-Line ('<title>FSLogix Health Check - ' + (ConvertTo-HtmlSafe $env:COMPUTERNAME) + '</title>')
    Add-Line '<style>'
    Add-Line ':root { --ink:#1a1a1a; --muted:#5f6b7a; --line:#e3e8ee; --bg:#f4f6f8; }'
    Add-Line 'body { font-family: Segoe UI, Arial, sans-serif; margin:0; padding:24px; background:var(--bg); color:var(--ink); }'
    Add-Line '.wrap { max-width:1200px; margin:0 auto; }'
    Add-Line 'h1 { font-size:22px; margin:0 0 4px 0; }'
    Add-Line '.meta { color:var(--muted); font-size:13px; margin-bottom:20px; }'
    Add-Line '.top { display:flex; gap:20px; flex-wrap:wrap; align-items:stretch; margin-bottom:20px; }'
    Add-Line '.score { background:#fff; border-radius:10px; padding:18px 26px; box-shadow:0 1px 3px rgba(0,0,0,.10); text-align:center; min-width:190px; }'
    Add-Line '.score .n { font-size:46px; font-weight:700; line-height:1; }'
    Add-Line '.score .g { font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; margin-top:6px; }'
    Add-Line '.chips { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }'
    Add-Line '.chip { padding:8px 16px; border-radius:8px; font-weight:600; color:#fff; font-size:14px; }'
    Add-Line '.chip-pass { background:#2e7d32; } .chip-warn { background:#b8860b; } .chip-fail { background:#c62828; } .chip-info { background:#616161; }'
    Add-Line '.alert { background:#fdecea; border-left:5px solid #c62828; padding:12px 16px; border-radius:6px; margin-bottom:20px; }'
    Add-Line '.alert b { color:#c62828; }'
    Add-Line 'table { border-collapse:collapse; width:100%; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.10); }'
    Add-Line 'th, td { text-align:left; padding:11px 13px; border-bottom:1px solid var(--line); vertical-align:top; font-size:14px; }'
    Add-Line 'th { background:#263238; color:#fff; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }'
    Add-Line 'tr.s-pass { border-left:4px solid #2e7d32; } tr.s-warn { border-left:4px solid #b8860b; }'
    Add-Line 'tr.s-fail { border-left:4px solid #c62828; } tr.s-info { border-left:4px solid #9aa5b1; }'
    Add-Line '.badge { display:inline-block; padding:2px 9px; border-radius:4px; color:#fff; font-size:11px; font-weight:700; }'
    Add-Line '.b-pass { background:#2e7d32; } .b-warn { background:#b8860b; } .b-fail { background:#c62828; } .b-info { background:#9aa5b1; }'
    Add-Line '.sev { font-size:11px; color:var(--muted); display:block; margin-top:4px; text-transform:uppercase; }'
    Add-Line '.cid { font-family:Consolas,monospace; font-size:11px; color:var(--muted); }'
    Add-Line '.ev { color:var(--muted); font-size:12.5px; margin-top:6px; word-break:break-word; }'
    Add-Line '.rec { color:#1565c0; font-size:12.5px; margin-top:6px; }'
    Add-Line '.ref a { color:#1565c0; font-size:12px; }'
    Add-Line '.applied { color:#2e7d32; font-weight:600; font-size:12.5px; margin-top:6px; }'
    Add-Line 'h2 { font-size:15px; margin:26px 0 10px 0; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }'
    Add-Line '</style>'
    Add-Line '</head>'
    Add-Line '<body><div class="wrap">'

    Add-Line ('<h1>FSLogix Health Check - ' + (ConvertTo-HtmlSafe $env:COMPUTERNAME) + '</h1>')
    Add-Line ('<div class="meta">Generated ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') +
              ' | FSLogix ' + (ConvertTo-HtmlSafe $fslogixVersion) +
              ' | Mode: ' + (ConvertTo-HtmlSafe $document.fslogix.mode) +
              ' | ' + (ConvertTo-HtmlSafe $hostContext.OSCaption) +
              ' | Rule set v' + $script:SchemaVersion + '</div>')

    Add-Line '<div class="top">'
    Add-Line ('<div class="score"><div class="n" style="color:' + $scoreColour + '">' + $healthScore + '</div><div class="g">' + (ConvertTo-HtmlSafe $grade) + '</div></div>')
    Add-Line '<div class="chips">'
    Add-Line ('<span class="chip chip-pass">' + $passCount + ' Pass</span>')
    Add-Line ('<span class="chip chip-warn">' + $warnCount + ' Warn</span>')
    Add-Line ('<span class="chip chip-fail">' + $failCount + ' Fail</span>')
    Add-Line ('<span class="chip chip-info">' + $infoCount + ' Info</span>')
    Add-Line '</div>'
    Add-Line '</div>'

    if ($criticalFails.Count -gt 0) {
        Add-Line '<div class="alert">'
        Add-Line ('<b>' + $criticalFails.Count + ' critical failure(s).</b> Users on this host are affected now:')
        Add-Line '<ul>'
        foreach ($c in $criticalFails) {
            Add-Line ('<li>' + (ConvertTo-HtmlSafe $c.Name) + ' - ' + (ConvertTo-HtmlSafe $c.Detail) + '</li>')
        }
        Add-Line '</ul></div>'
    }

    $order = @('Install', 'Configuration', 'Cloud Cache', 'Antivirus', 'Storage', 'Services', 'Groups', 'Runtime', 'Host')
    $categories = @($script:Results | Select-Object -ExpandProperty Category -Unique |
                    Sort-Object { $i = $order.IndexOf($_); if ($i -lt 0) { 99 } else { $i } })

    foreach ($cat in $categories) {
        Add-Line ('<h2>' + (ConvertTo-HtmlSafe $cat) + '</h2>')
        Add-Line '<table>'
        Add-Line '<tr><th style="width:78px">Status</th><th style="width:230px">Check</th><th>Finding</th></tr>'
        foreach ($r in ($script:Results | Where-Object { $_.Category -eq $cat })) {
            $sl = $r.Status.ToLower()
            Add-Line ('<tr class="s-' + $sl + '">')
            Add-Line ('<td><span class="badge b-' + $sl + '">' + $r.Status + '</span><span class="sev">' + (ConvertTo-HtmlSafe $r.Severity) + '</span></td>')
            Add-Line ('<td>' + (ConvertTo-HtmlSafe $r.Name) + '<br><span class="cid">' + (ConvertTo-HtmlSafe $r.Id) + '</span></td>')
            Add-Line ('<td>' + (ConvertTo-HtmlSafe $r.Detail))
            if ($r.Evidence)       { Add-Line ('<div class="ev">' + (ConvertTo-HtmlSafe $r.Evidence) + '</div>') }
            if ($r.Recommendation -and $r.Status -ne 'PASS') { Add-Line ('<div class="rec">Recommended: ' + (ConvertTo-HtmlSafe $r.Recommendation) + '</div>') }
            if ($r.FixApplied)     { Add-Line '<div class="applied">Remediation applied during this run.</div>' }
            if ($r.FixError)       { Add-Line ('<div class="rec">Remediation failed: ' + (ConvertTo-HtmlSafe $r.FixError) + '</div>') }
            if ($r.Reference)      { Add-Line ('<div class="ref"><a href="' + (ConvertTo-HtmlSafe $r.Reference) + '">Microsoft documentation</a></div>') }
            Add-Line '</td></tr>'
        }
        Add-Line '</table>'
    }

    Add-Line '<h2>About this report</h2>'
    Add-Line '<table><tr><td>'
    Add-Line 'Every rule is drawn from current Microsoft Learn FSLogix documentation: the Prerequisites page for antivirus exclusions, the Configuration Setting Reference for defaults, the Configuration examples page for recommended values, and the Codes page for Status and Reason decoding. '
    Add-Line 'The health score weights each finding by severity: a pass earns full weight, a warning half, a failure none. Informational rows are excluded from the score. '
    Add-Line 'A pass on this host does not prove the storage back end is correct: share-side antivirus exclusions, share and NTFS permissions for real user accounts, and storage performance are outside what a session host can observe.'
    Add-Line '</td></tr></table>'

    Add-Line '</div></body></html>'

    try {
        [System.IO.File]::WriteAllText($htmlFile, $sb.ToString())
        if (-not $Quiet) { Write-Host ("HTML report: {0}" -f $htmlFile) -ForegroundColor Cyan }
    } catch {
        Write-Warning "Could not write HTML to $htmlFile : $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Single-line result for the calling automation to capture
# ---------------------------------------------------------------------------

Write-Output ("FSLogix Health Check v{0} | {1} | Score {2}/100 ({3}) | {4} pass, {5} warn, {6} fail, {7} info | Critical: {8} | JSON: {9}" -f `
    $script:SchemaVersion, $env:COMPUTERNAME, $healthScore, $grade, $passCount, $warnCount, $failCount, $infoCount,
    $(if ($criticalFails.Count -gt 0) { ($criticalFails | ForEach-Object { $_.Id }) -join ',' } else { 'none' }),
    $jsonFile)
