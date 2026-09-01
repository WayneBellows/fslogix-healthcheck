#description: FSLogix best-practice and troubleshooting health check. Reports on registry config, AV exclusions, storage, services and live session state. Optional -Fix applies safe remediations after per-item confirmation.
#execution mode: Individual
#tags: FSLogix, AVD, Health Check

param(
    [switch]$Fix,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\FSLogix-HealthCheck-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append | Out-Null

if (-not $ReportPath) {
    $reportDir = 'C:\ProgramData\FSLogixHealthCheck'
    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
    $ReportPath = Join-Path $reportDir "FSLogix-HealthCheck-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
}

# Treat this as non-interactive automation (NME, or any host with no console) unless proven otherwise.
$IsAutomation = $true
if ([Environment]::UserInteractive) {
    try {
        if ($Host.Name -eq 'ConsoleHost' -and $Host.UI.RawUI) { $IsAutomation = $false }
    } catch { $IsAutomation = $true }
}
if (Get-Variable -Name 'SATrigger' -Scope Global -ErrorAction SilentlyContinue) { $IsAutomation = $true }

$script:Results = New-Object System.Collections.Generic.List[object]

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

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )
    try {
        if (-not (Test-Path $Path)) { return $Default }
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $Default }
        $val = $item.$Name
        if ($null -eq $val) { return $Default }
        return $val
    } catch {
        return $Default
    }
}

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Detail,
        [string]$FixSuggestion = '',
        [scriptblock]$FixAction = $null
    )
    $result = [PSCustomObject]@{
        Category      = $Category
        Name          = $Name
        Status        = $Status
        Detail        = $Detail
        FixSuggestion = $FixSuggestion
        FixAction     = $FixAction
        Fixed         = $false
    }
    $script:Results.Add($result) | Out-Null

    $colour = 'Gray'
    if ($Status -eq 'PASS') { $colour = 'Green' }
    if ($Status -eq 'WARN') { $colour = 'Yellow' }
    if ($Status -eq 'FAIL') { $colour = 'Red' }
    Write-Host ("[{0,-4}] {1,-14} {2}" -f $Status, $Category, $Name) -ForegroundColor $colour
    Write-Host ("       {0}" -f $Detail) -ForegroundColor DarkGray

    if ($FixAction -and $Status -ne 'PASS') {
        Invoke-ResultFix -Result $result
    }
}

function Invoke-ResultFix {
    param($Result)

    if (-not $Fix) { return }

    if ($IsAutomation) {
        Write-Host "       Fix available but skipped: running non-interactively. Run with -Fix at an interactive console to apply." -ForegroundColor Yellow
        return
    }

    Write-Host ("       Fix available: {0}" -f $Result.FixSuggestion) -ForegroundColor Cyan
    $answer = Read-Host "       Apply this fix now? (y/N)"
    if ($answer -eq 'y' -or $answer -eq 'Y') {
        try {
            & $Result.FixAction
            $Result.Fixed = $true
            Write-Host "       Fix applied." -ForegroundColor Green
        } catch {
            Write-Host ("       Fix failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } else {
        Write-Host "       Skipped." -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "FSLogix Health Check - $($env:COMPUTERNAME) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------------------------------------------------------
# 1. Installation and version
# ----------------------------------------------------------------------------

$appsKey = 'HKLM:\SOFTWARE\FSLogix\Apps'
$fslogixInstalled = Test-Path $appsKey
$fslogixVersion = $null

if (-not $fslogixInstalled) {
    Add-Result -Category 'Install' -Name 'FSLogix installed' -Status 'FAIL' `
        -Detail "No FSLogix installation found at $appsKey. All other checks skipped."
    $script:SkipRemaining = $true
} else {
    $fslogixVersion = Get-RegValue -Path $appsKey -Name 'InstallVersion' -Default 'unknown'
    Add-Result -Category 'Install' -Name 'FSLogix installed' -Status 'PASS' `
        -Detail "Installed, version $fslogixVersion. Frxtray.exe is retired (11 Feb 2025); ignore any reference to it in older docs."
    $script:SkipRemaining = $false
}

# ----------------------------------------------------------------------------
# 2. Profile Container configuration
# ----------------------------------------------------------------------------

if (-not $script:SkipRemaining) {

    $profilesKey = 'HKLM:\SOFTWARE\FSLogix\Profiles'
    $odfcKey = 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC'

    $profileEnabled = Get-RegValue -Path $profilesKey -Name 'Enabled' -Default 0
    if ($profileEnabled -eq 1) {
        Add-Result -Category 'Config' -Name 'Profile Container enabled' -Status 'PASS' -Detail 'Enabled=1 under HKLM:\SOFTWARE\FSLogix\Profiles.'
    } else {
        Add-Result -Category 'Config' -Name 'Profile Container enabled' -Status 'FAIL' `
            -Detail "Enabled is $profileEnabled, not 1. Profile Container is not active."
    }

    $odfcEnabled = Get-RegValue -Path $odfcKey -Name 'Enabled' -Default 0
    if ($odfcEnabled -eq 1) {
        Add-Result -Category 'Config' -Name 'ODFC container in use' -Status 'INFO' `
            -Detail 'ODFC (Office) container is enabled alongside Profile Container. Microsoft only recommends this when a separate roaming-profile product also manages the same profile scope - with FSLogix Profile Containers alone, Office/OneDrive data is already included.'
    }

    $vhdLocations = Get-RegValue -Path $profilesKey -Name 'VHDLocations' -Default ''
    $ccdLocations = Get-RegValue -Path $profilesKey -Name 'CCDLocations' -Default ''
    $usingCloudCache = [bool]$ccdLocations

    if ($vhdLocations -and $ccdLocations) {
        Add-Result -Category 'Config' -Name 'Storage location mode' -Status 'FAIL' `
            -Detail 'Both VHDLocations and CCDLocations are set. These are mutually exclusive - pick one mode.'
    } elseif (-not $vhdLocations -and -not $ccdLocations) {
        Add-Result -Category 'Config' -Name 'Storage location mode' -Status 'FAIL' `
            -Detail 'Neither VHDLocations nor CCDLocations is set. FSLogix has nowhere to store the profile.'
    } elseif ($usingCloudCache) {
        Add-Result -Category 'Config' -Name 'Storage location mode' -Status 'PASS' `
            -Detail "Cloud Cache mode. CCDLocations: $ccdLocations"
    } else {
        Add-Result -Category 'Config' -Name 'Storage location mode' -Status 'PASS' `
            -Detail "Standard mode. VHDLocations: $vhdLocations"
    }

    $volumeType = Get-RegValue -Path $profilesKey -Name 'VolumeType' -Default 'vhd'
    if ($volumeType -eq 'vhdx') {
        Add-Result -Category 'Config' -Name 'Volume type' -Status 'PASS' -Detail 'VolumeType is vhdx.'
    } else {
        Add-Result -Category 'Config' -Name 'Volume type' -Status 'WARN' `
            -Detail "VolumeType is '$volumeType'. Microsoft recommends vhdx for corruption resistance and better size handling. This only affects newly created containers, not existing ones." `
            -FixSuggestion 'Set VolumeType to vhdx for future containers.' `
            -FixAction { Set-ItemProperty -Path $profilesKey -Name 'VolumeType' -Value 'vhdx' -Type String }
    }

    $sizeInMBs = Get-RegValue -Path $profilesKey -Name 'SizeInMBs' -Default 30000
    if ([int]$sizeInMBs -lt 5000) {
        Add-Result -Category 'Config' -Name 'Container size ceiling' -Status 'WARN' `
            -Detail "SizeInMBs is $sizeInMBs. This is small for a profile container and the ceiling can only be raised, never shrunk, later." `
            -FixSuggestion 'Raise SizeInMBs to 30000 (30 GB).' `
            -FixAction { Set-ItemProperty -Path $profilesKey -Name 'SizeInMBs' -Value 30000 -Type DWord }
    } else {
        Add-Result -Category 'Config' -Name 'Container size ceiling' -Status 'PASS' -Detail "SizeInMBs is $sizeInMBs."
    }

    $roamIdentity = Get-RegValue -Path $profilesKey -Name 'RoamIdentity' -Default 0

    $entraJoined = $false
    $domainJoined = $false
    try {
        $dsregOutput = & dsregcmd /status 2>$null
        foreach ($line in $dsregOutput) {
            if ($line -match 'AzureAdJoined\s*:\s*YES') { $entraJoined = $true }
            if ($line -match 'DomainJoined\s*:\s*YES') { $domainJoined = $true }
        }
    } catch {
        # dsregcmd not available or failed - leave as unknown, treated as not Entra-joined below
    }

    if ($roamIdentity -eq 1 -and $entraJoined -and -not $domainJoined) {
        Add-Result -Category 'Config' -Name 'RoamIdentity setting' -Status 'FAIL' `
            -Detail 'RoamIdentity=1 on a device that is Entra-joined and not domain-joined. This legacy identity-roaming setting conflicts with modern token handling on Entra-only devices.' `
            -FixSuggestion 'Set RoamIdentity to 0.' `
            -FixAction { Set-ItemProperty -Path $profilesKey -Name 'RoamIdentity' -Value 0 -Type DWord }
    } elseif ($roamIdentity -eq 1) {
        Add-Result -Category 'Config' -Name 'RoamIdentity setting' -Status 'WARN' `
            -Detail 'RoamIdentity=1. Confirm this is intentional - Microsoft does not recommend enabling it on Entra-joined or Intune-managed devices.'
    } else {
        Add-Result -Category 'Config' -Name 'RoamIdentity setting' -Status 'PASS' -Detail 'RoamIdentity is 0 (default, recommended).'
    }

    $isAvdHost = [bool](Get-Service -Name 'RDAgentBootLoader' -ErrorAction SilentlyContinue)
    $profileType = Get-RegValue -Path $profilesKey -Name 'ProfileType' -Default 0
    if ([int]$profileType -in @(2, 3) -and $isAvdHost) {
        Add-Result -Category 'Config' -Name 'Concurrent session profile mode' -Status 'WARN' `
            -Detail "ProfileType is $profileType (concurrent-capable) and this host runs the AVD agent. AVD host pools do not support concurrent user connections at all, so concurrent profile mode provides no benefit here and may mask other multi-session issues."
    } else {
        Add-Result -Category 'Config' -Name 'Concurrent session profile mode' -Status 'PASS' -Detail "ProfileType is $profileType."
    }

    $deleteLocal = Get-RegValue -Path $profilesKey -Name 'DeleteLocalProfileWhenVHDShouldApply' -Default 0
    if ($deleteLocal -eq 0) {
        Add-Result -Category 'Config' -Name 'Local profile fallback protection' -Status 'WARN' `
            -Detail 'DeleteLocalProfileWhenVHDShouldApply=0. If a local profile already exists for a user, FSLogix will silently use it instead of the VHD, which is a common source of "my changes did not roam" tickets. Not auto-fixed here - deletes a local profile, confirm no one relies on it first.'
    } else {
        Add-Result -Category 'Config' -Name 'Local profile fallback protection' -Status 'PASS' -Detail 'DeleteLocalProfileWhenVHDShouldApply=1.'
    }

    if ($usingCloudCache) {
        $cacheDirKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\frxccd\Parameters'
        $proxyDirKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\frxccds\Parameters'
        $cacheDir = Get-RegValue -Path $cacheDirKey -Name 'CacheDirectory' -Default ''
        $proxyDir = Get-RegValue -Path $proxyDirKey -Name 'ProxyDirectory' -Default ''
        if ($cacheDir -and $proxyDir -and ($cacheDir -eq $proxyDir)) {
            Add-Result -Category 'Config' -Name 'Cloud Cache directory separation' -Status 'FAIL' `
                -Detail "CacheDirectory and ProxyDirectory are both '$cacheDir'. These must be different paths."
        } else {
            Add-Result -Category 'Config' -Name 'Cloud Cache directory separation' -Status 'PASS' `
                -Detail "CacheDirectory: $cacheDir | ProxyDirectory: $proxyDir"
        }
    }

    # ------------------------------------------------------------------------
    # 3. AV/EDR exclusions
    # ------------------------------------------------------------------------

    $defenderPresent = [bool](Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue)
    if ($defenderPresent) {
        try {
            $mpPref = Get-MpPreference
            $exclProcesses = @()
            $exclPaths = @()
            if ($mpPref.ExclusionProcess) { $exclProcesses = $mpPref.ExclusionProcess }
            if ($mpPref.ExclusionPath) { $exclPaths = $mpPref.ExclusionPath }

            $expectedProcesses = @('frxsvc.exe', 'frxccds.exe')
            $expectedPaths = @(
                'C:\Program Files\FSLogix\Apps\',
                'C:\ProgramData\FSLogix\'
            )
            foreach ($loc in ($vhdLocations, $ccdLocations)) {
                if ($loc) { $expectedPaths += $loc }
            }

            $missingProcesses = @()
            foreach ($p in $expectedProcesses) {
                if ($exclProcesses -notcontains $p) { $missingProcesses += $p }
            }

            $missingPaths = @()
            foreach ($p in $expectedPaths) {
                $found = $false
                foreach ($e in $exclPaths) {
                    if ($e.TrimEnd('\') -ieq $p.TrimEnd('\')) { $found = $true; break }
                }
                if (-not $found) { $missingPaths += $p }
            }

            if ($missingProcesses.Count -eq 0 -and $missingPaths.Count -eq 0) {
                Add-Result -Category 'AV Exclusions' -Name 'Defender process and path exclusions' -Status 'PASS' `
                    -Detail 'All core FSLogix processes and folders are excluded from Defender scanning.'
            } else {
                $missingList = ($missingProcesses + $missingPaths) -join ', '
                Add-Result -Category 'AV Exclusions' -Name 'Defender process and path exclusions' -Status 'FAIL' `
                    -Detail "Missing exclusions: $missingList. Microsoft's own troubleshooting guidance calls missing AV exclusions the leading cause of FSLogix container corruption." `
                    -FixSuggestion "Add the missing process and path exclusions to Windows Defender." `
                    -FixAction {
                        foreach ($p in $missingProcesses) { Add-MpPreference -ExclusionProcess $p }
                        foreach ($p in $missingPaths) { Add-MpPreference -ExclusionPath $p }
                    }
            }
        } catch {
            Add-Result -Category 'AV Exclusions' -Name 'Defender process and path exclusions' -Status 'WARN' `
                -Detail "Could not read Defender preferences: $($_.Exception.Message)"
        }
    } else {
        Add-Result -Category 'AV Exclusions' -Name 'AV exclusions (third-party)' -Status 'INFO' `
            -Detail 'Windows Defender is not the active engine on this host. Third-party AV exclusion lists cannot be verified remotely - manually confirm the full Microsoft-documented exclusion list (processes frxsvc.exe/frxccds.exe, drivers frxdrv.sys/frxdrvvt.sys/frxccd.sys, FSLogix program/data folders, the VHD(X) share paths, and registry keys under HKLM\SOFTWARE\FSLogix and HKLM\SOFTWARE\Policies\FSLogix) is applied in your AV console.'
    }

    Add-Result -Category 'AV Exclusions' -Name 'File server / share side exclusions' -Status 'INFO' `
        -Detail 'This check only covers AV exclusions on the session host itself. If the profile share is on a Windows File Server, confirm the same VHD(X)/lock/meta file exclusions are also applied on the AV product protecting that server.'

    # ------------------------------------------------------------------------
    # 4. Storage reachability, write access, free space
    # ------------------------------------------------------------------------

    $storagePath = if ($usingCloudCache) { $ccdLocations } else { $vhdLocations }
    $firstPath = ($storagePath -split ';')[0]

    if ($usingCloudCache -and $firstPath -match 'connectionString=') {
        Add-Result -Category 'Storage' -Name 'Reachability / write test' -Status 'INFO' `
            -Detail 'Cloud Cache CCDLocations uses a connection string rather than a plain UNC path - skipping the direct reachability and write test for this entry.'
    } elseif ($firstPath -match '^\\\\([^\\]+)\\') {
        $serverName = $Matches[1]
        $portOpen = $false
        try {
            $portOpen = (Test-NetConnection -ComputerName $serverName -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue)
        } catch { $portOpen = $false }

        if ($portOpen) {
            Add-Result -Category 'Storage' -Name 'Share reachability (SMB/445)' -Status 'PASS' -Detail "$serverName is reachable on port 445."
        } else {
            Add-Result -Category 'Storage' -Name 'Share reachability (SMB/445)' -Status 'FAIL' -Detail "$serverName is not reachable on port 445. Check network/DNS/firewall."
        }

        if ($portOpen) {
            $testFile = Join-Path $firstPath ("HealthCheck_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
            try {
                'health check' | Out-File -FilePath $testFile -Encoding ascii -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                Add-Result -Category 'Storage' -Name 'Share write access' -Status 'PASS' -Detail 'Successfully created and removed a test file on the profile share.'
            } catch {
                Add-Result -Category 'Storage' -Name 'Share write access' -Status 'FAIL' `
                    -Detail "Share is reachable but this host could not write to it: $($_.Exception.Message). This is a distinct fault from reachability - check NTFS and share-level permissions."
            }

            try {
                $fso = New-Object -ComObject Scripting.FileSystemObject
                $drive = $fso.GetDrive($firstPath)
                $freeGB = [math]::Round($drive.FreeSpace / 1GB, 1)
                $totalGB = [math]::Round($drive.TotalSize / 1GB, 1)
                $pctFree = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 1) } else { 0 }

                if ($freeGB -lt 0.5 -or $pctFree -lt 10) {
                    $status = 'FAIL'
                } elseif ($freeGB -lt 2 -or $pctFree -lt 30) {
                    $status = 'WARN'
                } else {
                    $status = 'PASS'
                }
                Add-Result -Category 'Storage' -Name 'Profile share free space' -Status $status `
                    -Detail "$freeGB GB free of $totalGB GB ($pctFree% free). Microsoft recommends keeping at least 30% free, with hard alert thresholds around 2 GB / 500 MB."
            } catch {
                Add-Result -Category 'Storage' -Name 'Profile share free space' -Status 'INFO' `
                    -Detail "Could not determine free space on $firstPath automatically - check manually."
            }
        }

        if ($serverName -match 'file\.core\.windows\.net') {
            $encTypes = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Default $null
            if ($null -eq $encTypes) {
                Add-Result -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'INFO' `
                    -Detail 'SupportedEncryptionTypes is not explicitly set - this host uses the OS default, which may still allow RC4. Microsoft is hardening Kerberos to prefer AES-SHA1 by default in an upcoming Windows Server cumulative update (flagged for around April 2026); confirm the storage account and this host both support AES before that update lands.'
            } else {
                $rc4Bit = 4
                $aes128Bit = 8
                $aes256Bit = 16
                $hasRc4 = ([int]$encTypes -band $rc4Bit) -ne 0
                $hasAes = (([int]$encTypes -band $aes128Bit) -ne 0) -or (([int]$encTypes -band $aes256Bit) -ne 0)
                if ($hasRc4 -and -not $hasAes) {
                    Add-Result -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'WARN' `
                        -Detail "SupportedEncryptionTypes ($encTypes) allows RC4 only, no AES. Microsoft's Kerberos hardening update will affect access to this share once it lands - move to AES-SHA1 ahead of time."
                } else {
                    Add-Result -Category 'Storage' -Name 'Kerberos encryption (Azure Files)' -Status 'PASS' -Detail "SupportedEncryptionTypes ($encTypes) includes AES."
                }
            }
        }
    } else {
        Add-Result -Category 'Storage' -Name 'Reachability / write test' -Status 'INFO' `
            -Detail "Could not parse a UNC server name out of '$firstPath' - skipping automated reachability/write tests for this entry."
    }

    # ------------------------------------------------------------------------
    # 5. Services and drivers
    # ------------------------------------------------------------------------

    $svcChecks = @('frxsvc')
    if ($usingCloudCache) { $svcChecks += 'frxccds' }

    foreach ($svcName in $svcChecks) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-Result -Category 'Services' -Name "$svcName service" -Status 'FAIL' -Detail 'Service not found.'
        } elseif ($svc.Status -ne 'Running') {
            Add-Result -Category 'Services' -Name "$svcName service" -Status 'FAIL' -Detail "Service status is $($svc.Status), expected Running." `
                -FixSuggestion "Start the $svcName service." `
                -FixAction { Start-Service -Name $svcName }
        } else {
            Add-Result -Category 'Services' -Name "$svcName service" -Status 'PASS' -Detail 'Running.'
        }
    }

    try {
        $fltOutput = & fltmc filters 2>$null
        $fltText = $fltOutput -join "`n"
        $driversToCheck = @('frxdrv')
        if ($usingCloudCache) { $driversToCheck += 'frxccd' } else { $driversToCheck += 'frxdrvvt' }

        $missingDrivers = @()
        foreach ($d in $driversToCheck) {
            if ($fltText -notmatch $d) { $missingDrivers += $d }
        }
        if ($missingDrivers.Count -eq 0) {
            Add-Result -Category 'Services' -Name 'Minifilter drivers loaded' -Status 'PASS' -Detail "Expected FSLogix minifilters are loaded: $($driversToCheck -join ', ')."
        } else {
            Add-Result -Category 'Services' -Name 'Minifilter drivers loaded' -Status 'FAIL' -Detail "Not loaded: $($missingDrivers -join ', '). Container attach/redirect will not work correctly."
        }
    } catch {
        Add-Result -Category 'Services' -Name 'Minifilter drivers loaded' -Status 'WARN' -Detail "Could not run fltmc: $($_.Exception.Message)"
    }

    # ------------------------------------------------------------------------
    # 6. Live session state
    # ------------------------------------------------------------------------

    try {
        $currentUser = New-Object System.Security.Principal.NTAccount($env:USERNAME)
        $currentSid = ($currentUser.Translate([System.Security.Principal.SecurityIdentifier])).Value
        $sessionKey = "HKLM:\Software\FSLogix\Profiles\Sessions\$currentSid"

        if (Test-Path $sessionKey) {
            $status = Get-RegValue -Path $sessionKey -Name 'Status' -Default $null
            $reason = Get-RegValue -Path $sessionKey -Name 'Reason' -Default $null
            $errCode = Get-RegValue -Path $sessionKey -Name 'Error' -Default $null

            if ($status -eq 0) {
                Add-Result -Category 'Runtime' -Name 'Current user session mount status' -Status 'PASS' -Detail 'Status 0 (success).'
            } else {
                Add-Result -Category 'Runtime' -Name 'Current user session mount status' -Status 'WARN' `
                    -Detail "Status=$status, Reason=$reason, Error=$errCode. See Microsoft's FSLogix status/reason/error code reference (Troubleshooting - Error Codes page) to decode the specific value; this script does not guess at meanings it has not confirmed from Microsoft's documentation."
            }
        } else {
            Add-Result -Category 'Runtime' -Name 'Current user session mount status' -Status 'INFO' `
                -Detail "No session registry entry found for SID $currentSid. This is expected if the script is not running in the context of a signed-in FSLogix user session (for example, under LocalSystem via a scripted action)."
        }
    } catch {
        Add-Result -Category 'Runtime' -Name 'Current user session mount status' -Status 'INFO' -Detail "Could not evaluate: $($_.Exception.Message)"
    }

    try {
        $benignEventId26 = $entraJoined -and -not $domainJoined
        $fsLogixLogs = @('Microsoft-FSLogix-Apps/Admin', 'Microsoft-FSLogix-Apps/Operational')
        $errorCount = 0
        $sampleMessages = @()
        foreach ($logName in $fsLogixLogs) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue |
                    Where-Object { $_.LevelDisplayName -eq 'Error' -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }
                foreach ($e in $events) {
                    if ($benignEventId26 -and $e.Id -eq 26) { continue }
                    $errorCount++
                    if ($sampleMessages.Count -lt 5) { $sampleMessages += "[$($e.TimeCreated)] Event $($e.Id): $($e.Message)" }
                }
            } catch {
                # Log may not exist if the feature area (e.g. Cloud Cache) is not in use - skip quietly.
            }
        }

        if ($errorCount -eq 0) {
            Add-Result -Category 'Runtime' -Name 'FSLogix event log errors (last 7 days)' -Status 'PASS' -Detail 'No unfiltered Error-level events in the FSLogix Apps logs.'
        } else {
            Add-Result -Category 'Runtime' -Name 'FSLogix event log errors (last 7 days)' -Status 'WARN' `
                -Detail "$errorCount error-level event(s) found. Sample: $($sampleMessages -join ' | ')"
        }
    } catch {
        Add-Result -Category 'Runtime' -Name 'FSLogix event log errors (last 7 days)' -Status 'INFO' -Detail "Could not read event logs: $($_.Exception.Message)"
    }

    if (-not $usingCloudCache -and $firstPath -match '^\\\\') {
        try {
            $lockFiles = @(Get-ChildItem -Path $firstPath -Filter '*.lock' -Recurse -ErrorAction SilentlyContinue -Force)
            if ($lockFiles.Count -gt 0) {
                Add-Result -Category 'Runtime' -Name 'Orphaned lock files on profile share' -Status 'WARN' `
                    -Detail "$($lockFiles.Count) .lock file(s) found on the share. A lock file with no matching active session is a common 'container in use' cause - review manually before assuming any specific one is safe to remove."
            } else {
                Add-Result -Category 'Runtime' -Name 'Orphaned lock files on profile share' -Status 'PASS' -Detail 'No .lock files found at the top level of the scanned path.'
            }
        } catch {
            Add-Result -Category 'Runtime' -Name 'Orphaned lock files on profile share' -Status 'INFO' -Detail "Could not scan for lock files: $($_.Exception.Message)"
        }
    }

} else {
    Write-Host ""
    Write-Host "FSLogix is not installed - remaining checks skipped." -ForegroundColor Red
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------

$passCount = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$infoCount = @($script:Results | Where-Object { $_.Status -eq 'INFO' }).Count

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ("Summary: {0} pass, {1} warn, {2} fail, {3} info" -f $passCount, $warnCount, $failCount, $infoCount) -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# HTML report (built line by line - no here-strings, so this survives being
# re-serialized by the NME scripted action delivery wrapper unchanged)
# ----------------------------------------------------------------------------

$sb = New-Object System.Text.StringBuilder

function Add-Line {
    param([string]$Text)
    [void]$sb.AppendLine($Text)
}

Add-Line '<!DOCTYPE html>'
Add-Line '<html lang="en">'
Add-Line '<head>'
Add-Line '<meta charset="utf-8">'
Add-Line ('<title>FSLogix Health Check - ' + (ConvertTo-HtmlSafe $env:COMPUTERNAME) + '</title>')
Add-Line '<style>'
Add-Line 'body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f4f6f8; color: #1a1a1a; }'
Add-Line 'h1 { font-size: 20px; }'
Add-Line '.meta { color: #555; margin-bottom: 20px; }'
Add-Line '.summary { display: flex; gap: 12px; margin-bottom: 20px; }'
Add-Line '.chip { padding: 6px 14px; border-radius: 6px; font-weight: 600; color: #fff; }'
Add-Line '.chip-pass { background: #2e7d32; }'
Add-Line '.chip-warn { background: #b8860b; }'
Add-Line '.chip-fail { background: #c62828; }'
Add-Line '.chip-info { background: #616161; }'
Add-Line 'table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }'
Add-Line 'th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }'
Add-Line 'th { background: #263238; color: #fff; }'
Add-Line 'tr.status-pass { border-left: 4px solid #2e7d32; }'
Add-Line 'tr.status-warn { border-left: 4px solid #b8860b; }'
Add-Line 'tr.status-fail { border-left: 4px solid #c62828; }'
Add-Line 'tr.status-info { border-left: 4px solid #616161; }'
Add-Line '.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 12px; font-weight: 700; }'
Add-Line '.badge-pass { background: #2e7d32; }'
Add-Line '.badge-warn { background: #b8860b; }'
Add-Line '.badge-fail { background: #c62828; }'
Add-Line '.badge-info { background: #616161; }'
Add-Line '.category { color: #888; font-size: 12px; text-transform: uppercase; }'
Add-Line '.fix { color: #1565c0; font-size: 12px; margin-top: 4px; }'
Add-Line '</style>'
Add-Line '</head>'
Add-Line '<body>'
Add-Line ('<h1>FSLogix Health Check - ' + (ConvertTo-HtmlSafe $env:COMPUTERNAME) + '</h1>')
Add-Line ('<div class="meta">Generated ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + ' | FSLogix version: ' + (ConvertTo-HtmlSafe $fslogixVersion) + '</div>')
Add-Line '<div class="summary">'
Add-Line ('<span class="chip chip-pass">' + $passCount + ' Pass</span>')
Add-Line ('<span class="chip chip-warn">' + $warnCount + ' Warn</span>')
Add-Line ('<span class="chip chip-fail">' + $failCount + ' Fail</span>')
Add-Line ('<span class="chip chip-info">' + $infoCount + ' Info</span>')
Add-Line '</div>'
Add-Line '<table>'
Add-Line '<tr><th>Status</th><th>Category</th><th>Check</th><th>Detail</th></tr>'

foreach ($r in $script:Results) {
    $statusLower = $r.Status.ToLower()
    Add-Line ('<tr class="status-' + $statusLower + '">')
    Add-Line ('<td><span class="badge badge-' + $statusLower + '">' + (ConvertTo-HtmlSafe $r.Status) + '</span></td>')
    Add-Line ('<td class="category">' + (ConvertTo-HtmlSafe $r.Category) + '</td>')
    Add-Line ('<td>' + (ConvertTo-HtmlSafe $r.Name) + '</td>')
    $detailHtml = (ConvertTo-HtmlSafe $r.Detail)
    Add-Line ('<td>' + $detailHtml)
    if ($r.FixSuggestion) {
        $fixNote = if ($r.Fixed) { 'Fix applied during this run.' } else { 'Suggested fix: ' + (ConvertTo-HtmlSafe $r.FixSuggestion) }
        Add-Line ('<div class="fix">' + $fixNote + '</div>')
    }
    Add-Line '</td>'
    Add-Line '</tr>'
}

Add-Line '</table>'
Add-Line '</body>'
Add-Line '</html>'

try {
    [System.IO.File]::WriteAllText($ReportPath, $sb.ToString())
    Write-Host ""
    Write-Host "HTML report saved to: $ReportPath" -ForegroundColor Cyan
} catch {
    Write-Warning "Could not write HTML report to $ReportPath : $($_.Exception.Message)"
}

Write-Output "FSLogix Health Check complete. $passCount pass, $warnCount warn, $failCount fail, $infoCount info. Report: $ReportPath"

Stop-Transcript | Out-Null
