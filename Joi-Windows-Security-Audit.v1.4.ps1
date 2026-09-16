#requires -Version 5.1
<#
.SYNOPSIS
  One-time, read-only Windows security audit collector for analysis by Joi/Hermes.

.DESCRIPTION
  Collects broad security, persistence, startup, software, Defender/Security Center,
  firewall, networking, policy, user/group, service/driver, scheduled task, certificate,
  update and event-log information.

  PRIVACY / SCOPE BOUNDARY
  - Does NOT recursively enumerate Documents, Downloads, Desktop, Pictures, Videos,
    Music, OneDrive, or arbitrary user data directories.
  - The collector's own PowerShell/native inspection does NOT enumerate files on non-system drives.
    If Autorunsc is enabled, that external Sysinternals tool may access metadata of referenced images,
    including referenced files on other drives; use -SkipAutoruns for the strict no-touch boundary.
  - Does NOT dump browser history/cookies/passwords, Credential Manager, SAM/SECURITY
    hives, DPAPI secrets, LSASS memory, saved credentials, Wi-Fi keys, private keys,
    or file contents from personal folders.
  - It MAY record a configured path/command that points to another drive or a personal
    folder if Windows itself references that path as a service/task/startup/persistence
    entry. It will NOT open/hash/signature-check that referenced file.
  - File metadata/hash/signature inspection is restricted to referenced executable or
    script targets on the system drive and excludes personal content folders.
  - Narrow targeted exception: known PowerShell profile paths on the system drive may be checked
    non-recursively for existence/basic metadata (size/timestamps/owner) as a persistence signal.
    This includes the standard profile paths below the current user's Documents folder. Profile
    contents, hashes and signatures are never read. Profile paths on non-system drives are recorded only.
  - Specific system configuration files may be read (for example hosts and sshd_config)
    because their content is directly security-relevant.
  - The collector does not remediate or change Windows security settings, services, scheduled
    tasks, firewall, Defender or startup entries. It writes its own audit output folder.
    If Sysinternals Autorunsc is used with -accepteula, the Sysinternals tool may persist its
    normal EULA-acceptance value for the current user; no Autoruns entries are changed.

  Run from an elevated Windows PowerShell 5.1 or PowerShell 7 console.

.PARAMETER OutputRoot
  Parent folder for the timestamped audit directory. Default: C:\JoiAudit

.PARAMETER EventDays
  How far back to collect selected event logs. Default: 30 days.

.PARAMETER MaxEventsPerLog
  Maximum number of events exported from each selected channel/query. Default: 50000.

.PARAMETER AutorunscPath
  Optional path to Sysinternals autorunsc64.exe / autorunsc.exe.

.PARAMETER DownloadAutoruns
  If Autorunsc is not found, download the official Microsoft Sysinternals Autoruns ZIP,
  extract Autorunsc into a temporary folder inside this audit directory, run it, then
  remove the temporary binaries. No VirusTotal functionality is used.

.PARAMETER SkipAutoruns
  Never invoke Autorunsc, even if it is installed or -DownloadAutoruns was supplied. Autorunsc may
  access referenced image files to obtain metadata such as timestamps/version resources even without
  VirusTotal/hash/signature options. Use -SkipAutoruns when the strict no-touch boundary must also
  apply to external tooling and non-system-drive targets. Persistence coverage is reduced.

.PARAMETER SkipZip
  Do not create a ZIP archive at the end.

.EXAMPLE
  .\Joi-Windows-Security-Audit.ps1

.EXAMPLE
  .\Joi-Windows-Security-Audit.ps1 -EventDays 60 -DownloadAutoruns

.NOTES
  Designed for a one-time security audit, not continuous monitoring.

  v1.1 (2026-09-16):
  - IList collections (arrays, List[object], ...) are unrolled for CSV and JSON output; empty result
    sets are written explicitly instead of silently producing nothing at all.
  - Collector blocks are split into smaller groups so that one failing step no longer silently skips
    the remaining steps of its whole section; collector-errors.log names the failing script line.
  - The optional Sysinternals Autorunsc invocation is stderr-safe (Windows PowerShell 5.1), keeps
    stderr in its own file and records the process exit code.

  v1.2 (2026-09-16):
  - Collector quality is explicit: OK, PARTIAL or ERROR. Caught sub-step failures and non-zero native
    exit codes are recorded in collector-warnings.log and make the affected collector PARTIAL.
  - Event exports write per-query metadata (count, oldest/newest returned event, source-log coverage,
    and whether MaxEvents was reached) so truncated/short-retention data is visible to the analyst.
  - Adds pending-reboot/servicing state, per-service ServiceDll persistence, PowerShell profile metadata
    (metadata only, never profile contents), and system exploit/process-mitigation configuration.
  - Autorunsc temporary files are cleaned in finally, and archive creation gets a size preflight.
  - Empty CSV result sets are zero-byte CSV files plus a .meta.json marker instead of non-CSV text.
  - Per-target file metadata records expose hash/signature/ACL/stream inspection warnings instead of
    silently leaving fields null when one of those sub-checks fails.
  - Adds -SkipAutoruns for a conservative external-tool boundary; using it deliberately reduces
    persistence coverage but guarantees the collector itself will not launch Autorunsc.

  v1.3 (2026-09-16):
  - Native command exit codes are evaluated against per-call expected codes and recorded in collector
    status; expected non-zero codes no longer create false PARTIAL results. WinRM queries are skipped
    normally when the WinRM service is absent or not running.
  - collector_status.csv warning Details are capped at five entries while WarningCount stays complete;
    collector-warnings.log remains the authoritative full warning log.
  - PowerShell profile ACL-read failures are explicit warnings/OwnerError values; the targeted Documents
    profile-metadata exception is documented more precisely.
  - Autorunsc's possible metadata access to referenced images is documented; -SkipAutoruns is the strict
    no-touch mode for non-system-drive/personal referenced targets. collector_status_final.csv is the
    canonical QA status file.

  v1.4 (2026-09-16):
  - Autorunsc stdout is preserved verbatim in autorunsc_stdout_raw.txt, then normalized by locating the
    real CSV header after the Sysinternals banner. autoruns_all_users.csv is now a clean importable CSV.
  - Autoruns target correlation uses the normalized CSV, so Image Path entries are again included in the
    bounded persistence-target metadata/signature pass.
  - CSV normalization writes explicit metadata (header line, row count, raw/clean paths) for audit QA.
  - collector-errors.log and collector-warnings.log are created up front, even when they remain empty.
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = 'C:\JoiAudit',

    [ValidateRange(1, 3650)]
    [int]$EventDays = 30,

    [ValidateRange(100, 500000)]
    [int]$MaxEventsPerLog = 50000,

    [string]$AutorunscPath = '',

    [switch]$DownloadAutoruns,

    [switch]$SkipAutoruns,

    [switch]$SkipZip
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# -----------------------------------------------------------------------------
# Safety / initialization
# -----------------------------------------------------------------------------

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Error 'This collector must be run from an elevated PowerShell window (Run as administrator). It will not self-elevate.'
    exit 1
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$AuditRoot = Join-Path $OutputRoot ("JoiAudit-{0}-{1}" -f $env:COMPUTERNAME, $timestamp)
$Dirs = @(
    $AuditRoot,
    (Join-Path $AuditRoot 'system'),
    (Join-Path $AuditRoot 'security'),
    (Join-Path $AuditRoot 'persistence'),
    (Join-Path $AuditRoot 'software'),
    (Join-Path $AuditRoot 'network'),
    (Join-Path $AuditRoot 'users'),
    (Join-Path $AuditRoot 'events'),
    (Join-Path $AuditRoot 'registry'),
    (Join-Path $AuditRoot 'certificates'),
    (Join-Path $AuditRoot 'raw')
)
foreach ($d in $Dirs) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

$CollectorLog = Join-Path $AuditRoot 'collector.log'
$ErrorLog = Join-Path $AuditRoot 'collector-errors.log'
$WarningLog = Join-Path $AuditRoot 'collector-warnings.log'
# Always materialize the QA logs. Empty files mean no errors/warnings were recorded.
[IO.File]::WriteAllBytes($ErrorLog, [byte[]]@())
[IO.File]::WriteAllBytes($WarningLog, [byte[]]@())
$Status = New-Object System.Collections.Generic.List[object]
$script:CollectorContext = $null
$script:ArchivePreflight = $null

function Write-CollectorLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Tee-Object -FilePath $CollectorLog -Append | Write-Host
}

function Add-CollectorError {
    param([string]$Collector, [System.Management.Automation.ErrorRecord]$ErrorRecord)
    # The failing script line makes an aborted collector step identifiable in the log.
    $scriptLine = 0
    $scriptCode = ''
    if ($ErrorRecord.InvocationInfo) {
        $scriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        if ($ErrorRecord.InvocationInfo.Line) { $scriptCode = $ErrorRecord.InvocationInfo.Line.Trim() }
    }
    $line = '[{0}] [{1}] line {2}: {3} | {4}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Collector, $scriptLine, $ErrorRecord.Exception.Message, $scriptCode
    $line | Out-File -FilePath $ErrorLog -Append -Encoding utf8
}

function Add-CollectorWarning {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $collector = if ($script:CollectorContext) { $script:CollectorContext.Name } else { 'GLOBAL' }
    $detail = $Message
    if ($ErrorRecord) {
        $scriptLine = 0
        $scriptCode = ''
        if ($ErrorRecord.InvocationInfo) {
            $scriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
            if ($ErrorRecord.InvocationInfo.Line) { $scriptCode = $ErrorRecord.InvocationInfo.Line.Trim() }
        }
        $detail = '{0} line {1}: {2} | {3}' -f $Message, $scriptLine, $ErrorRecord.Exception.Message, $scriptCode
    }
    ('[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $collector, $detail) | Out-File -FilePath $WarningLog -Append -Encoding utf8
    if ($script:CollectorContext) { $script:CollectorContext.Warnings.Add($detail) }
}

function Get-CollectorWarningSummary {
    param(
        [System.Collections.Generic.List[string]]$Warnings,
        [int]$Limit = 5
    )
    if (-not $Warnings -or $Warnings.Count -eq 0) { return $null }
    $shown = @($Warnings | Select-Object -First $Limit)
    $summary = ($shown -join ' || ')
    if ($Warnings.Count -gt $Limit) {
        $remaining = $Warnings.Count - $Limit
        $summary += " || (+$remaining more; see collector-warnings.log)"
    }
    return $summary
}

function Invoke-Collector {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    Write-CollectorLog "START: $Name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $previousContext = $script:CollectorContext
    $context = [pscustomobject]@{
        Name = $Name
        Warnings = (New-Object System.Collections.Generic.List[string])
        NativeExitCodes = (New-Object System.Collections.Generic.List[string])
    }
    $script:CollectorContext = $context
    try {
        & $ScriptBlock
        $sw.Stop()
        $statusValue = if ($context.Warnings.Count -gt 0) { 'PARTIAL' } else { 'OK' }
        $details = Get-CollectorWarningSummary -Warnings $context.Warnings
        $nativeExitSummary = if ($context.NativeExitCodes.Count -gt 0) { $context.NativeExitCodes -join '; ' } else { $null }
        $Status.Add([pscustomobject]@{
            Collector=$Name; Status=$statusValue; Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2)
            WarningCount=$context.Warnings.Count; Details=$details
            NativeExitCount=$context.NativeExitCodes.Count; NativeExitCodes=$nativeExitSummary; Error=$null
        })
        Write-CollectorLog "DONE : $Name [$statusValue] ($([math]::Round($sw.Elapsed.TotalSeconds,2)) s)"
    }
    catch {
        $sw.Stop()
        Add-CollectorError -Collector $Name -ErrorRecord $_
        $details = Get-CollectorWarningSummary -Warnings $context.Warnings
        $nativeExitSummary = if ($context.NativeExitCodes.Count -gt 0) { $context.NativeExitCodes -join '; ' } else { $null }
        $Status.Add([pscustomobject]@{
            Collector=$Name; Status='ERROR'; Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2)
            WarningCount=$context.Warnings.Count; Details=$details
            NativeExitCount=$context.NativeExitCodes.Count; NativeExitCodes=$nativeExitSummary; Error=$_.Exception.Message
        })
        Write-CollectorLog "ERROR: $Name -- $($_.Exception.Message)"
    }
    finally {
        $script:CollectorContext = $previousContext
    }
}

function Invoke-CollectorStep {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    try { & $ScriptBlock }
    catch { Add-CollectorWarning -Message ("Step '$Name' failed.") -ErrorRecord $_ }
}

function Export-JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]$InputObject,
        [Parameter(Mandatory=$true, Position=1)][string]$Path,
        [Parameter(Position=2)][int]$Depth = 8,
        [switch]$AlwaysArray
    )
    begin { $items = New-Object System.Collections.Generic.List[object] }
    process {
        if ($null -ne $InputObject) {
            if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
                foreach ($x in $InputObject) { if ($null -ne $x) { $items.Add($x) } }
            }
            else { $items.Add($InputObject) }
        }
    }
    end {
        if ($items.Count -eq 0) {
            '[]' | Out-File -FilePath $Path -Encoding utf8
        }
        elseif ($AlwaysArray) {
            ConvertTo-Json -InputObject @($items.ToArray()) -Depth $Depth | Out-File -FilePath $Path -Encoding utf8
        }
        elseif ($items.Count -eq 1) {
            $items[0] | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding utf8
        }
        else {
            ConvertTo-Json -InputObject @($items.ToArray()) -Depth $Depth | Out-File -FilePath $Path -Encoding utf8
        }
    }
}

function Export-CsvFile {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]$InputObject,
        [Parameter(Mandatory=$true, Position=1)][string]$Path
    )
    begin { $items = New-Object System.Collections.Generic.List[object] }
    process {
        if ($null -ne $InputObject) {
            if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
                foreach ($x in $InputObject) { if ($null -ne $x) { $items.Add($x) } }
            }
            else { $items.Add($InputObject) }
        }
    }
    end {
        if ($items.Count -eq 0) {
            # Keep the .csv syntactically neutral. The sidecar distinguishes an empty result from a missing collector.
            [IO.File]::WriteAllBytes($Path, [byte[]]@())
            [pscustomobject]@{ Empty=$true; Rows=0; Note='Collector ran successfully but returned no rows.' } |
                ConvertTo-Json -Depth 3 | Out-File -FilePath ($Path + '.meta.json') -Encoding utf8
        }
        else {
            $items.ToArray() | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }
    }
}

function Convert-AutorunscCsvOutput {
    param(
        [Parameter(Mandatory=$true)][string]$RawPath,
        [Parameter(Mandatory=$true)][string]$CsvPath
    )

    if (-not (Test-Path -LiteralPath $RawPath -PathType Leaf)) {
        throw "Autorunsc raw stdout file was not created: $RawPath"
    }

    $lines = @(Get-Content -LiteralPath $RawPath -ErrorAction Stop)
    $headerIndex = -1
    $headerFields = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $candidate = ([string]$lines[$i]).TrimStart([char]0xFEFF)
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        # Do not assume a fixed banner length or an exact Autoruns version. The header is accepted when
        # the security-relevant canonical fields are all present. Quotes around field names are tolerated.
        $fieldNames = @($candidate.Split([char]',') | ForEach-Object { $_.Trim().Trim([char]34) })
        if (($fieldNames -contains 'Time') -and
            ($fieldNames -contains 'Entry Location') -and
            ($fieldNames -contains 'Entry') -and
            ($fieldNames -contains 'Category') -and
            ($fieldNames -contains 'Image Path') -and
            ($fieldNames -contains 'Launch String')) {
            $headerIndex = $i
            $headerFields = $fieldNames
            break
        }
    }

    if ($headerIndex -lt 0) {
        throw 'Autorunsc CSV header was not found after the Sysinternals banner.'
    }

    # Preserve the raw stdout separately and make the public .csv syntactically clean/importable.
    $lines[$headerIndex..($lines.Count - 1)] | Set-Content -LiteralPath $CsvPath -Encoding UTF8
    $rows = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)

    return [pscustomobject]@{
        RawPath = $RawPath
        CsvPath = $CsvPath
        RawLineCount = $lines.Count
        HeaderLineNumber = $headerIndex + 1
        BannerLineCount = $headerIndex
        Success = $true
        RowCount = $rows.Count
        Columns = $headerFields
    }
}

function Invoke-ExternalCapture {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [int[]]$ExpectedExitCodes = @(0)
    )
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments 2>&1 | Out-File -FilePath $OutputPath -Encoding utf8
        $exitCode = $LASTEXITCODE
        $isExpected = ($null -ne $exitCode -and $ExpectedExitCodes -contains [int]$exitCode)
        $exitLabel = if ($isExpected) { 'expected' } else { 'unexpected' }
        if ($script:CollectorContext -and $null -ne $exitCode) {
            $script:CollectorContext.NativeExitCodes.Add(("{0}={1}({2})" -f $FilePath,$exitCode,$exitLabel))
        }
        if ($isExpected) {
            Write-CollectorLog ("NATIVE: '$FilePath' exited with expected code $exitCode")
        }
        elseif ($null -ne $exitCode) {
            Add-CollectorWarning -Message ("Native command '$FilePath' exited with unexpected code $exitCode; expected: $($ExpectedExitCodes -join ','); see $OutputPath")
        }
        return $exitCode
    }
    finally {
        $ErrorActionPreference = $oldEap
    }
}

function Get-CommandIfAvailable {
    param([string]$Name)
    return Get-Command $Name -ErrorAction SilentlyContinue
}

function Get-RegistryKeySnapshot {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $props = [ordered]@{}
    foreach ($name in $item.GetValueNames()) {
        try {
            $value = $item.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $item.GetValueKind($name).ToString()
            $props[$name] = [pscustomobject]@{ Type=$kind; Value=$value }
        } catch {
            $props[$name] = [pscustomobject]@{ Type='ERROR'; Value=$_.Exception.Message }
        }
    }
    return [pscustomobject]@{ Path=$Path; Values=$props }
}

function Get-RegistryTreeSnapshot {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$MaxDepth = 4,
        [int]$CurrentDepth = 0
    )
    if (-not (Test-Path $Path)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $snap = Get-RegistryKeySnapshot -Path $Path
        if ($null -ne $snap) { $out.Add($snap) }
    }
    catch {
        Add-CollectorWarning -Message ("Registry snapshot failed for $Path.") -ErrorRecord $_
    }
    if ($CurrentDepth -lt $MaxDepth) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue) {
            foreach ($entry in Get-RegistryTreeSnapshot -Path $child.PSPath -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)) {
                $out.Add($entry)
            }
        }
    }
    return $out
}

function Test-PersonalContentPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path).Trim('"')
    $escapedDrive = [regex]::Escape($env:SystemDrive)
    $patterns = @(
        "^$escapedDrive\\Users\\[^\\]+\\Documents(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\Downloads(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\Desktop(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\Pictures(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\Videos(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\Music(?:\\|$)",
        "^$escapedDrive\\Users\\[^\\]+\\OneDrive(?:\\|$)"
    )
    foreach ($pattern in $patterns) {
        if ($p -match $pattern) { return $true }
    }
    return $false
}

function Test-AuditFileInspectionAllowed {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path).Trim('"')
    if ($p -notmatch '^[A-Za-z]:\\') { return $false }
    if (-not $p.StartsWith($env:SystemDrive + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if (Test-PersonalContentPath $p) { return $false }
    $ext = [IO.Path]::GetExtension($p)
    return $ext -match '^\.(exe|dll|sys|com|bat|cmd|ps1|psm1|psd1|vbs|vbe|js|jse|wsf|wsh|msi|msp|scr|cpl)$'
}

function Get-PrimaryExecutablePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $s = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($s -match '^\s*"([A-Za-z]:\\[^\"]+)"') { return $matches[1] }
    if ($s -match '^\s*([A-Za-z]:\\.*?\.(?:exe|com|bat|cmd|ps1|vbs|js|msi|scr|cpl|sys|dll))(?=\s|$)') { return $matches[1] }
    if ($s -match '^\s*([^\s]+\.(?:exe|com|bat|cmd|ps1|vbs|js|msi|scr|cpl))(?=\s|$)') {
        $candidate = $matches[1]
        $resolved = Get-Command $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($resolved -and $resolved.Source) { return $resolved.Source }
    }
    return $null
}

function Get-SafeTargetMetadata {
    param(
        [string]$Source,
        [string]$CommandLine
    )
    $path = Get-PrimaryExecutablePath -CommandLine $CommandLine
    $inspectionWarnings = New-Object System.Collections.Generic.List[string]
    $base = [ordered]@{
        Source = $Source
        CommandLine = $CommandLine
        ParsedPath = $path
        FileInspected = $false
        InspectionReason = $null
        Exists = $null
        Length = $null
        CreationTimeUtc = $null
        LastWriteTimeUtc = $null
        Version = $null
        Company = $null
        Product = $null
        SHA256 = $null
        SignatureStatus = $null
        Signer = $null
        Owner = $null
        Sddl = $null
        AlternateStreams = $null
        InspectionWarnings = $inspectionWarnings
    }
    if (-not $path) {
        $base.InspectionReason = 'No directly parseable executable/script path.'
        return [pscustomobject]$base
    }
    if (-not (Test-AuditFileInspectionAllowed $path)) {
        if ($path -match '^[A-Za-z]:\\' -and -not $path.StartsWith($env:SystemDrive + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $base.InspectionReason = 'Referenced path is on a non-system drive; path recorded from configuration, file not opened.'
        } elseif (Test-PersonalContentPath $path) {
            $base.InspectionReason = 'Referenced path is inside an excluded personal-content folder; path recorded from configuration, file not opened.'
        } else {
            $base.InspectionReason = 'File type/path outside approved inspection scope.'
        }
        return [pscustomobject]$base
    }
    try {
        $base.FileInspected = $true
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $base.Exists = $exists
        if (-not $exists) {
            $base.InspectionReason = 'Allowed target path, but file does not exist.'
            return [pscustomobject]$base
        }
        $item = Get-Item -LiteralPath $path -Force
        $base.Length = $item.Length
        $base.CreationTimeUtc = $item.CreationTimeUtc
        $base.LastWriteTimeUtc = $item.LastWriteTimeUtc
        if ($item.VersionInfo) {
            $base.Version = $item.VersionInfo.FileVersion
            $base.Company = $item.VersionInfo.CompanyName
            $base.Product = $item.VersionInfo.ProductName
        }
        try { $base.SHA256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch { $inspectionWarnings.Add('SHA256 failed: ' + $_.Exception.Message) }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $path
            $base.SignatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) { $base.Signer = $sig.SignerCertificate.Subject }
        } catch { $inspectionWarnings.Add('Authenticode signature query failed: ' + $_.Exception.Message) }
        try {
            $acl = Get-Acl -LiteralPath $path
            $base.Owner = $acl.Owner
            $base.Sddl = $acl.Sddl
        } catch { $inspectionWarnings.Add('ACL query failed: ' + $_.Exception.Message) }
        try {
            $streams = Get-Item -LiteralPath $path -Stream * -ErrorAction Stop | Select-Object Stream,Length
            $base.AlternateStreams = @($streams)
        } catch { $inspectionWarnings.Add('Alternate-stream query failed: ' + $_.Exception.Message) }
        $base.InspectionReason = 'Referenced file is on system drive and outside excluded personal-content folders.'
    }
    catch {
        $base.InspectionReason = 'Inspection failed: ' + $_.Exception.Message
    }
    return [pscustomobject]$base
}

function Export-EventQueryJsonl {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][hashtable]$Filter,
        [int]$MaxEvents = $MaxEventsPerLog
    )
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '_')
    $path = Join-Path (Join-Path $AuditRoot 'events') ($safeName + '.jsonl')
    $metaPath = $path + '.meta.json'
    $returned = 0
    $oldest = $null
    $newest = $null
    $coverage = [ordered]@{ LogName=$null; RecordCount=$null; OldestAvailable=$null; NewestAvailable=$null; CoverageError=$null }

    if ($Filter.ContainsKey('LogName') -and $Filter.LogName -is [string]) {
        $coverage.LogName = $Filter.LogName
        try {
            $logInfo = Get-WinEvent -ListLog $Filter.LogName -ErrorAction Stop
            $coverage.RecordCount = $logInfo.RecordCount
            if ($logInfo.RecordCount -gt 0) {
                $oldestRecord = Get-WinEvent -LogName $Filter.LogName -Oldest -MaxEvents 1 -ErrorAction Stop
                $newestRecord = Get-WinEvent -LogName $Filter.LogName -MaxEvents 1 -ErrorAction Stop
                if ($oldestRecord) { $coverage.OldestAvailable = $oldestRecord.TimeCreated }
                if ($newestRecord) { $coverage.NewestAvailable = $newestRecord.TimeCreated }
            }
        }
        catch { $coverage.CoverageError = $_.Exception.Message }
    }

    try {
        $events = Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop
        $writer = New-Object IO.StreamWriter($path, $false, (New-Object Text.UTF8Encoding($false)))
        try {
            foreach ($ev in $events) {
                $returned++
                if ($ev.TimeCreated) {
                    if ($null -eq $oldest -or $ev.TimeCreated -lt $oldest) { $oldest = $ev.TimeCreated }
                    if ($null -eq $newest -or $ev.TimeCreated -gt $newest) { $newest = $ev.TimeCreated }
                }
                $props = @()
                foreach ($p in $ev.Properties) { $props += $p.Value }
                $obj = [ordered]@{
                    TimeCreated = $ev.TimeCreated
                    Id = $ev.Id
                    Level = $ev.Level
                    LevelDisplayName = $ev.LevelDisplayName
                    ProviderName = $ev.ProviderName
                    LogName = $ev.LogName
                    RecordId = $ev.RecordId
                    ProcessId = $ev.ProcessId
                    ThreadId = $ev.ThreadId
                    UserId = if ($ev.UserId) { $ev.UserId.Value } else { $null }
                    MachineName = $ev.MachineName
                    Message = $ev.Message
                    Properties = $props
                }
                $writer.WriteLine(($obj | ConvertTo-Json -Compress -Depth 5))
            }
        }
        finally { $writer.Dispose() }

        [pscustomobject]@{
            Name=$Name
            Filter=$Filter
            RequestedStartTime=if ($Filter.ContainsKey('StartTime')) { $Filter.StartTime } else { $null }
            MaxEvents=$MaxEvents
            Returned=$returned
            HitMaxEventsLimit=($returned -ge $MaxEvents)
            OldestReturned=$oldest
            NewestReturned=$newest
            SourceLog=$coverage
            Note='HitMaxEventsLimit=true means the query may be truncated. SourceLog.OldestAvailable shows channel retention, which can be shorter than EventDays.'
        } | ConvertTo-Json -Depth 8 | Out-File -FilePath $metaPath -Encoding utf8
    }
    catch {
        if ($_.FullyQualifiedErrorId -match '^NoMatchingEventsFound') {
            [IO.File]::WriteAllBytes($path, [byte[]]@())
            [pscustomobject]@{
                Name=$Name; Filter=$Filter
                RequestedStartTime=if ($Filter.ContainsKey('StartTime')) { $Filter.StartTime } else { $null }
                MaxEvents=$MaxEvents; Returned=0; HitMaxEventsLimit=$false
                OldestReturned=$null; NewestReturned=$null; SourceLog=$coverage
                Note='Query completed with no matching events.'
            } | ConvertTo-Json -Depth 8 | Out-File -FilePath $metaPath -Encoding utf8
        }
        else {
            Add-CollectorWarning -Message ("Event query '$Name' failed.") -ErrorRecord $_
            ('ERROR: ' + $_.Exception.Message) | Out-File -FilePath ($path + '.error.txt') -Encoding utf8
            [pscustomobject]@{
                Name=$Name; Filter=$Filter; MaxEvents=$MaxEvents; Returned=$returned; Error=$_.Exception.Message; SourceLog=$coverage
            } | ConvertTo-Json -Depth 8 | Out-File -FilePath $metaPath -Encoding utf8
        }
    }
}

$StartTime = (Get-Date).AddDays(-$EventDays)
$PersistenceTargets = New-Object System.Collections.Generic.List[object]

Write-CollectorLog "Audit root: $AuditRoot"
Write-CollectorLog "Event window: last $EventDays day(s), max $MaxEventsPerLog events per query/channel"

# -----------------------------------------------------------------------------
# Scope manifest
# -----------------------------------------------------------------------------

Invoke-Collector 'Scope manifest' {
    $scope = [ordered]@{
        CollectorVersion = '1.4'
        ComputerName = $env:COMPUTERNAME
        CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        StartedAt = Get-Date
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
        IsAdministrator = $true
        SystemDrive = $env:SystemDrive
        EventDays = $EventDays
        MaxEventsPerLog = $MaxEventsPerLog
        SkipAutoruns = [bool]$SkipAutoruns
        PrivacyBoundary = @(
            'No recursive Documents/Downloads/Desktop/Pictures/Videos/Music/OneDrive enumeration, except targeted metadata-only checks of known PowerShell profile paths.',
            'The collector itself does not enumerate non-system-drive files; if Autorunsc is enabled, that external tool may access metadata of referenced images on other drives. Use -SkipAutoruns for strict no-touch.',
            'No browser history/cookies/passwords.',
            'No Credential Manager/SAM/SECURITY hive/DPAPI/LSASS/Wi-Fi key/private-key extraction.',
            'Configured path strings may identify excluded/non-system locations, but referenced files there are not opened.',
            'Specific system security configuration files may be read.',
            'Only referenced executable/script targets on the system drive and outside personal-content folders may be hashed/signature-checked.',
            'Known PowerShell profile paths on the system drive may be checked for existence/basic metadata only; their contents are never read. Non-system-drive profile paths are recorded only.'
        )
    }
    Export-JsonFile $scope (Join-Path $AuditRoot 'scope.json') 5

    @"
JOI WINDOWS SECURITY AUDIT - ANALYSIS SCOPE
==========================================
This dataset is a one-time security/configuration snapshot. It is not a copy of the user's personal files.

Primary goals:
- Identify unexpected startup/persistence mechanisms.
- Identify unnecessary or risky services, drivers, scheduled tasks, listeners, firewall rules, remote-access configuration and software.
- Reconcile Microsoft Defender status with Windows Security Center status and event logs.
- Identify stale/broken AV registrations, Defender exclusions, disabled protections, security-policy weaknesses and suspicious persistence.
- Correlate installed software -> service/task/startup -> executable path -> signature/hash metadata -> network listeners -> event history.

Important privacy boundary:
- Do not expect recursive Documents, Downloads, Desktop, media-folder, OneDrive or non-system-drive contents in this dataset.
- A service/task/autorun command may contain a PATH STRING pointing to such a place. The collector's own bounded file-inspection pass does not open that referenced file.
- Narrow targeted exception: known PowerShell profile PATHS may be listed as persistence locations. On the system drive only (including standard profile paths below Documents), existence/basic metadata may be recorded non-recursively; profile contents are never read. On non-system drives, only the path string is retained.
- External-tool caveat: if Autorunsc is enabled, Autorunsc may access metadata/version/timestamp information from referenced image files, including referenced images on non-system drives. Use -SkipAutoruns when strict no-touch of those files is required.

Data-quality check BEFORE drawing conclusions:
- Read collector_status_final.csv, collector-errors.log and collector-warnings.log first. collector_status_final.csv is canonical; collector_status.csv is only the pre-checksum snapshot.
- OK = collector completed without known sub-step warnings.
- PARTIAL = useful output exists, but at least one sub-step/native command failed or optional coverage was unavailable.
- ERROR = collector aborted on an unhandled error.
- For every events/*.jsonl used in a finding, inspect its matching .meta.json. HitMaxEventsLimit=true may mean truncation; SourceLog.OldestAvailable reveals short event-log retention.
- An empty CSV is represented by a zero-byte .csv plus a .csv.meta.json marker.
- Windows PowerShell 5.1 Out-File/Export-Csv UTF-8 outputs may carry a BOM; event JSONL is deliberately UTF-8 without BOM; CLIXML is PowerShell-native serialization.
- output_sha256.csv intentionally excludes the live collector logs/status files that can still change while finalization runs.
- If Autorunsc was used, -accepteula may have persisted the normal Sysinternals EULA-acceptance value for the current user. It does not remediate/disable/delete autorun entries.
- Autorunsc stdout is preserved as persistence/autorunsc_stdout_raw.txt (including the Sysinternals banner); persistence/autoruns_all_users.csv is the normalized banner-free CSV used for analysis and target correlation. persistence/autorunsc_csv_normalization.json records the normalization details.

Recommended output from the audit agent:
1. Executive summary.
2. Defender / Windows Security inconsistency diagnosis.
3. Persistence/startup findings grouped by confidence and risk.
4. Network exposure findings.
5. Security configuration findings.
6. Obsolete/unnecessary software/services/tasks.
7. Findings that need manual verification because the privacy boundary prevented file inspection.
8. Proposed remediation commands separately; DO NOT execute remediation automatically.
"@ | Out-File -FilePath (Join-Path $AuditRoot 'README_FOR_AGENT.txt') -Encoding utf8
}

# -----------------------------------------------------------------------------
# System / platform inventory
# -----------------------------------------------------------------------------

Invoke-Collector 'System inventory (platform)' {
    if (Get-CommandIfAvailable 'Get-ComputerInfo') {
        $computerInfo = Get-ComputerInfo
        $computerInfo | Export-Clixml -Path (Join-Path $AuditRoot 'system\computer_info.clixml')
        $computerInfo | Format-List * | Out-File (Join-Path $AuditRoot 'system\computer_info.txt') -Encoding utf8
    }
}

Invoke-Collector 'System inventory (hardware)' {
    $trimCim = { param($x) $x | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
    Invoke-CollectorStep 'Win32_OperatingSystem' { Export-JsonFile (& $trimCim (Get-CimInstance Win32_OperatingSystem)) (Join-Path $AuditRoot 'system\operating_system.json') 5 }
    Invoke-CollectorStep 'Win32_ComputerSystem' { Export-JsonFile (& $trimCim (Get-CimInstance Win32_ComputerSystem)) (Join-Path $AuditRoot 'system\computer_system.json') 5 }
    Invoke-CollectorStep 'Win32_BIOS' { Export-JsonFile (& $trimCim (Get-CimInstance Win32_BIOS)) (Join-Path $AuditRoot 'system\bios.json') 5 }
    Invoke-CollectorStep 'Win32_BaseBoard' { Export-JsonFile (& $trimCim (Get-CimInstance Win32_BaseBoard)) (Join-Path $AuditRoot 'system\baseboard.json') 5 }
    Invoke-CollectorStep 'Win32_Processor' { Export-JsonFile (& $trimCim (Get-CimInstance Win32_Processor)) (Join-Path $AuditRoot 'system\processor.json') 5 -AlwaysArray }
    Invoke-CollectorStep 'System drive' { Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType | Export-CsvFile -Path (Join-Path $AuditRoot 'system\system_drive.csv') }
    Invoke-CollectorStep 'Time zone' { Get-TimeZone | Format-List * | Out-File (Join-Path $AuditRoot 'system\timezone.txt') -Encoding utf8 }
}

Invoke-Collector 'System inventory (boot tools)' {
    Invoke-ExternalCapture 'systeminfo.exe' @() (Join-Path $AuditRoot 'system\systeminfo.txt') | Out-Null
    Invoke-ExternalCapture 'bcdedit.exe' @('/enum','all') (Join-Path $AuditRoot 'system\bcdedit_all.txt') | Out-Null
}

Invoke-Collector 'Security platform features' {
    if (Get-CommandIfAvailable 'Get-Tpm') {
        Invoke-CollectorStep 'TPM status' { Get-Tpm | Format-List * | Out-File (Join-Path $AuditRoot 'security\tpm.txt') -Encoding utf8 }
    }
    try {
        [pscustomobject]@{ SecureBootEnabled = (Confirm-SecureBootUEFI) } | Export-JsonFile -Path (Join-Path $AuditRoot 'security\secure_boot.json')
    } catch {
        [pscustomobject]@{ SecureBootEnabled=$null; Error=$_.Exception.Message } | Export-JsonFile -Path (Join-Path $AuditRoot 'security\secure_boot.json')
        Add-CollectorWarning -Message 'Secure Boot query failed.' -ErrorRecord $_
    }
    try {
        Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' |
            Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties |
            Export-JsonFile -Path (Join-Path $AuditRoot 'security\device_guard_vbs.json') -Depth 6
    } catch { Add-CollectorWarning -Message 'Device Guard / VBS query failed.' -ErrorRecord $_ }
    if (Get-CommandIfAvailable 'Get-BitLockerVolume') {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object MountPoint,VolumeType,VolumeStatus,EncryptionPercentage,EncryptionMethod,ProtectionStatus,LockStatus,AutoUnlockEnabled
            Export-JsonFile $bl (Join-Path $AuditRoot 'security\bitlocker_system_drive.json') 4
        } catch { Add-CollectorWarning -Message 'BitLocker system-drive query failed.' -ErrorRecord $_ }
    }
}

Invoke-Collector 'Windows optional features and capabilities' {
    if (Get-CommandIfAvailable 'Get-WindowsOptionalFeature') {
        Invoke-CollectorStep 'Optional features' { Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State | Sort-Object FeatureName | Export-CsvFile -Path (Join-Path $AuditRoot 'system\windows_optional_features.csv') }
    }
    if (Get-CommandIfAvailable 'Get-WindowsCapability') {
        Invoke-CollectorStep 'Windows capabilities' { Get-WindowsCapability -Online | Select-Object Name,State | Sort-Object Name | Export-CsvFile -Path (Join-Path $AuditRoot 'system\windows_capabilities.csv') }
    }
}

# -----------------------------------------------------------------------------
# Users / groups / sessions / local policy
# -----------------------------------------------------------------------------

Invoke-Collector 'Local users and groups' {
    if (Get-CommandIfAvailable 'Get-LocalUser') {
        Get-LocalUser | Select-Object Name,Enabled,Description,AccountExpires,PasswordExpires,PasswordLastSet,PasswordRequired,PasswordChangeableDate,UserMayChangePassword,LastLogon,SID,PrincipalSource | Export-CsvFile -Path (Join-Path $AuditRoot 'users\local_users.csv')
        $groups = Get-LocalGroup
        $groups | Select-Object Name,Description,SID,PrincipalSource | Export-CsvFile -Path (Join-Path $AuditRoot 'users\local_groups.csv')
        $members = New-Object System.Collections.Generic.List[object]
        foreach ($g in $groups) {
            try {
                foreach ($m in Get-LocalGroupMember -Group $g.Name -ErrorAction Stop) {
                    $members.Add([pscustomobject]@{ Group=$g.Name; Name=$m.Name; ObjectClass=$m.ObjectClass; PrincipalSource=$m.PrincipalSource; SID=$m.SID.Value })
                }
            } catch {
                $members.Add([pscustomobject]@{ Group=$g.Name; Name=$null; ObjectClass=$null; PrincipalSource=$null; SID=$null; Error=$_.Exception.Message })
                Add-CollectorWarning -Message ("Could not enumerate members of local group '$($g.Name)'.") -ErrorRecord $_
            }
        }
        Export-CsvFile $members (Join-Path $AuditRoot 'users\local_group_members.csv')
    }
}

Invoke-Collector 'Local users and groups (CLI)' {
    Invoke-ExternalCapture 'whoami.exe' @('/all') (Join-Path $AuditRoot 'users\whoami_all.txt') | Out-Null
    Invoke-ExternalCapture 'net.exe' @('accounts') (Join-Path $AuditRoot 'users\net_accounts.txt') | Out-Null
    # quser returns exit code 1 when there are no sessions to list; that is a valid audit result.
    Invoke-ExternalCapture 'quser.exe' @() (Join-Path $AuditRoot 'users\logged_on_sessions.txt') -ExpectedExitCodes @(0,1) | Out-Null
}

Invoke-Collector 'Local audit and security policy' {
    Invoke-ExternalCapture 'auditpol.exe' @('/get','/category:*','/r') (Join-Path $AuditRoot 'security\audit_policy.csv') | Out-Null
    Invoke-ExternalCapture 'secedit.exe' @('/export','/cfg',(Join-Path $AuditRoot 'security\local_security_policy.inf'),'/quiet') (Join-Path $AuditRoot 'raw\secedit_export_console.txt') | Out-Null
}

Invoke-Collector 'Effective policy (gpresult, AppLocker, execution policy)' {
    Invoke-ExternalCapture 'gpresult.exe' @('/r','/scope','computer') (Join-Path $AuditRoot 'security\gpresult_computer.txt') | Out-Null
    Invoke-ExternalCapture 'gpresult.exe' @('/r','/scope','user') (Join-Path $AuditRoot 'security\gpresult_user.txt') | Out-Null
    if (Get-CommandIfAvailable 'Get-AppLockerPolicy') {
        try { (Get-AppLockerPolicy -Effective -Xml) | Out-File (Join-Path $AuditRoot 'security\applocker_effective.xml') -Encoding utf8 } catch { Add-CollectorWarning -Message 'Effective AppLocker policy query failed.' -ErrorRecord $_ }
    }
    Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-File (Join-Path $AuditRoot 'security\powershell_execution_policy.txt') -Encoding utf8
}

# -----------------------------------------------------------------------------
# Installed software / packages / updates
# -----------------------------------------------------------------------------

Invoke-Collector 'Installed classic software' {
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($root in $uninstallRoots) {
        Get-ItemProperty $root -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,InstallSource,UninstallString,QuietUninstallString,WindowsInstaller,SystemComponent,PSPath
    }
    $apps | Sort-Object DisplayName,DisplayVersion -Unique | Export-CsvFile -Path (Join-Path $AuditRoot 'software\installed_classic_software.csv')
}

Invoke-Collector 'AppX/MSIX packages' {
    if (Get-CommandIfAvailable 'Get-AppxPackage') {
        Get-AppxPackage -AllUsers | Select-Object Name,PackageFullName,PackageFamilyName,Publisher,Architecture,Version,InstallLocation,IsFramework,NonRemovable,SignatureKind,Status | Sort-Object Name | Export-CsvFile -Path (Join-Path $AuditRoot 'software\appx_packages_all_users.csv')
    }
}

Invoke-Collector 'Windows updates (hotfixes)' {
    Get-HotFix | Select-Object Source,Description,HotFixID,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending | Export-CsvFile -Path (Join-Path $AuditRoot 'software\hotfixes.csv')
}

Invoke-Collector 'Windows updates (update history)' {
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        $hist = $searcher.QueryHistory(0, [Math]::Min($count, 1000)) | Select-Object Date,Title,Description,Operation,ResultCode,HResult,SupportUrl
        Export-CsvFile $hist (Join-Path $AuditRoot 'software\windows_update_history.csv')
    } catch {
        $_.Exception.Message | Out-File (Join-Path $AuditRoot 'software\windows_update_history.error.txt') -Encoding utf8
        Add-CollectorWarning -Message 'Windows Update history query failed.' -ErrorRecord $_
    }
}

Invoke-Collector 'Pending reboot and servicing state' {
    $sessionManager = Get-RegistryKeySnapshot 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pendingRename = $null
    $pendingRename2 = $null
    if ($sessionManager -and $sessionManager.Values) {
        if ($sessionManager.Values.Contains('PendingFileRenameOperations')) { $pendingRename = $sessionManager.Values['PendingFileRenameOperations'].Value }
        if ($sessionManager.Values.Contains('PendingFileRenameOperations2')) { $pendingRename2 = $sessionManager.Values['PendingFileRenameOperations2'].Value }
    }
    $activeComputerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
    $configuredComputerName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
    $updateExeVolatile = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction SilentlyContinue).UpdateExeVolatile
    [pscustomobject]@{
        WindowsUpdateRebootRequired = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        ComponentBasedServicingRebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        ComponentBasedServicingPackagesPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending')
        PendingFileRenameOperations = $pendingRename
        PendingFileRenameOperations2 = $pendingRename2
        UpdateExeVolatile = $updateExeVolatile
        ActiveComputerName = $activeComputerName
        ConfiguredComputerName = $configuredComputerName
        ComputerRenamePending = ($activeComputerName -and $configuredComputerName -and $activeComputerName -ne $configuredComputerName)
    } | Export-JsonFile -Path (Join-Path $AuditRoot 'software\pending_reboot_servicing_state.json') -Depth 8
}

# -----------------------------------------------------------------------------
# Services / drivers / devices
# -----------------------------------------------------------------------------

Invoke-Collector 'Services' {
    $services = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,Description,State,Status,StartMode,StartName,PathName,ProcessId,ServiceType,DesktopInteract,ExitCode,Started
    Export-CsvFile $services (Join-Path $AuditRoot 'persistence\services.csv')
    foreach ($s in $services) {
        if ($s.PathName) { $PersistenceTargets.Add([pscustomobject]@{ Source=('Service:' + $s.Name); CommandLine=$s.PathName }) }
    }
}

Invoke-Collector 'ServiceDll persistence' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($serviceKey in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
        $parametersPath = Join-Path $serviceKey.PSPath 'Parameters'
        if (-not (Test-Path $parametersPath)) { continue }
        try {
            $p = Get-ItemProperty -LiteralPath $parametersPath -ErrorAction Stop
            if ($null -ne $p.ServiceDll) {
                $rows.Add([pscustomobject]@{
                    ServiceName=$serviceKey.PSChildName
                    ServiceDll=$p.ServiceDll
                    ServiceMain=$p.ServiceMain
                    ServiceDllUnloadOnStop=$p.ServiceDllUnloadOnStop
                })
                $PersistenceTargets.Add([pscustomobject]@{ Source=('ServiceDll:' + $serviceKey.PSChildName); CommandLine=[string]$p.ServiceDll })
            }
        }
        catch { Add-CollectorWarning -Message ("Could not read ServiceDll parameters for '$($serviceKey.PSChildName)'.") -ErrorRecord $_ }
    }
    Export-CsvFile $rows (Join-Path $AuditRoot 'persistence\service_dlls.csv')
}

Invoke-Collector 'System drivers' {
    Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,Description,State,Status,StartMode,PathName,ServiceType,Started | Sort-Object Name | Export-CsvFile -Path (Join-Path $AuditRoot 'persistence\system_drivers.csv')
}

Invoke-Collector 'PnP signed drivers' {
    try {
        Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName,DeviceClass,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,IsSigned,Signer,DeviceID | Export-CsvFile -Path (Join-Path $AuditRoot 'system\pnp_signed_drivers.csv')
    } catch { Add-CollectorWarning -Message 'PnP signed-driver inventory failed.' -ErrorRecord $_ }
}

# -----------------------------------------------------------------------------
# Scheduled tasks / startup / persistence
# -----------------------------------------------------------------------------

Invoke-Collector 'Scheduled tasks' {
    if (-not (Get-CommandIfAvailable 'Get-ScheduledTask')) { return }
    $tasks = Get-ScheduledTask
    $taskDetails = New-Object System.Collections.Generic.List[object]
    foreach ($task in $tasks) {
        $info = $null
        try { $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop } catch { Add-CollectorWarning -Message ("Task info query failed for '$($task.TaskPath)$($task.TaskName)'.") -ErrorRecord $_ }
        $actions = @()
        foreach ($a in @($task.Actions)) {
            $actions += [pscustomobject]@{
                Execute = $a.Execute
                Arguments = $a.Arguments
                WorkingDirectory = $a.WorkingDirectory
                ClassId = $a.ClassId
                Data = $a.Data
            }
            $cmd = (($a.Execute, $a.Arguments) -join ' ').Trim()
            if ($cmd) { $PersistenceTargets.Add([pscustomobject]@{ Source=('ScheduledTask:' + $task.TaskPath + $task.TaskName); CommandLine=$cmd }) }
        }
        $triggers = @()
        foreach ($t in @($task.Triggers)) {
            $triggers += [pscustomobject]@{
                CimClass = $t.CimClass.CimClassName
                Enabled = $t.Enabled
                StartBoundary = $t.StartBoundary
                EndBoundary = $t.EndBoundary
                ExecutionTimeLimit = $t.ExecutionTimeLimit
                Delay = $t.Delay
                Repetition = $t.Repetition
                UserId = $t.UserId
                Subscription = $t.Subscription
            }
        }
        $taskDetails.Add([pscustomobject]@{
            TaskPath = $task.TaskPath
            TaskName = $task.TaskName
            State = $task.State
            Author = $task.Author
            Description = $task.Description
            URI = $task.URI
            Actions = $actions
            Triggers = $triggers
            Principal = $task.Principal
            Settings = $task.Settings
            LastRunTime = if ($info) { $info.LastRunTime } else { $null }
            LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
            NextRunTime = if ($info) { $info.NextRunTime } else { $null }
            NumberOfMissedRuns = if ($info) { $info.NumberOfMissedRuns } else { $null }
        })
    }
    Export-JsonFile $taskDetails (Join-Path $AuditRoot 'persistence\scheduled_tasks.json') 12 -AlwaysArray
}

Invoke-Collector 'Startup commands (WMI)' {
    $startup = Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User,UserSID
    Export-CsvFile $startup (Join-Path $AuditRoot 'persistence\win32_startup_commands.csv')
    foreach ($s in $startup) {
        if ($s.Command) { $PersistenceTargets.Add([pscustomobject]@{ Source=('StartupCommand:' + $s.Name); CommandLine=$s.Command }) }
    }

}

Invoke-Collector 'Startup folders' {
    $startupFolders = New-Object System.Collections.Generic.List[string]
    $common = [Environment]::GetFolderPath('CommonStartup')
    if ($common) { $startupFolders.Add($common) }
    $current = [Environment]::GetFolderPath('Startup')
    if ($current) { $startupFolders.Add($current) }
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    if (Test-Path $usersRoot) {
        foreach ($userDir in Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue) {
            $p = Join-Path $userDir.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            if (Test-Path $p) { $startupFolders.Add($p) }
        }
    }
    $startupFolders = $startupFolders | Sort-Object -Unique
    $shell = New-Object -ComObject WScript.Shell
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($folder in $startupFolders) {
        foreach ($item in Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction SilentlyContinue) {
            $target = $null; $linkArgs = $null; $work = $null
            if ($item.Extension -ieq '.lnk') {
                try {
                    $lnk = $shell.CreateShortcut($item.FullName)
                    $target = $lnk.TargetPath
                    $linkArgs = $lnk.Arguments
                    $work = $lnk.WorkingDirectory
                } catch { Add-CollectorWarning -Message ("Could not resolve startup shortcut '$($item.FullName)'.") -ErrorRecord $_ }
            }
            $entries.Add([pscustomobject]@{ Folder=$folder; Name=$item.Name; FullName=$item.FullName; Extension=$item.Extension; Length=$item.Length; LastWriteTimeUtc=$item.LastWriteTimeUtc; LinkTarget=$target; LinkArguments=$linkArgs; WorkingDirectory=$work })
            if ($target) {
                $cmd = (($target,$linkArgs) -join ' ').Trim()
                $PersistenceTargets.Add([pscustomobject]@{ Source=('StartupFolder:' + $item.FullName); CommandLine=$cmd })
            } elseif ($item.Extension -match '^\.(exe|com|bat|cmd|ps1|vbs|js|scr)$') {
                $PersistenceTargets.Add([pscustomobject]@{ Source=('StartupFolder:' + $item.FullName); CommandLine=('"' + $item.FullName + '"') })
            }
        }
    }
    Export-CsvFile $entries (Join-Path $AuditRoot 'persistence\startup_folder_entries.csv')
}

Invoke-Collector 'Registry persistence locations' {
    $snaps = New-Object System.Collections.Generic.List[object]
    $directKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SOFTWARE\Microsoft\Command Processor',
        'HKCU:\SOFTWARE\Microsoft\Command Processor',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    )
    foreach ($key in $directKeys) {
        try {
            $x = Get-RegistryKeySnapshot $key
            if ($null -ne $x) { $snaps.Add($x) }
        }
        catch { Add-CollectorWarning -Message ("Persistence registry snapshot failed for '$key'.") -ErrorRecord $_ }
    }

    # Loaded user hives only; do not load NTUSER.DAT from disk.
    if (Test-Path 'Registry::HKEY_USERS') {
        foreach ($hive in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
            $sid = $hive.PSChildName
            if ($sid -match '^S-1-5-21-' -and $sid -notmatch '_Classes$') {
                foreach ($suffix in @(
                    'Software\Microsoft\Windows\CurrentVersion\Run',
                    'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                    'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
                    'Software\Microsoft\Command Processor',
                    'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                    'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
                )) {
                    $path = "Registry::HKEY_USERS\$sid\$suffix"
                    try {
                        $x = Get-RegistryKeySnapshot $path
                        if ($null -ne $x) { $snaps.Add($x) }
                    }
                    catch { Add-CollectorWarning -Message ("Loaded-user persistence registry snapshot failed for '$path'.") -ErrorRecord $_ }
                }
            }
        }
    }
    Export-JsonFile $snaps (Join-Path $AuditRoot 'registry\startup_direct_keys.json') 8 -AlwaysArray

}

Invoke-Collector 'Registry persistence (trees and browser policies)' {
    # Recursive persistence/security-sensitive registry trees.
    $trees = [ordered]@{}
    foreach ($pair in @(
        @('IFEO','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',2),
        @('SilentProcessExit','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit',2),
        @('AppCertDlls','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',2),
        @('ActiveSetup64','HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',2),
        @('ActiveSetup32','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components',2),
        @('WinlogonNotify','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify',2),
        @('ShellExecuteHooks','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',1)
    )) {
        $trees[$pair[0]] = @(Get-RegistryTreeSnapshot -Path $pair[1] -MaxDepth ([int]$pair[2]))
    }
    Export-JsonFile $trees (Join-Path $AuditRoot 'registry\persistence_trees.json') 10

    # Browser extension deployment policy only; browser profile files/history are NOT read.
    $browserPolicyTrees = [ordered]@{}
    foreach ($pair in @(
        @('Edge','HKLM:\SOFTWARE\Policies\Microsoft\Edge',4),
        @('EdgeUser','HKCU:\SOFTWARE\Policies\Microsoft\Edge',4),
        @('Chrome','HKLM:\SOFTWARE\Policies\Google\Chrome',4),
        @('ChromeUser','HKCU:\SOFTWARE\Policies\Google\Chrome',4),
        @('Firefox','HKLM:\SOFTWARE\Policies\Mozilla\Firefox',4),
        @('FirefoxUser','HKCU:\SOFTWARE\Policies\Mozilla\Firefox',4)
    )) {
        $browserPolicyTrees[$pair[0]] = @(Get-RegistryTreeSnapshot -Path $pair[1] -MaxDepth ([int]$pair[2]))
    }
    Export-JsonFile $browserPolicyTrees (Join-Path $AuditRoot 'security\browser_extension_and_security_policies.json') 10
}

Invoke-Collector 'WMI permanent event subscriptions' {
    $ns = 'root\subscription'
    $out = [ordered]@{}
    foreach ($class in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','LogFileEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer','__FilterToConsumerBinding')) {
        try {
            $items = Get-CimInstance -Namespace $ns -ClassName $class -ErrorAction Stop
            $out[$class] = @($items | Select-Object *)
            if ($class -eq 'CommandLineEventConsumer') {
                foreach ($i in $items) {
                    if ($i.CommandLineTemplate) { $PersistenceTargets.Add([pscustomobject]@{ Source=('WMIConsumer:' + $i.Name); CommandLine=$i.CommandLineTemplate }) }
                    elseif ($i.ExecutablePath) { $PersistenceTargets.Add([pscustomobject]@{ Source=('WMIConsumer:' + $i.Name); CommandLine=$i.ExecutablePath }) }
                }
            }
        } catch { $out[$class] = @([pscustomobject]@{ Error=$_.Exception.Message }); Add-CollectorWarning -Message ("WMI subscription class '$class' query failed.") -ErrorRecord $_ }
    }
    Export-JsonFile $out (Join-Path $AuditRoot 'persistence\wmi_permanent_subscriptions.json') 12
}

Invoke-Collector 'BITS jobs' {
    if (Get-CommandIfAvailable 'Get-BitsTransfer') {
        try {
            Get-BitsTransfer -AllUsers | Select-Object DisplayName,Description,JobId,JobState,OwnerAccount,TransferType,Priority,CreationTime,ModificationTime,FilesTransferred,FilesTotal,BytesTransferred,BytesTotal | Export-CsvFile -Path (Join-Path $AuditRoot 'persistence\bits_jobs.csv')
        } catch {
            $_.Exception.Message | Out-File (Join-Path $AuditRoot 'persistence\bits_jobs.error.txt') -Encoding utf8
            Add-CollectorWarning -Message 'BITS all-users job query failed.' -ErrorRecord $_
        }
    }
}

# Sysinternals Autoruns is optional but strongly recommended for the broadest persistence coverage.
Invoke-Collector 'Sysinternals Autorunsc' {
    $tool = $null
    $tempToolDir = $null
    if ($SkipAutoruns) {
        Add-CollectorWarning -Message 'Autorunsc was explicitly disabled with -SkipAutoruns; some persistence classes are not covered by Sysinternals.'
        @"
Autorunsc was explicitly disabled with -SkipAutoruns.
Native Windows collectors were still used, but Sysinternals coverage (for example some Winsock, print-monitor, KnownDLL, BootExecute and shell-extension classes) is intentionally missing.
"@ | Out-File (Join-Path $AuditRoot 'persistence\autoruns_NOT_COLLECTED.txt') -Encoding utf8
    }
    else {
    try {
        $candidates = New-Object System.Collections.Generic.List[string]
        if ($AutorunscPath) { $candidates.Add($AutorunscPath) }
        foreach ($c in @(
            (Join-Path $PSScriptRoot 'autorunsc64.exe'),
            (Join-Path $PSScriptRoot 'autorunsc.exe'),
            'C:\Sysinternals\autorunsc64.exe',
            'C:\Sysinternals\autorunsc.exe',
            'C:\Tools\Sysinternals\autorunsc64.exe',
            'C:\Tools\Sysinternals\autorunsc.exe'
        )) { if ($c) { $candidates.Add($c) } }
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -PathType Leaf) { $tool = $c; break }
        }

        if (-not $tool -and $DownloadAutoruns) {
            $tempToolDir = Join-Path $AuditRoot '_autoruns_temp'
            New-Item -ItemType Directory -Path $tempToolDir -Force | Out-Null
            $zip = Join-Path $tempToolDir 'Autoruns.zip'
            try {
                Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Autoruns.zip' -OutFile $zip -UseBasicParsing
                Expand-Archive -LiteralPath $zip -DestinationPath $tempToolDir -Force
                foreach ($c in @((Join-Path $tempToolDir 'autorunsc64.exe'),(Join-Path $tempToolDir 'autorunsc.exe'))) {
                    if (Test-Path -LiteralPath $c) { $tool = $c; break }
                }
            }
            catch {
                Add-CollectorWarning -Message 'Sysinternals Autoruns download/extraction failed; native collectors will still be used.' -ErrorRecord $_
                $tool = $null
            }
        }

        if ($tool) {
            # Intentionally NO -v/-vs VirusTotal options and no broad -h/-s target hashing.
            # Autorunsc may still access referenced image files to populate ordinary metadata/version/
            # timestamp columns. Use -SkipAutoruns when even that external-tool metadata access is
            # outside the desired boundary.
            $autorunsRaw = Join-Path $AuditRoot 'persistence\autorunsc_stdout_raw.txt'
            $autorunsCsv = Join-Path $AuditRoot 'persistence\autoruns_all_users.csv'
            $autorunsNormalizeMeta = Join-Path $AuditRoot 'persistence\autorunsc_csv_normalization.json'
            $autorunsStderr = Join-Path $AuditRoot 'persistence\autorunsc_stderr.txt'
            $autorunsExitCode = $null
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & $tool '-accepteula' '-a' '*' '-c' '-t' '*' 2> $autorunsStderr | Out-File $autorunsRaw -Encoding utf8
                $autorunsExitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $previousPreference }

            try {
                $vi = (Get-Item -LiteralPath $tool).VersionInfo
                $stdoutBytes = if (Test-Path -LiteralPath $autorunsRaw) { (Get-Item -LiteralPath $autorunsRaw).Length } else { $null }
                $stderrBytes = if (Test-Path -LiteralPath $autorunsStderr) { (Get-Item -LiteralPath $autorunsStderr).Length } else { $null }
                [pscustomobject]@{
                    Path=$tool; ProductVersion=$vi.ProductVersion; FileVersion=$vi.FileVersion
                    CompanyName=$vi.CompanyName; ExitCode=$autorunsExitCode
                    RawStdout=$autorunsRaw; RawStdoutBytes=$stdoutBytes
                    NormalizedCsv=$autorunsCsv; Stderr=$autorunsStderr; StderrBytes=$stderrBytes
                } | Export-JsonFile -Path (Join-Path $AuditRoot 'persistence\autorunsc_version.json')
            }
            catch { Add-CollectorWarning -Message 'Could not read Autorunsc version metadata.' -ErrorRecord $_ }

            if ($null -ne $autorunsExitCode -and $autorunsExitCode -ne 0) {
                Add-CollectorWarning -Message ("autorunsc.exe returned exit code $autorunsExitCode; output may be incomplete.")
                ('autorunsc.exe returned exit code {0}; autorunsc_stdout_raw.txt / autoruns_all_users.csv may be incomplete.' -f $autorunsExitCode) |
                    Out-File (Join-Path $AuditRoot 'persistence\autoruns_EXIT_CODE_WARNING.txt') -Encoding utf8
            }

            try {
                $normalization = Convert-AutorunscCsvOutput -RawPath $autorunsRaw -CsvPath $autorunsCsv
                $normalization | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $autorunsNormalizeMeta -Encoding utf8

                $rows = @(Import-Csv -LiteralPath $autorunsCsv -ErrorAction Stop)
                if ($rows.Count -gt 0) {
                    $props = @($rows[0].PSObject.Properties.Name)
                    $imageProp = $props | Where-Object { $_ -match '^(Image Path|ImagePath)$' } | Select-Object -First 1
                    $entryProp = $props | Where-Object { $_ -match '^(Entry|Entry Name|EntryName)$' } | Select-Object -First 1
                    if ($imageProp) {
                        foreach ($row in $rows) {
                            $img = $row.$imageProp
                            if ($img) {
                                $label = if ($entryProp) { $row.$entryProp } else { 'AutorunsEntry' }
                                $PersistenceTargets.Add([pscustomobject]@{ Source=('Autoruns:' + $label); CommandLine=$img })
                            }
                        }
                    }
                    else { Add-CollectorWarning -Message 'Normalized Autorunsc CSV did not expose an Image Path column; target correlation is reduced.' }
                }
            }
            catch {
                Add-CollectorWarning -Message 'Autorunsc stdout normalization/CSV import/target correlation failed; inspect autorunsc_stdout_raw.txt.' -ErrorRecord $_
                [pscustomobject]@{
                    RawPath=$autorunsRaw; CsvPath=$autorunsCsv; Success=$false; Error=$_.Exception.Message
                } | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $autorunsNormalizeMeta -Encoding utf8
            }
        }
        else {
            Add-CollectorWarning -Message 'Autorunsc was not available; coverage for some persistence classes is missing.'
            @"
Autorunsc was not found, so the native Windows persistence collectors were used but Sysinternals Autoruns coverage is missing.
For a broader audit, place autorunsc64.exe next to this script, pass -AutorunscPath, or rerun with -DownloadAutoruns.
"@ | Out-File (Join-Path $AuditRoot 'persistence\autoruns_NOT_COLLECTED.txt') -Encoding utf8
        }
    }
    finally {
        if ($tempToolDir -and (Test-Path -LiteralPath $tempToolDir)) {
            Remove-Item -LiteralPath $tempToolDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    }
}

# -----------------------------------------------------------------------------
# Defender / Security Center / security-health discrepancy diagnostics
# -----------------------------------------------------------------------------

Invoke-Collector 'Microsoft Defender status and configuration' {
    if (Get-CommandIfAvailable 'Get-MpComputerStatus') {
        Invoke-CollectorStep 'Get-MpComputerStatus' {
            $mpStatus = Get-MpComputerStatus
            $mpStatus | Format-List * | Out-File (Join-Path $AuditRoot 'security\defender_computer_status.txt') -Encoding utf8
            Export-JsonFile $mpStatus (Join-Path $AuditRoot 'security\defender_computer_status.json') 6
        }
    }
    else { Add-CollectorWarning -Message 'Get-MpComputerStatus is not available.' }
    if (Get-CommandIfAvailable 'Get-MpPreference') {
        Invoke-CollectorStep 'Get-MpPreference' {
            $mpPreference = Get-MpPreference
            $mpPreference | Format-List * | Out-File (Join-Path $AuditRoot 'security\defender_preferences.txt') -Encoding utf8
            Export-JsonFile $mpPreference (Join-Path $AuditRoot 'security\defender_preferences.json') 8
        }
    }
    else { Add-CollectorWarning -Message 'Get-MpPreference is not available.' }
}

Invoke-Collector 'Defender detections and service state' {
    if (Get-CommandIfAvailable 'Get-MpThreat') {
        try { Export-JsonFile (Get-MpThreat) (Join-Path $AuditRoot 'security\defender_threats.json') 8 -AlwaysArray } catch { Add-CollectorWarning -Message 'Defender threat inventory failed.' -ErrorRecord $_ }
    }
    if (Get-CommandIfAvailable 'Get-MpThreatDetection') {
        try { Export-JsonFile (Get-MpThreatDetection) (Join-Path $AuditRoot 'security\defender_threat_detections.json') 8 -AlwaysArray } catch { Add-CollectorWarning -Message 'Defender threat-detection history failed.' -ErrorRecord $_ }
    }
    Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('WinDefend','WdNisSvc','SecurityHealthService','wscsvc','Sense','MsSense') } | Select-Object Name,DisplayName,Status,StartType | Export-CsvFile -Path (Join-Path $AuditRoot 'security\security_services.csv')
}

Invoke-Collector 'Windows Security Center registered products' {
    $result = [ordered]@{}
    foreach ($class in @('AntiVirusProduct','FirewallProduct','AntiSpywareProduct')) {
        try {
            $items = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName $class -ErrorAction Stop | Select-Object displayName,instanceGuid,pathToSignedProductExe,pathToSignedReportingExe,productState,timestamp
            $result[$class] = @($items)
        } catch {
            $result[$class] = @([pscustomobject]@{ Error=$_.Exception.Message })
            Add-CollectorWarning -Message ("SecurityCenter2 class '$class' query failed.") -ErrorRecord $_
        }
    }
    Export-JsonFile $result (Join-Path $AuditRoot 'security\security_center_registered_products.json') 8

}

Invoke-Collector 'Windows Security Center registry' {
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Microsoft\Security Center',
        'HKLM:\SOFTWARE\Microsoft\Security Center\Provider',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityCenter'
    )) {
        $safe = ($key -replace '[:\\]','_')
        try {
            Export-JsonFile (Get-RegistryTreeSnapshot -Path $key -MaxDepth 3) (Join-Path $AuditRoot ("registry\securitycenter_{0}.json" -f $safe)) 10 -AlwaysArray
        } catch { Add-CollectorWarning -Message ("Security Center registry snapshot failed for '$key'.") -ErrorRecord $_ }
    }
}

# -----------------------------------------------------------------------------
# Firewall / network / remote access / shares
# -----------------------------------------------------------------------------

Invoke-Collector 'Network adapters, IP, routes and DNS' {
    if (Get-CommandIfAvailable 'Get-NetAdapter') { Invoke-CollectorStep 'Network adapters' { Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceIndex,Status,MacAddress,LinkSpeed,MediaType,PhysicalMediaType,Virtual,DriverInformation | Export-CsvFile -Path (Join-Path $AuditRoot 'network\adapters.csv') } }
    if (Get-CommandIfAvailable 'Get-NetIPAddress') { Invoke-CollectorStep 'IP addresses' { Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressState,Type | Export-CsvFile -Path (Join-Path $AuditRoot 'network\ip_addresses.csv') } }
    if (Get-CommandIfAvailable 'Get-NetRoute') { Invoke-CollectorStep 'Routes' { Get-NetRoute | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric,Protocol,State | Export-CsvFile -Path (Join-Path $AuditRoot 'network\routes.csv') } }
    if (Get-CommandIfAvailable 'Get-DnsClientServerAddress') { Invoke-CollectorStep 'DNS servers' { Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses | Export-JsonFile -Path (Join-Path $AuditRoot 'network\dns_servers.json') -Depth 5 -AlwaysArray } }
    if (Get-CommandIfAvailable 'Get-DnsClientNrptPolicy') { Invoke-CollectorStep 'NRPT policy' { Get-DnsClientNrptPolicy -Effective | Export-JsonFile -Path (Join-Path $AuditRoot 'network\nrpt_effective.json') -Depth 8 -AlwaysArray } }
    if (Get-CommandIfAvailable 'Get-NetConnectionProfile') { Invoke-CollectorStep 'Connection profiles' { Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity | Export-CsvFile -Path (Join-Path $AuditRoot 'network\connection_profiles.csv') } }
}

Invoke-Collector 'Listeners, connections and proxy' {
    $procMap = @{}
    try { foreach ($p in Get-CimInstance Win32_Process) { $procMap[[int]$p.ProcessId] = $p.Name } }
    catch { Add-CollectorWarning -Message 'Process-name map for network endpoints failed; endpoint rows may lack ProcessName.' -ErrorRecord $_ }
    if (Get-CommandIfAvailable 'Get-NetTCPConnection') {
        Invoke-CollectorStep 'TCP connections/listeners' { Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,OwningProcess,@{N='ProcessName';E={$procMap[[int]$_.OwningProcess]}} | Export-CsvFile -Path (Join-Path $AuditRoot 'network\tcp_connections_and_listeners.csv') }
    }
    if (Get-CommandIfAvailable 'Get-NetUDPEndpoint') {
        Invoke-CollectorStep 'UDP endpoints' { Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={$procMap[[int]$_.OwningProcess]}} | Export-CsvFile -Path (Join-Path $AuditRoot 'network\udp_endpoints.csv') }
    }
    Invoke-CollectorStep 'netstat -ano' { Invoke-ExternalCapture 'netstat.exe' @('-ano') (Join-Path $AuditRoot 'network\netstat_ano.txt') | Out-Null }
    Invoke-CollectorStep 'WinHTTP proxy' { Invoke-ExternalCapture 'netsh.exe' @('winhttp','show','proxy') (Join-Path $AuditRoot 'network\winhttp_proxy.txt') | Out-Null }

}

Invoke-Collector 'Network registry settings and hosts file' {
    foreach ($key in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    )) {
        try {
            $snap = Get-RegistryKeySnapshot $key
            if ($snap) {
                $name = ($key -replace '[:\\]','_')
                Export-JsonFile $snap (Join-Path $AuditRoot ("network\registry_{0}.json" -f $name)) 6
            }
        } catch { Add-CollectorWarning -Message ("Network registry snapshot failed for '$key'.") -ErrorRecord $_ }
    }

    # Specific system networking config file: allowed by audit scope.
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path $hosts) { Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | Out-File (Join-Path $AuditRoot 'network\hosts_file.txt') -Encoding utf8 }
}

Invoke-Collector 'Process inventory' {
    Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate,SessionId,HandleCount,ThreadCount,WorkingSetSize,VirtualSize | Export-CsvFile -Path (Join-Path $AuditRoot 'system\processes_with_commandlines.csv')
}

Invoke-Collector 'Windows Firewall profiles' {
    if (Get-CommandIfAvailable 'Get-NetFirewallProfile') {
        Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,NotifyOnListen,LogFileName,LogMaxSizeKilobytes,LogAllowed,LogBlocked,LogIgnored | Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_profiles.csv')
    }
}

Invoke-Collector 'Windows Firewall rules and filters' {
    if (Get-CommandIfAvailable 'Get-NetFirewallRule') {
        Invoke-CollectorStep 'Firewall rules' {
            Get-NetFirewallRule | Select-Object Name,DisplayName,Description,DisplayGroup,Group,Enabled,Profile,Platform,Direction,Action,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Owner,PrimaryStatus,Status,PolicyStoreSource,PolicyStoreSourceType |
                Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_rules.csv')
        }
    }
    if (Get-CommandIfAvailable 'Get-NetFirewallPortFilter') {
        Invoke-CollectorStep 'Firewall port filters' {
            Get-NetFirewallPortFilter | Select-Object InstanceID,Protocol,@{N='LocalPort';E={@($_.LocalPort) -join ';'}},@{N='RemotePort';E={@($_.RemotePort) -join ';'}},@{N='IcmpType';E={@($_.IcmpType) -join ';'}},DynamicTarget |
                Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_port_filters.csv')
        }
    }
    if (Get-CommandIfAvailable 'Get-NetFirewallAddressFilter') {
        Invoke-CollectorStep 'Firewall address filters' {
            Get-NetFirewallAddressFilter | Select-Object InstanceID,@{N='LocalAddress';E={@($_.LocalAddress) -join ';'}},@{N='RemoteAddress';E={@($_.RemoteAddress) -join ';'}} |
                Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_address_filters.csv')
        }
    }
    if (Get-CommandIfAvailable 'Get-NetFirewallApplicationFilter') {
        Invoke-CollectorStep 'Firewall application filters' { Get-NetFirewallApplicationFilter | Select-Object InstanceID,Program,Package | Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_application_filters.csv') }
    }
    if (Get-CommandIfAvailable 'Get-NetFirewallServiceFilter') {
        Invoke-CollectorStep 'Firewall service filters' { Get-NetFirewallServiceFilter | Select-Object InstanceID,Service | Export-CsvFile -Path (Join-Path $AuditRoot 'network\firewall_service_filters.csv') }
    }
    if (Get-CommandIfAvailable 'Get-NetIPsecRule') {
        Invoke-CollectorStep 'IPsec rules' { Get-NetIPsecRule | Select-Object Name,DisplayName,Enabled,Profile,Mode,InboundSecurity,OutboundSecurity,PrimaryStatus,Status | Export-CsvFile -Path (Join-Path $AuditRoot 'network\ipsec_rules.csv') }
    }
}

Invoke-Collector 'SMB shares and SMB configuration' {
    if (Get-CommandIfAvailable 'Get-SmbShare') {
        $shares = Get-SmbShare | Select-Object Name,Path,Description,ScopeName,FolderEnumerationMode,CachingMode,EncryptData,ConcurrentUserLimit,Special
        Export-CsvFile $shares (Join-Path $AuditRoot 'network\smb_shares.csv')
        $access = New-Object System.Collections.Generic.List[object]
        foreach ($s in $shares) {
            try {
                foreach ($a in Get-SmbShareAccess -Name $s.Name -ErrorAction Stop) {
                    $access.Add([pscustomobject]@{ Share=$s.Name; AccountName=$a.AccountName; AccessControlType=$a.AccessControlType; AccessRight=$a.AccessRight })
                }
            } catch { Add-CollectorWarning -Message ("SMB share access query failed for '$($s.Name)'.") -ErrorRecord $_ }
        }
        Export-CsvFile $access (Join-Path $AuditRoot 'network\smb_share_access.csv')
    }
}

Invoke-Collector 'SMB server and client configuration' {
    if (Get-CommandIfAvailable 'Get-SmbServerConfiguration') { Get-SmbServerConfiguration | Format-List * | Out-File (Join-Path $AuditRoot 'network\smb_server_configuration.txt') -Encoding utf8 }
    if (Get-CommandIfAvailable 'Get-SmbClientConfiguration') { Get-SmbClientConfiguration | Format-List * | Out-File (Join-Path $AuditRoot 'network\smb_client_configuration.txt') -Encoding utf8 }
}

Invoke-Collector 'Remote access configuration' {
    $rdp = [ordered]@{}
    foreach ($key in @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    )) {
        try { $rdp[$key] = Get-RegistryKeySnapshot $key } catch { $rdp[$key] = [pscustomobject]@{ Error=$_.Exception.Message }; Add-CollectorWarning -Message ("RDP/Remote Assistance registry snapshot failed for '$key'.") -ErrorRecord $_ }
    }
    Export-JsonFile $rdp (Join-Path $AuditRoot 'network\rdp_remote_assistance_config.json') 8

}

Invoke-Collector 'Remote access (WinRM, OpenSSH, services)' {
    $winrmService = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
    $winrmState = [pscustomobject]@{
        Installed = [bool]$winrmService
        Status = if ($winrmService) { [string]$winrmService.Status } else { $null }
        StartType = if ($winrmService) { [string]$winrmService.StartType } else { $null }
        CliQueriesAttempted = [bool]($winrmService -and $winrmService.Status -eq 'Running')
    }
    Export-JsonFile $winrmState (Join-Path $AuditRoot 'network\winrm_service_state.json') 4
    if ($winrmService -and $winrmService.Status -eq 'Running') {
        try { Invoke-ExternalCapture 'winrm.cmd' @('get','winrm/config') (Join-Path $AuditRoot 'network\winrm_config.txt') | Out-Null } catch { Add-CollectorWarning -Message 'WinRM configuration query failed while the WinRM service was running.' -ErrorRecord $_ }
        try { Invoke-ExternalCapture 'winrm.cmd' @('enumerate','winrm/config/listener') (Join-Path $AuditRoot 'network\winrm_listeners.txt') | Out-Null } catch { Add-CollectorWarning -Message 'WinRM listener query failed while the WinRM service was running.' -ErrorRecord $_ }
    }
    else {
        $stateText = if ($winrmService) { "WinRM service is present but not running (Status=$($winrmService.Status), StartType=$($winrmService.StartType)); winrm.cmd queries were intentionally not attempted." } else { 'WinRM service is not installed/present; winrm.cmd queries were intentionally not attempted.' }
        $stateText | Out-File (Join-Path $AuditRoot 'network\winrm_queries_NOT_ATTEMPTED.txt') -Encoding utf8
        Write-CollectorLog "INFO : $stateText"
    }

    $sshConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
    if (Test-Path $sshConfig) {
        # Specific security configuration file, not a user document.
        Get-Content -LiteralPath $sshConfig -ErrorAction SilentlyContinue | Out-File (Join-Path $AuditRoot 'network\openssh_sshd_config.txt') -Encoding utf8
    }
    Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('TermService','WinRM','sshd','RemoteRegistry') } | Select-Object Name,DisplayName,Status,StartType | Export-CsvFile -Path (Join-Path $AuditRoot 'network\remote_access_services.csv')
}

# -----------------------------------------------------------------------------
# Security-related registry / PowerShell / hardening settings
# -----------------------------------------------------------------------------

Invoke-Collector 'Security-sensitive registry configuration' {
    $securityTrees = [ordered]@{}
    foreach ($pair in @(
        @('UAC','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',3),
        @('Lsa','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',3),
        @('LanmanServer','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',2),
        @('LanmanWorkstation','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',2),
        @('PowerShellPoliciesMachine','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',5),
        @('PowerShellPoliciesUser','HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',5),
        @('WindowsSystemPolicies','HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',3),
        @('CredentialsDelegation','HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation',4),
        @('WDigest','HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',2),
        @('Schannel','HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',4),
        @('CryptographyPolicies','HKLM:\SOFTWARE\Policies\Microsoft\Cryptography',4)
    )) {
        $securityTrees[$pair[0]] = @(Get-RegistryTreeSnapshot -Path $pair[1] -MaxDepth ([int]$pair[2]))
    }
    Export-JsonFile $securityTrees (Join-Path $AuditRoot 'security\security_registry_configuration.json') 12
}

Invoke-Collector 'PowerShell profile metadata' {
    # Specific persistence-relevant profile paths only. Profile CONTENTS are never read or hashed.
    # This is a targeted non-recursive metadata exception for known profile files, including standard
    # profile locations below Documents. Non-system-drive profile paths are recorded as strings only.
    $paths = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(
        @('PROFILE.AllUsersAllHosts', $PROFILE.AllUsersAllHosts),
        @('PROFILE.AllUsersCurrentHost', $PROFILE.AllUsersCurrentHost),
        @('PROFILE.CurrentUserAllHosts', $PROFILE.CurrentUserAllHosts),
        @('PROFILE.CurrentUserCurrentHost', $PROFILE.CurrentUserCurrentHost)
    )) {
        if ($pair[1]) { $paths.Add([pscustomobject]@{ Source=$pair[0]; Path=[string]$pair[1] }) }
    }
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if ($docs) {
        foreach ($relative in @(
            'WindowsPowerShell\profile.ps1',
            'WindowsPowerShell\Microsoft.PowerShell_profile.ps1',
            'PowerShell\profile.ps1',
            'PowerShell\Microsoft.PowerShell_profile.ps1'
        )) { $paths.Add([pscustomobject]@{ Source='KnownCurrentUserProfilePath'; Path=(Join-Path $docs $relative) }) }
    }
    $rows = foreach ($entry in ($paths | Sort-Object Path -Unique)) {
        $expandedPath = [Environment]::ExpandEnvironmentVariables([string]$entry.Path).Trim('"')
        $onSystemDrive = ($expandedPath -match '^[A-Za-z]:\\') -and $expandedPath.StartsWith($env:SystemDrive + '\', [StringComparison]::OrdinalIgnoreCase)
        if (-not $onSystemDrive) {
            [pscustomobject]@{
                Source=$entry.Source; Path=$expandedPath; MetadataInspected=$false
                InspectionReason='Profile path is not on the system drive; path recorded only.'
                Exists=$null; Length=$null; CreationTimeUtc=$null; LastWriteTimeUtc=$null; Owner=$null; OwnerError=$null; ContentRead=$false
            }
            continue
        }
        $exists = Test-Path -LiteralPath $expandedPath -PathType Leaf
        $item = if ($exists) { Get-Item -LiteralPath $expandedPath -Force -ErrorAction SilentlyContinue } else { $null }
        $owner = $null
        $ownerError = $null
        if ($item) {
            try { $owner = (Get-Acl -LiteralPath $expandedPath -ErrorAction Stop).Owner }
            catch {
                $ownerError = $_.Exception.Message
                Add-CollectorWarning -Message ("Could not read ACL owner for PowerShell profile '$expandedPath'.") -ErrorRecord $_
            }
        }
        [pscustomobject]@{
            Source=$entry.Source; Path=$expandedPath; MetadataInspected=$true
            InspectionReason='Known PowerShell profile path on the system drive; metadata only.'
            Exists=$exists
            Length=if ($item) { $item.Length } else { $null }
            CreationTimeUtc=if ($item) { $item.CreationTimeUtc } else { $null }
            LastWriteTimeUtc=if ($item) { $item.LastWriteTimeUtc } else { $null }
            Owner=$owner
            OwnerError=$ownerError
            ContentRead=$false
        }
    }
    Export-CsvFile $rows (Join-Path $AuditRoot 'persistence\powershell_profile_metadata.csv')
}

Invoke-Collector 'System exploit and process mitigations' {
    if (Get-CommandIfAvailable 'Get-ProcessMitigation') {
        try {
            $mitigation = Get-ProcessMitigation -System
            $mitigation | Export-Clixml -Path (Join-Path $AuditRoot 'security\process_mitigation_system.clixml')
            $mitigation | Format-List * | Out-File (Join-Path $AuditRoot 'security\process_mitigation_system.txt') -Encoding utf8
        }
        catch { Add-CollectorWarning -Message 'System process-mitigation query failed.' -ErrorRecord $_ }
    }
    else { Add-CollectorWarning -Message 'Get-ProcessMitigation is not available on this system/session.' }
}

# -----------------------------------------------------------------------------
# Certificates (metadata only, no private-key export)
# -----------------------------------------------------------------------------

Invoke-Collector 'Certificate stores metadata' {
    $certRows = New-Object System.Collections.Generic.List[object]
    foreach ($store in @(
        'Cert:\LocalMachine\Root','Cert:\LocalMachine\CA','Cert:\LocalMachine\TrustedPublisher','Cert:\LocalMachine\My',
        'Cert:\CurrentUser\Root','Cert:\CurrentUser\CA','Cert:\CurrentUser\TrustedPublisher','Cert:\CurrentUser\My'
    )) {
        if (Test-Path $store) {
            foreach ($c in Get-ChildItem $store -ErrorAction SilentlyContinue) {
                $certRows.Add([pscustomobject]@{
                    Store=$store; Thumbprint=$c.Thumbprint; Subject=$c.Subject; Issuer=$c.Issuer;
                    NotBefore=$c.NotBefore; NotAfter=$c.NotAfter; FriendlyName=$c.FriendlyName;
                    HasPrivateKey=$c.HasPrivateKey; SignatureAlgorithm=$c.SignatureAlgorithm.FriendlyName;
                    PublicKeyAlgorithm=$c.PublicKey.Oid.FriendlyName; DnsNameList=(@($c.DnsNameList) -join '; ')
                })
            }
        }
    }
    Export-CsvFile $certRows (Join-Path $AuditRoot 'certificates\certificate_store_metadata.csv')
}

# -----------------------------------------------------------------------------
# File metadata/signature/hash for persistence targets within explicit boundary
# -----------------------------------------------------------------------------

Invoke-Collector 'Persistence target commands' {
    $unique = $PersistenceTargets | Where-Object { $_.CommandLine } | Sort-Object Source,CommandLine -Unique
    Export-CsvFile $unique (Join-Path $AuditRoot 'persistence\persistence_target_commands.csv')
}

Invoke-Collector 'Persistence target file metadata' {
    # Recomputed on purpose: the hash/signature pass is the slow, most failure-prone step and it must
    # not be able to take the command list collected above with it.
    $unique = $PersistenceTargets | Where-Object { $_.CommandLine } | Sort-Object Source,CommandLine -Unique
    $meta = foreach ($target in $unique) {
        Get-SafeTargetMetadata -Source $target.Source -CommandLine $target.CommandLine
    }
    Export-JsonFile $meta (Join-Path $AuditRoot 'persistence\persistence_target_file_metadata.json') 8 -AlwaysArray
}

# -----------------------------------------------------------------------------
# Event logs
# -----------------------------------------------------------------------------

Invoke-Collector 'Event log inventory' {
    $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Select-Object LogName,IsEnabled,RecordCount,LogMode,MaximumSizeInBytes,FileSize,LastWriteTime
    Export-CsvFile $logs (Join-Path $AuditRoot 'events\event_log_inventory.csv')
}

Invoke-Collector 'Security-relevant event queries' {
    $securityChangeIds = @(1102,4616,4688,4697,4698,4699,4700,4701,4702,4719,4720,4722,4724,4725,4726,4732,4733,4735,4738,4740,4756,4757,4798,4799,4946,4947,4948,4950,4951,5038,5140,5142,5143,5144)
    Export-EventQueryJsonl -Name 'Security_changes_and_persistence' -Filter @{ LogName='Security'; StartTime=$StartTime; Id=$securityChangeIds }
    Export-EventQueryJsonl -Name 'Security_authentication' -Filter @{ LogName='Security'; StartTime=$StartTime; Id=@(4624,4625,4648,4672,4768,4769,4771,4776) }

    # System: errors/warnings/critical plus service-install/start-type-change events.
    Export-EventQueryJsonl -Name 'System_warnings_errors' -Filter @{ LogName='System'; StartTime=$StartTime; Level=1,2,3 }
    Export-EventQueryJsonl -Name 'System_service_changes' -Filter @{ LogName='System'; StartTime=$StartTime; ProviderName='Service Control Manager'; Id=7040,7045 }

    Export-EventQueryJsonl -Name 'Application_warnings_errors' -Filter @{ LogName='Application'; StartTime=$StartTime; Level=1,2,3 }
    Export-EventQueryJsonl -Name 'Application_MSI_installer' -Filter @{ LogName='Application'; StartTime=$StartTime; ProviderName='MsiInstaller' }

    $channelSpecs = @(
        @{ Name='Defender_Operational'; Log='Microsoft-Windows-Windows Defender/Operational'; Id=$null },
        @{ Name='PowerShell_Operational'; Log='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104,4105,4106) },
        @{ Name='TaskScheduler_changes'; Log='Microsoft-Windows-TaskScheduler/Operational'; Id=@(106,140,141,142) },
        @{ Name='WMI_Activity'; Log='Microsoft-Windows-WMI-Activity/Operational'; Id=@(5857,5858,5859,5860,5861) },
        @{ Name='CodeIntegrity_Operational'; Log='Microsoft-Windows-CodeIntegrity/Operational'; Id=$null },
        @{ Name='AppLocker_EXE_DLL'; Log='Microsoft-Windows-AppLocker/EXE and DLL'; Id=$null },
        @{ Name='AppLocker_MSI_Script'; Log='Microsoft-Windows-AppLocker/MSI and Script'; Id=$null },
        @{ Name='WindowsUpdateClient'; Log='Microsoft-Windows-WindowsUpdateClient/Operational'; Id=$null },
        @{ Name='TerminalServices_LocalSessionManager'; Log='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=$null },
        @{ Name='RemoteDesktopServices_RdpCoreTS'; Log='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id=$null },
        @{ Name='OpenSSH_Operational'; Log='OpenSSH/Operational'; Id=$null },
        @{ Name='Sysmon_Operational'; Log='Microsoft-Windows-Sysmon/Operational'; Id=$null }
    )
    $available = @{}
    foreach ($log in Get-WinEvent -ListLog * -ErrorAction SilentlyContinue) { $available[$log.LogName] = $true }
    foreach ($spec in $channelSpecs) {
        if ($available.ContainsKey($spec.Log) -and $available[$spec.Log]) {
            $filter = @{ LogName=$spec.Log; StartTime=$StartTime }
            if ($spec.Id) { $filter.Id = $spec.Id }
            Export-EventQueryJsonl -Name $spec.Name -Filter $filter
        }
    }

    # Dynamically include available Security Center / Security Health channels.
    foreach ($logName in ($available.Keys | Where-Object { $_ -match 'SecurityCenter|SecurityHealth' } | Sort-Object -Unique)) {
        if ($available[$logName]) {
            Export-EventQueryJsonl -Name ('SecurityHealth_' + $logName) -Filter @{ LogName=$logName; StartTime=$StartTime }
        }
    }
}

# -----------------------------------------------------------------------------
# Finish / manifest / checksums / zip
# -----------------------------------------------------------------------------

Invoke-Collector 'Archive preflight' {
    $filesForArchive = @(Get-ChildItem -LiteralPath $AuditRoot -File -Recurse -ErrorAction Stop)
    $totalBytes = [int64](($filesForArchive | Measure-Object -Property Length -Sum).Sum)
    $largest = $filesForArchive | Sort-Object Length -Descending | Select-Object -First 1
    $largestBytes = if ($largest) { [int64]$largest.Length } else { [int64]0 }
    $script:ArchivePreflight = [pscustomobject]@{
        FileCount=$filesForArchive.Count
        TotalBytes=$totalBytes
        TotalGiB=[math]::Round(($totalBytes / 1GB),3)
        LargestFile=if ($largest) { $largest.FullName.Substring($AuditRoot.Length).TrimStart('\') } else { $null }
        LargestFileBytes=$largestBytes
        LargestFileGiB=if ($largest) { [math]::Round(($largest.Length / 1GB),3) } else { 0 }
        CompressArchiveSingleFileRisk=($largestBytes -ge 2GB)
    }
    $script:ArchivePreflight | Export-JsonFile -Path (Join-Path $AuditRoot 'archive_preflight.json') -Depth 4
    if ($script:ArchivePreflight.LargestFileBytes -ge 2GB) {
        Add-CollectorWarning -Message 'At least one output file is >= 2 GiB; Compress-Archive will be skipped to avoid its per-entry size limitation.'
    }
    elseif ($totalBytes -ge 1536MB) {
        Add-CollectorWarning -Message 'Audit dataset is >= 1.5 GiB; Compress-Archive may be memory-intensive. Consider -SkipZip and 7-Zip if compression fails.'
    }
}

Invoke-Collector 'Collector status and output checksums' {
    # This is a pre-checksum snapshot. collector_status_final.csv written after this collector is canonical.
    Export-CsvFile $Status (Join-Path $AuditRoot 'collector_status.csv')
    $files = Get-ChildItem -LiteralPath $AuditRoot -File -Recurse | Where-Object { $_.Name -notin @('output_sha256.csv','collector.log','collector-errors.log','collector-warnings.log','collector_status.csv','collector_status_final.csv') }
    $hashes = foreach ($f in $files) {
        try {
            [pscustomobject]@{ RelativePath=$f.FullName.Substring($AuditRoot.Length).TrimStart('\'); Length=$f.Length; SHA256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
        } catch {
            Add-CollectorWarning -Message ("SHA256 calculation failed for '$($f.FullName)'.") -ErrorRecord $_
            [pscustomobject]@{ RelativePath=$f.FullName.Substring($AuditRoot.Length).TrimStart('\'); Length=$f.Length; SHA256=$null; Error=$_.Exception.Message }
        }
    }
    Export-CsvFile $hashes (Join-Path $AuditRoot 'output_sha256.csv')
}

# Canonical QA status: includes the checksum collector itself. Use this file for audit completeness decisions.
$Status | Export-Csv -Path (Join-Path $AuditRoot 'collector_status_final.csv') -NoTypeInformation -Encoding UTF8

$zipPath = $null
if (-not $SkipZip) {
    if ($script:ArchivePreflight -and $script:ArchivePreflight.LargestFileBytes -ge 2GB) {
        'ZIP was not created because at least one audit output file is >= 2 GiB. Use the audit folder directly or archive it with a tool that supports large entries (for example 7-Zip).' |
            Out-File -FilePath (Join-Path $AuditRoot 'ZIP_NOT_CREATED_LARGE_FILE.txt') -Encoding utf8
        Write-CollectorLog 'ZIP skipped: at least one output file is >= 2 GiB.'
    }
    else {
        Write-CollectorLog 'Creating ZIP archive...'
        $zipPath = "$AuditRoot.zip"
        try {
            Compress-Archive -Path (Join-Path $AuditRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
            Write-CollectorLog "ZIP: $zipPath"
        } catch {
            Add-CollectorError -Collector 'ZIP' -ErrorRecord $_
            Write-CollectorLog "ZIP ERROR: $($_.Exception.Message)"
        }
    }
}

Write-CollectorLog 'Audit collection completed.'
Write-Host ''
Write-Host '============================================================'
Write-Host ' JOI WINDOWS SECURITY AUDIT COMPLETE'
Write-Host '============================================================'
Write-Host "Folder: $AuditRoot"
if ($zipPath -and (Test-Path $zipPath)) { Write-Host "ZIP   : $zipPath" }
Write-Host "Errors: $ErrorLog"
Write-Host "Warnings: $WarningLog"
Write-Host ''
Write-Host 'No remediation was performed. Review the dataset before sharing it.'
