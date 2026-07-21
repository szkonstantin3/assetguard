Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ReleaseRoot = "C:\AssetGuardRelease"
$ExchangeRoot = "C:\AssetGuardExchange"
$WorkRoot = "C:\AssetGuardWork"
$ResultPath = Join-Path $ExchangeRoot "sandbox-result.json"
$ResultChecksumPath = Join-Path $ExchangeRoot "sandbox-result.sha256"
$ControlPath = Join-Path $ExchangeRoot "sandbox-control.json"
$Checks = New-Object System.Collections.Generic.List[object]
$ReleaseEvidence = [ordered]@{
    version = "0.1.0"
    executable_sha256 = ""
    zip_sha256 = ""
    manifest_sha256 = ""
    checksum_sha256 = ""
}
$EnvironmentEvidence = [ordered]@{
    architecture = [string]$env:PROCESSOR_ARCHITECTURE
    python_available = $true
    source_tree_mapped = $true
    release_mapping_read_only = $false
    networking_disabled = $false
    windows_product_name = "unknown"
    windows_version = [Environment]::OSVersion.Version.ToString()
    windows_build = [Environment]::OSVersion.Version.Build.ToString()
    powershell_version = $PSVersionTable.PSVersion.ToString()
}

function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [object]$Details
    )
    $Checks.Add([ordered]@{
        name = $Name
        passed = $Passed
        details = $Details
    })
}

function Assert-Check {
    param(
        [bool]$Condition,
        [string]$Name,
        [object]$Details
    )
    Add-Check -Name $Name -Passed $Condition -Details $Details
    if (-not $Condition) {
        throw "Check failed: $Name"
    }
}

function Write-Utf8Lf {
    param([string]$Path, [string]$Text)
    $Normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    if (-not $Normalized.EndsWith("`n")) {
        $Normalized += "`n"
    }
    [IO.File]::WriteAllText($Path, $Normalized, (New-Object Text.UTF8Encoding($false)))
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Quote-Argument {
    param([string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-Executable {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )
    $Info = New-Object Diagnostics.ProcessStartInfo
    $Info.FileName = $Executable
    $Info.Arguments = (($Arguments | ForEach-Object { Quote-Argument $_ }) -join " ")
    $Info.WorkingDirectory = $WorkRoot
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    foreach ($Name in @("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV")) {
        [void]$Info.EnvironmentVariables.Remove($Name)
    }
    $Info.EnvironmentVariables["PATH"] = (
        "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    )
    $Info.EnvironmentVariables["TEMP"] = Join-Path $WorkRoot "temp"
    $Info.EnvironmentVariables["TMP"] = Join-Path $WorkRoot "temp"
    $Info.EnvironmentVariables["PYTHONUTF8"] = "1"
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $Info
    [void]$Process.Start()
    $Stdout = $Process.StandardOutput.ReadToEnd()
    $Stderr = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()
    return [ordered]@{
        exit_code = $Process.ExitCode
        stdout = $Stdout
        stderr = $Stderr
    }
}

function Test-UsableRuntime {
    param([string]$Name)
    $Command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $Command) {
        return $false
    }
    $Info = New-Object Diagnostics.ProcessStartInfo
    $Info.FileName = $Command.Source
    $Info.Arguments = "--version"
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    foreach ($Variable in @("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV")) {
        [void]$Info.EnvironmentVariables.Remove($Variable)
    }
    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $Info
    try {
        [void]$Process.Start()
        if (-not $Process.WaitForExit(5000)) {
            $Process.Kill()
            return $false
        }
        $Output = $Process.StandardOutput.ReadToEnd() + $Process.StandardError.ReadToEnd()
        if ($Process.ExitCode -ne 0) {
            return $false
        }
        return ($Output -match "(?i)(Python|pip)\s+[0-9]+\.[0-9]+")
    }
    catch {
        return $false
    }
}

function Get-AssetState {
    param([string[]]$Paths, [string]$Root)
    $State = [ordered]@{}
    foreach ($Path in ($Paths | Sort-Object)) {
        $Item = Get-Item -LiteralPath $Path
        $Relative = $Item.FullName.Substring($Root.Length).TrimStart('\').Replace('\', '/')
        $State[$Relative] = [ordered]@{
            sha256 = Get-Sha256 $Item.FullName
            length = $Item.Length
            last_write_utc_ticks = $Item.LastWriteTimeUtc.Ticks
        }
    }
    return $State
}

function Write-Tga {
    param([string]$Path)
    [byte[]]$Bytes = New-Object byte[] 30
    $Bytes[2] = 2
    $Bytes[12] = 2
    $Bytes[14] = 2
    $Bytes[16] = 24
    for ($Index = 18; $Index -lt 30; $Index += 3) {
        $Bytes[$Index] = 192
        $Bytes[$Index + 1] = 127
        $Bytes[$Index + 2] = 24
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function New-ScanCommand {
    param(
        [string]$Assets,
        [string]$Config,
        [string]$Json,
        [string]$Html,
        [string]$Cache
    )
    $Arguments = @(
        "scan", $Assets, "--config", $Config, "--output", $Json,
        "--workers", "4"
    )
    if ($Html) {
        $Arguments += @("--html-output", $Html)
    }
    if ($Cache) {
        $Arguments += @("--cache", $Cache)
    }
    return $Arguments
}

try {
    $env:PYTHONHOME = $null
    $env:PYTHONPATH = $null
    $env:VIRTUAL_ENV = $null
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    if (Test-Path -LiteralPath $WorkRoot) {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force
    }
    [void](New-Item -ItemType Directory -Path $WorkRoot)
    [void](New-Item -ItemType Directory -Path (Join-Path $WorkRoot "temp"))

    $Control = Get-Content -LiteralPath $ControlPath -Raw | ConvertFrom-Json
    $EnvironmentEvidence.networking_disabled = [bool]$Control.networking_disabled
    $PythonAvailable = $false
    foreach ($CommandName in @("python.exe", "python3.exe", "py.exe", "pip.exe")) {
        if (Test-UsableRuntime $CommandName) {
            $PythonAvailable = $true
        }
    }
    $EnvironmentEvidence.python_available = $PythonAvailable
    Assert-Check (-not $PythonAvailable) "python_unavailable" ([ordered]@{
        commands_checked = @("python", "python3", "py", "pip")
    })

    $SourceMapped = (
        (Test-Path -LiteralPath "C:\AssetGuardSource") -or
        (Test-Path -LiteralPath (Join-Path $ReleaseRoot "src")) -or
        (Test-Path -LiteralPath (Join-Path $ReleaseRoot ".git"))
    )
    $EnvironmentEvidence.source_tree_mapped = $SourceMapped
    Assert-Check (-not $SourceMapped) "source_tree_isolation" ([ordered]@{
        source_tree_mapped = $SourceMapped
    })
    Assert-Check ([bool]$Control.networking_disabled) "networking_disabled" ([ordered]@{
        configured = [bool]$Control.networking_disabled
    })

    $ExpectedNames = @(
        "AssetGuard-0.1.0-windows-x86_64.exe",
        "AssetGuard-0.1.0-windows-x86_64.manifest.json",
        "AssetGuard-0.1.0-windows-x86_64.sha256",
        "AssetGuard-0.1.0-windows-x86_64.zip"
    )
    $ActualNames = @(Get-ChildItem -LiteralPath $ReleaseRoot -File | Sort-Object Name | ForEach-Object Name)
    Assert-Check (($ActualNames -join "|") -eq ($ExpectedNames -join "|")) "release_file_set" ([ordered]@{
        file_count = $ActualNames.Count
    })

    $StandaloneExe = Join-Path $ReleaseRoot $ExpectedNames[0]
    $ManifestPath = Join-Path $ReleaseRoot $ExpectedNames[1]
    $ChecksumPath = Join-Path $ReleaseRoot $ExpectedNames[2]
    $ZipPath = Join-Path $ReleaseRoot $ExpectedNames[3]
    $ReleaseEvidence.executable_sha256 = Get-Sha256 $StandaloneExe
    $ReleaseEvidence.manifest_sha256 = Get-Sha256 $ManifestPath
    $ReleaseEvidence.checksum_sha256 = Get-Sha256 $ChecksumPath
    $ReleaseEvidence.zip_sha256 = Get-Sha256 $ZipPath
    foreach ($Name in $ExpectedNames) {
        $ExpectedHash = [string]$Control.expected_hashes.$Name
        $ActualHash = Get-Sha256 (Join-Path $ReleaseRoot $Name)
        if ($ActualHash -ne $ExpectedHash) {
            throw "Release hash mismatch: $Name"
        }
    }

    $ChecksumLines = Get-Content -LiteralPath $ChecksumPath
    $ChecksumTargets = [ordered]@{}
    foreach ($Line in $ChecksumLines) {
        if ($Line -notmatch '^([0-9a-f]{64})  ([^/\\]+)$') {
            throw "Malformed checksum line"
        }
        if ($ChecksumTargets.Contains($Matches[2])) {
            throw "Duplicate checksum target"
        }
        $ChecksumTargets[$Matches[2]] = $Matches[1]
    }
    foreach ($Name in @($ExpectedNames[0], $ExpectedNames[1], $ExpectedNames[3])) {
        if ($ChecksumTargets[$Name] -ne (Get-Sha256 (Join-Path $ReleaseRoot $Name))) {
            throw "Checksum validation failed: $Name"
        }
    }
    Assert-Check $true "release_checksums" ([ordered]@{ verified = 3 })

    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $ManifestValid = (
        $Manifest.schema_version -eq 1 -and
        $Manifest.product.name -eq "AssetGuard" -and
        $Manifest.product.version -eq "0.1.0" -and
        $Manifest.product.platform -eq "windows" -and
        $Manifest.product.architecture -eq "x86_64" -and
        $Manifest.product.format -eq "pyinstaller-onefile" -and
        $Manifest.toolchain.python -eq "3.13.9" -and
        $Manifest.toolchain.pyinstaller -eq "6.21.0" -and
        $Manifest.toolchain.pyinstaller_hooks_contrib -eq "2026.6" -and
        $Manifest.toolchain.source_date_epoch -eq 1767225600 -and
        $Manifest.source.sha256 -eq [string]$Control.expected_source_digest
    )
    Assert-Check $ManifestValid "manifest_contract" ([ordered]@{
        source_digest = [string]$Manifest.source.sha256
    })

    $ReleaseReadOnly = $false
    $Handle = $null
    try {
        $Handle = [IO.File]::Open(
            $StandaloneExe,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read
        )
        $Handle.Close()
    }
    catch [UnauthorizedAccessException] {
        $ReleaseReadOnly = $true
    }
    catch [IO.IOException] {
        $ReleaseReadOnly = $true
    }
    finally {
        if ($null -ne $Handle) {
            $Handle.Dispose()
        }
    }
    $EnvironmentEvidence.release_mapping_read_only = $ReleaseReadOnly
    Assert-Check $ReleaseReadOnly "release_mapping_read_only" ([ordered]@{
        write_access_opened = $false
    })

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $EntryNames = @($Archive.Entries | ForEach-Object FullName)
        $ExpectedEntries = @(
            "AssetGuard-0.1.0-windows-x86_64/AssetGuard.exe",
            "AssetGuard-0.1.0-windows-x86_64/README.md",
            "AssetGuard-0.1.0-windows-x86_64/examples/rules.yaml"
        )
        $SafeEntries = $true
        foreach ($Name in $EntryNames) {
            if ($Name.StartsWith("/") -or $Name.StartsWith("\") -or $Name.Contains("..") -or $Name.Contains(":")) {
                $SafeEntries = $false
            }
        }
        Assert-Check (
            $SafeEntries -and (($EntryNames -join "|") -eq ($ExpectedEntries -join "|"))
        ) "zip_contract" ([ordered]@{ entry_count = $EntryNames.Count })
    }
    finally {
        $Archive.Dispose()
    }

    $ExtractRoot = Join-Path $WorkRoot "extracted"
    [IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractRoot)
    $ExtractedBundle = Join-Path $ExtractRoot "AssetGuard-0.1.0-windows-x86_64"
    $ExtractedExe = Join-Path $ExtractedBundle "AssetGuard.exe"
    $PayloadByPath = @{}
    foreach ($Entry in $Manifest.payload) {
        $PayloadByPath[[string]$Entry.path] = $Entry
    }
    $ExtractedHash = Get-Sha256 $ExtractedExe
    $PayloadValid = (
        $ExtractedHash -eq [string]$PayloadByPath["AssetGuard.exe"].sha256 -and
        $ExtractedHash -eq $ReleaseEvidence.executable_sha256 -and
        -not (Test-Path -LiteralPath (Join-Path $ExtractedBundle "src")) -and
        @(Get-ChildItem -LiteralPath $ExtractedBundle -Recurse -Filter "*.py" -File).Count -eq 0
    )
    Assert-Check $PayloadValid "release_payload" ([ordered]@{
        executable_sha256 = $ExtractedHash
    })

    $HelpStandalone = Invoke-Executable $StandaloneExe @("--help")
    $HelpExtracted = Invoke-Executable $ExtractedExe @("--help")
    Assert-Check (
        $HelpStandalone.exit_code -eq 0 -and $HelpExtracted.exit_code -eq 0
    ) "executable_help" ([ordered]@{ standalone = 0; extracted = 0 })
    $ScanHelpStandalone = Invoke-Executable $StandaloneExe @("scan", "--help")
    $ScanHelpExtracted = Invoke-Executable $ExtractedExe @("scan", "--help")
    Assert-Check (
        $ScanHelpStandalone.exit_code -eq 0 -and $ScanHelpExtracted.exit_code -eq 0
    ) "scan_help" ([ordered]@{ standalone = 0; extracted = 0 })

    $UnicodeName = -join @(
        [char]0x0434, [char]0x0430, [char]0x043d,
        [char]0x043d, [char]0x044b, [char]0x0435
    )
    $AssetsRoot = Join-Path $WorkRoot "assets"
    $ConfigRoot = Join-Path $WorkRoot "configs"
    $OutputRoot = Join-Path $WorkRoot ($UnicodeName + "-outputs")
    foreach ($Directory in @($AssetsRoot, $ConfigRoot, $OutputRoot)) {
        [void](New-Item -ItemType Directory -Path $Directory)
    }
    $ValidAssets = Join-Path $AssetsRoot $UnicodeName
    $WarningAssets = Join-Path $AssetsRoot "warning"
    $ErrorAssets = Join-Path $AssetsRoot "error"
    $MalformedAssets = Join-Path $AssetsRoot "malformed"
    $SelfAssets = Join-Path $AssetsRoot "self-exclusion"
    foreach ($Directory in @($ValidAssets, $WarningAssets, $ErrorAssets, $MalformedAssets, $SelfAssets)) {
        [void](New-Item -ItemType Directory -Path $Directory)
    }

    $PngPath = Join-Path $ValidAssets "T_valid.png"
    [IO.File]::WriteAllBytes(
        $PngPath,
        [Convert]::FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAEklEQVR4nGNkZGJmYGBgYgADAABwAAqyASBNAAAAAElFTkSuQmCC"
        )
    )
    $TgaPath = Join-Path $ValidAssets "T_valid.tga"
    Write-Tga $TgaPath
    $ObjPath = Join-Path $ValidAssets "SM_valid.obj"
    Write-Utf8Lf $ObjPath @"
v 0 0 0
v 1 0 0
v 0 1 0
vt 0 0
vt 1 0
vt 0 1
f 1/1 2/2 3/3
"@
    [IO.File]::WriteAllBytes((Join-Path $WarningAssets "T_first.bin"), [Text.Encoding]::ASCII.GetBytes("duplicate"))
    [IO.File]::WriteAllBytes((Join-Path $WarningAssets "T_second.bin"), [Text.Encoding]::ASCII.GetBytes("duplicate"))
    [IO.File]::WriteAllBytes((Join-Path $ErrorAssets "invalid.bin"), [Text.Encoding]::ASCII.GetBytes("invalid"))
    $QuadPath = Join-Path $ErrorAssets "SM_quad.obj"
    Write-Utf8Lf $QuadPath @"
v 0 0 0
v 1 0 0
v 1 1 0
v 0 1 0
vt 0 0
vt 1 0
vt 1 1
vt 0 1
f 1/1 2/2 3/3 4/4
"@
    $MalformedPath = Join-Path $MalformedAssets "SM_bad.obj"
    Write-Utf8Lf $MalformedPath "f 1/1/1/1 2 3"
    [IO.File]::WriteAllBytes((Join-Path $SelfAssets "T_asset.bin"), [Text.Encoding]::ASCII.GetBytes("self"))

    $ValidConfig = Join-Path $ConfigRoot ($UnicodeName + ".yaml")
    Write-Utf8Lf $ValidConfig @"
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_, SM_]
textures:
  enabled: true
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: true
  severity: warning
"@
    $WarningConfig = Join-Path $ConfigRoot "warning.yaml"
    Write-Utf8Lf $WarningConfig @"
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: true
  severity: warning
"@
    $ErrorConfig = Join-Path $ConfigRoot "error.yaml"
    Write-Utf8Lf $ErrorConfig @"
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_, SM_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: false
  severity: warning
"@
    $MalformedConfig = Join-Path $ConfigRoot "malformed.yaml"
    Write-Utf8Lf $MalformedConfig @"
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [SM_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: false
  severity: warning
"@
    $SelfConfig = Join-Path $ConfigRoot "self.yaml"
    Write-Utf8Lf $SelfConfig @"
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: false
  severity: warning
"@

    $AssetPaths = @(
        $PngPath, $TgaPath, $ObjPath,
        (Join-Path $WarningAssets "T_first.bin"),
        (Join-Path $WarningAssets "T_second.bin"),
        (Join-Path $ErrorAssets "invalid.bin"),
        $QuadPath, $MalformedPath,
        (Join-Path $SelfAssets "T_asset.bin")
    )
    $BeforeState = Get-AssetState $AssetPaths $AssetsRoot

    $StandaloneJson = Join-Path $OutputRoot "standalone.json"
    $StandaloneHtml = Join-Path $OutputRoot "standalone.html"
    $StandaloneCache = Join-Path $OutputRoot "standalone.sqlite3"
    $ValidArguments = New-ScanCommand $ValidAssets $ValidConfig $StandaloneJson $StandaloneHtml $StandaloneCache
    $ValidResult = Invoke-Executable $StandaloneExe $ValidArguments
    Assert-Check ($ValidResult.exit_code -eq 0) "valid_exit" ([ordered]@{ exit_code = $ValidResult.exit_code })
    Copy-Item -LiteralPath $StandaloneJson -Destination (Join-Path $WorkRoot "standalone-first.json")
    Copy-Item -LiteralPath $StandaloneHtml -Destination (Join-Path $WorkRoot "standalone-first.html")
    $RepeatResult = Invoke-Executable $StandaloneExe $ValidArguments
    $CacheHit = $RepeatResult.stdout -match 'Cache hits: [1-9][0-9]*'
    Assert-Check ($RepeatResult.exit_code -eq 0 -and $CacheHit) "cache_hits" ([ordered]@{
        cache_hit_reported = $CacheHit
    })
    Assert-Check ($ValidArguments -contains "4") "worker_4" ([ordered]@{ workers = 4 })

    $WarningJson = Join-Path $OutputRoot "warning.json"
    $WarningResult = Invoke-Executable $StandaloneExe (New-ScanCommand $WarningAssets $WarningConfig $WarningJson "" "")
    $WarningReport = Get-Content -LiteralPath $WarningJson -Raw | ConvertFrom-Json
    $WarningCodes = @($WarningReport.issues | ForEach-Object code)
    Assert-Check (
        $WarningResult.exit_code -eq 0 -and $WarningCodes -contains "DUPLICATE_CONTENT"
    ) "warning_exit" ([ordered]@{ exit_code = $WarningResult.exit_code; issue_codes = @($WarningCodes | Sort-Object) })

    $ErrorJson = Join-Path $OutputRoot "error.json"
    $ErrorHtml = Join-Path $OutputRoot "error.html"
    $ErrorResult = Invoke-Executable $StandaloneExe (New-ScanCommand $ErrorAssets $ErrorConfig $ErrorJson $ErrorHtml "")
    $ErrorReport = Get-Content -LiteralPath $ErrorJson -Raw | ConvertFrom-Json
    $ErrorCodes = @($ErrorReport.issues | ForEach-Object code)
    Assert-Check (
        $ErrorResult.exit_code -eq 1 -and
        $ErrorCodes -contains "NAMING_INVALID_PREFIX" -and
        $ErrorCodes -contains "MESH_NON_TRIANGULATED_FACE"
    ) "error_exit" ([ordered]@{ exit_code = $ErrorResult.exit_code; issue_codes = @($ErrorCodes | Sort-Object) })

    $MalformedJson = Join-Path $OutputRoot "malformed.json"
    $MalformedHtml = Join-Path $OutputRoot "malformed.html"
    $MalformedResult = Invoke-Executable $StandaloneExe (New-ScanCommand $MalformedAssets $MalformedConfig $MalformedJson $MalformedHtml "")
    Assert-Check (
        $MalformedResult.exit_code -eq 2 -and
        $MalformedResult.stderr -notmatch "Traceback" -and
        -not (Test-Path -LiteralPath $MalformedJson) -and
        -not (Test-Path -LiteralPath $MalformedHtml)
    ) "malformed_exit" ([ordered]@{ exit_code = $MalformedResult.exit_code; traceback = $false })

    $SelfJson = Join-Path $SelfAssets "report.json"
    $SelfHtml = Join-Path $SelfAssets "report.html"
    $SelfCache = Join-Path $SelfAssets "metrics.sqlite3"
    $SelfArguments = New-ScanCommand $SelfAssets $SelfConfig $SelfJson $SelfHtml $SelfCache
    $SelfFirst = Invoke-Executable $StandaloneExe $SelfArguments
    $SelfSecond = Invoke-Executable $StandaloneExe $SelfArguments
    $SelfReport = Get-Content -LiteralPath $SelfJson -Raw | ConvertFrom-Json
    Assert-Check (
        $SelfFirst.exit_code -eq 0 -and $SelfSecond.exit_code -eq 0 -and
        $SelfReport.scan.files_scanned -eq 1
    ) "cache_output_self_exclusion" ([ordered]@{ files_scanned = [int]$SelfReport.scan.files_scanned })

    $ExtractedJson = Join-Path $OutputRoot "extracted.json"
    $ExtractedHtml = Join-Path $OutputRoot "extracted.html"
    $ExtractedCache = Join-Path $OutputRoot "extracted.sqlite3"
    $ExtractedResult = Invoke-Executable $ExtractedExe (
        New-ScanCommand $ValidAssets $ValidConfig $ExtractedJson $ExtractedHtml $ExtractedCache
    )
    $StandaloneFirstJson = Join-Path $WorkRoot "standalone-first.json"
    $StandaloneFirstHtml = Join-Path $WorkRoot "standalone-first.html"
    $JsonEqual = (Get-Sha256 $StandaloneFirstJson) -eq (Get-Sha256 $ExtractedJson)
    $HtmlEqual = (Get-Sha256 $StandaloneFirstHtml) -eq (Get-Sha256 $ExtractedHtml)
    $StandaloneReport = Get-Content -LiteralPath $StandaloneFirstJson -Raw | ConvertFrom-Json
    $ExtractedReport = Get-Content -LiteralPath $ExtractedJson -Raw | ConvertFrom-Json
    $SemanticEqual = (
        $ExtractedResult.exit_code -eq 0 -and
        $StandaloneReport.summary.errors -eq $ExtractedReport.summary.errors -and
        $StandaloneReport.summary.warnings -eq $ExtractedReport.summary.warnings -and
        $StandaloneReport.scan.files_scanned -eq $ExtractedReport.scan.files_scanned -and
        $StandaloneReport.scan.duplicate_groups -eq $ExtractedReport.scan.duplicate_groups
    )
    Assert-Check ($JsonEqual -and $SemanticEqual) "json_equivalence" ([ordered]@{
        byte_identical = $JsonEqual
        files_scanned = [int]$ExtractedReport.scan.files_scanned
    })
    Assert-Check $HtmlEqual "html_equivalence" ([ordered]@{ byte_identical = $HtmlEqual })

    $HtmlText = Get-Content -LiteralPath $ErrorHtml -Raw
    $ReportContentValid = (
        $StandaloneReport.schema_version -eq 1 -and
        $HtmlText -match "FAILED" -and
        $HtmlText -match "NAMING_INVALID_PREFIX" -and
        $HtmlText -match "MESH_NON_TRIANGULATED_FACE" -and
        (Get-Content -LiteralPath $StandaloneJson -Raw) -notmatch [regex]::Escape($WorkRoot) -and
        $HtmlText -notmatch [regex]::Escape($WorkRoot)
    )
    Assert-Check $ReportContentValid "report_content" ([ordered]@{
        schema_version = [int]$StandaloneReport.schema_version
        absolute_work_path_absent = $true
    })
    Assert-Check (Test-Path -LiteralPath $StandaloneHtml) "html_output" ([ordered]@{
        generated = $true
    })
    Assert-Check (
        (Test-Path -LiteralPath $ValidAssets) -and
        (Test-Path -LiteralPath $ValidConfig) -and
        (Test-Path -LiteralPath $StandaloneJson) -and
        (Test-Path -LiteralPath $StandaloneHtml) -and
        (Test-Path -LiteralPath $StandaloneCache)
    ) "unicode_paths" ([ordered]@{ unicode_code_points = 6 })

    $AfterState = Get-AssetState $AssetPaths $AssetsRoot
    $BeforeJson = $BeforeState | ConvertTo-Json -Depth 8 -Compress
    $AfterJson = $AfterState | ConvertTo-Json -Depth 8 -Compress
    Assert-Check ($BeforeJson -ceq $AfterJson) "asset_non_destructive" ([ordered]@{
        assets_compared = $AssetPaths.Count
    })

    $VersionInfo = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $EnvironmentEvidence.windows_product_name = [string]$VersionInfo.ProductName
    $EnvironmentEvidence.windows_version = [string]$VersionInfo.DisplayVersion
    if (-not $EnvironmentEvidence.windows_version) {
        $EnvironmentEvidence.windows_version = [Environment]::OSVersion.Version.ToString()
    }
    $EnvironmentEvidence.windows_build = [string]$VersionInfo.CurrentBuild
    Assert-Check $true "environment_isolation" ([ordered]@{
        python_available = $EnvironmentEvidence.python_available
        source_tree_mapped = $EnvironmentEvidence.source_tree_mapped
        release_mapping_read_only = $EnvironmentEvidence.release_mapping_read_only
        networking_disabled = $EnvironmentEvidence.networking_disabled
    })
}
catch {
    Add-Check -Name "verification_error" -Passed $false -Details ([ordered]@{
        message = $_.Exception.Message
    })
}
finally {
    try {
        $SortedChecks = @($Checks | Sort-Object { $_.name })
        $PassedCount = @($SortedChecks | Where-Object { $_.passed }).Count
        $FailedCount = @($SortedChecks | Where-Object { -not $_.passed }).Count
        $Result = [ordered]@{
            schema_version = 1
            environment = $EnvironmentEvidence
            release = $ReleaseEvidence
            checks = $SortedChecks
            summary = [ordered]@{
                passed = ($FailedCount -eq 0)
                checks_passed = $PassedCount
                checks_failed = $FailedCount
            }
        }
        $Json = $Result | ConvertTo-Json -Depth 12
        Write-Utf8Lf $ResultPath $Json
        $ResultHash = Get-Sha256 $ResultPath
        Write-Utf8Lf $ResultChecksumPath "$ResultHash  sandbox-result.json"
    }
    catch {
        try {
            Write-Utf8Lf $ResultPath "{`"schema_version`":1,`"summary`":{`"passed`":false,`"checks_passed`":0,`"checks_failed`":1}}"
            $FallbackHash = Get-Sha256 $ResultPath
            Write-Utf8Lf $ResultChecksumPath "$FallbackHash  sandbox-result.json"
        }
        catch {
        }
    }
    Start-Sleep -Seconds 2
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" -ArgumentList @("/s", "/t", "0") -WindowStyle Hidden
    }
    catch {
    }
}
