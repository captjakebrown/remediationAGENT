<#
RSD CleanAgent - Intune Proactive Remediation Remediation
PowerShell 5.1 compatible
Version: 2026.03.05.4

Installs/updates local cleanAGENT + targets.json and registers a scheduled task.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'

param(
  [string]$RunSource
)

$AgentRoot = 'C:\ProgramData\RSD\Agent'
$AgentScript = Join-Path $AgentRoot 'cleanAGENT.ps1'
$TargetsPath = Join-Path $AgentRoot 'targets.json'
$VersionFile = Join-Path $AgentRoot 'version.txt'
$StateFile   = Join-Path $AgentRoot 'state.json'
$LogDir      = Join-Path $AgentRoot 'Logs'

$ThisVersion = '2026.03.05.4'

$AgentPayload = @'
<#
RSD CleanAgent (local) - PowerShell 5.1
Version: 2026.03.05.4

Behavior:
- Batch inventory UWP/ARP once per run.
- Removes UWP packages found.
- Removes ARP apps ONLY via QuietUninstallString (no invented quiet args).
- Builds a residual set and does a single bounded filesystem index pass for portable/installer artifacts.
- Backoff schedule is enforced via state.json:
    Phase 0: every hour for 24h
    Phase 1: every 2h for next 24h
    Phase 2: every 4h for next 24h
    Phase 3: once daily at 09:00 local IF clean; if forbidden apps detected, reset to Phase 0.
- Writes debug log to C:\ProgramData\RSD\Agent\Logs
- Writes receipt RSD ATTN.log on user desktop (OneDrive Desktop preferred), ACL-hardened and readable by Users.

Runs as SYSTEM via Task Scheduler.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'

$AgentRoot = 'C:\ProgramData\RSD\Agent'
$TargetsPath = Join-Path $AgentRoot 'targets.json'
$StateFile   = Join-Path $AgentRoot 'state.json'
$LogDir      = Join-Path $AgentRoot 'Logs'
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

$logPath = Join-Path $LogDir ("cleanAGENT_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Log([string]$m, [string]$lvl='INFO') {
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  try { Add-Content -Path $logPath -Value ("{0} [{1}] {2}" -f $ts, $lvl, $m) -Encoding UTF8 } catch {}
}

function Read-JsonFile([string]$path, $fallback) {
  if (-not (Test-Path $path)) { return $fallback }
  try { return (Get-Content -Raw -Path $path -Encoding UTF8 | ConvertFrom-Json) } catch { return $fallback }
}

function Write-JsonFile([string]$path, $obj) {
  try { ($obj | ConvertTo-Json -Depth 8) | Set-Content -Path $path -Encoding UTF8 } catch {}
}

function Get-ActiveUserSid([string]$user) {
  if (-not $user) { return $null }
  try {
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
      if (-not $p.LocalPath) { continue }
      if ($p.LocalPath -ieq ("C:\Users\{0}" -f $user)) { return $p.SID }
    }
  } catch {}
  return $null
}

function Invoke-RegLoadWithTimeout([string]$hiveName, [string]$ntUserDat, [int]$timeoutMs) {
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'reg.exe'
    $psi.Arguments = "load HKU\$hiveName `"$ntUserDat`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p) { return $false }
    if (-not $p.WaitForExit($timeoutMs)) {
      try { $p.Kill() } catch {}
      Remediate-Log -m ("reg load timeout for hive " + $hiveName) -lvl 'WARN'
      return $false
    }
    return ($p.ExitCode -eq 0)
  } catch { return $false }
}

function Set-OneDriveDeletePromptPolicyForUser([string]$user) {
  if (-not $user) { return }

  # First preference: active loaded user hive by SID (fast, no hive mount/unmount risk).
  $sid = Get-ActiveUserSid $user
  if ($sid -and (Test-Path ("Registry::HKEY_USERS\{0}" -f $sid))) {
    try {
      $loadedPath = "Registry::HKEY_USERS\{0}\Software\Microsoft\OneDrive" -f $sid
      if (-not (Test-Path $loadedPath)) { New-Item -Path $loadedPath -Force | Out-Null }
      New-ItemProperty -Path $loadedPath -Name 'DisableFirstDeleteDialog' -Value 1 -PropertyType DWord -Force | Out-Null
      Log ("Applied HKCU OneDrive policy to loaded hive SID=" + $sid)
      return
    } catch {}
  }

  # Fallback: mount NTUSER.DAT with timeout so we cannot block the clean pass.
  $ntUser = "C:\Users\{0}\NTUSER.DAT" -f $user
  if (-not (Test-Path $ntUser)) { return }

  $mounted = $false
  try {
    if (-not (Test-Path 'Registry::HKEY_USERS\RSDTEMP')) {
      $mounted = Invoke-RegLoadWithTimeout 'RSDTEMP' $ntUser 5000
    }
    if (Test-Path 'Registry::HKEY_USERS\RSDTEMP') {
      $userPath = 'Registry::HKEY_USERS\RSDTEMP\Software\Microsoft\OneDrive'
      if (-not (Test-Path $userPath)) { New-Item -Path $userPath -Force | Out-Null }
      New-ItemProperty -Path $userPath -Name 'DisableFirstDeleteDialog' -Value 1 -PropertyType DWord -Force | Out-Null
      Log ("Applied HKCU OneDrive policy using mounted temp hive for user=" + $user)
    }
  } catch {}
  finally {
    if ($mounted) { try { reg.exe unload "HKU\RSDTEMP" | Out-Null } catch {} }
  }
}


function Disable-OneDriveDeletePrompt([string]$user) {
  try {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    New-ItemProperty -Path $policyPath -Name 'DisableFirstDeleteDialog' -Value 1 -PropertyType DWord -Force | Out-Null
  } catch {}
  Set-OneDriveDeletePromptPolicyForUser $user
}

function Is-DueToRun($state) {
  $now = Get-Date
  $phase = [int]($state.phase)
  if ($phase -eq 0) { return $true }
  if ($phase -eq 1) { return (($now.Hour % 2) -eq 0) }
  if ($phase -eq 2) { return (($now.Hour % 4) -eq 0) }
  return ($now.Hour -eq 9)
}

function Advance-PhaseIfTime($state) {
  $now = Get-Date
  $phase = [int]($state.phase)
  $phaseStart = Get-Date ($state.phaseStart)
  if (-not $phaseStart) { $state.phase = 0; $state.phaseStart = $now.ToString("o"); return $state }
  $elapsedHours = (New-TimeSpan -Start $phaseStart -End $now).TotalHours
  if ($phase -eq 0 -and $elapsedHours -ge 24) { $state.phase = 1; $state.phaseStart = $now.ToString("o") }
  elseif ($phase -eq 1 -and $elapsedHours -ge 24) { $state.phase = 2; $state.phaseStart = $now.ToString("o") }
  elseif ($phase -eq 2 -and $elapsedHours -ge 24) { $state.phase = 3; $state.phaseStart = $now.ToString("o") }
  return $state
}

function Reset-Phase($state) { $state.phase = 0; $state.phaseStart = (Get-Date).ToString("o"); return $state }

function Get-ActiveUser() {
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.UserName) { return $cs.UserName.Split('\')[-1] }
  } catch {}
  return $null
}

function Get-DesktopPathForUser([string]$user) {
  if (-not $user) { return $null }
  $one = "C:\Users\{0}\OneDrive - Riverview School District\Desktop" -f $user
  $loc = "C:\Users\{0}\Desktop" -f $user
  if (Test-Path $one) { return $one }
  if (Test-Path $loc) { return $loc }
  return $null
}

function Ensure-ReceiptAcl([string]$p) {
  try { (Get-Item $p -ErrorAction SilentlyContinue).Attributes = 'ReadOnly' } catch {}
  try {
    icacls $p /inheritance:r | Out-Null
    icacls $p /remove:d "Users" "Authenticated Users" | Out-Null
    icacls $p /grant:r "Users:(R)" "Authenticated Users:(R)" "Administrators:(F)" "SYSTEM:(F)" | Out-Null
  } catch {}
}

function Update-Receipt([string[]]$incidentApps, [bool]$isNewIncident) {
  $incidentApps = @($incidentApps | Where-Object { $_ } | Sort-Object -Unique)
  if ($incidentApps.Length -eq 0) { return }

  $user = Get-ActiveUser
  $desk = Get-DesktopPathForUser $user
  if (-not $desk) { return }

  $receipt = Join-Path $desk 'RSD ATTN.log'
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $list = ($incidentApps -join ', ')
  $line = "$ts - Removed: $list"

  if (-not (Test-Path $receipt)) {
    try {
      Set-Content -Path $receipt -Value "Forbidden software has been removed from your computer." -Encoding UTF8
      Add-Content -Path $receipt -Value ("Removed: " + $list) -Encoding UTF8
      Add-Content -Path $receipt -Value "If additional forbidden software is discovered in the future, school administration will determine appropriate discipline." -Encoding UTF8
      Add-Content -Path $receipt -Value "" -Encoding UTF8
      Add-Content -Path $receipt -Value $line -Encoding UTF8
      Ensure-ReceiptAcl $receipt
      return
    } catch {}
  }

  try {
    if ($isNewIncident) {
      Add-Content -Path $receipt -Value $line -Encoding UTF8
    } else {
      $lines = @()
      try { $lines = @(Get-Content -Path $receipt -Encoding UTF8) } catch {}
      $updated = $false
      for ($i = $lines.Length - 1; $i -ge 0; $i--) {
        if ($lines[$i] -match '^\d{4}-\d{2}-\d{2} .* - Removed: ') {
          $lines[$i] = $line
          $updated = $true
          break
        }
      }
      if ($updated) {
        Set-Content -Path $receipt -Value $lines -Encoding UTF8
      } else {
        Add-Content -Path $receipt -Value $line -Encoding UTF8
      }
    }
  } catch {}

  Ensure-ReceiptAcl $receipt
}

function Get-Targets() {
  $t = Read-JsonFile $TargetsPath @()
  if ($t -isnot [System.Array]) { return @() + $t }
  return $t
}

function Snapshot-Uwp() {
  $set = @{}
  try { Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { $set[$_.PackageFamilyName.ToLowerInvariant()] = $_ } } catch {}
  return $set
}

function Snapshot-Arp() {
  $list = @()
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach ($p in $paths) {
    try { Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object { if ($_.DisplayName) { $list += $_ } } } catch {}
  }
  return $list
}

function Match-Arp($arpList, $pattern) {
  if (-not $pattern) { return @() }
  return @($arpList | Where-Object { $_.DisplayName -like $pattern })
}

function Get-TargetValue($target, [string]$name) {
  if (-not $target -or -not $name) { return $null }
  try {
    $prop = $target.PSObject.Properties[$name]
    if ($prop) { return $prop.Value }
  } catch {}
  return $null
}

function Remove-UwpFamily($family) {
  if (-not $family) { return $false }
  $removed = $false
  try {
    $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.PackageFamilyName -eq $family }
    foreach ($p in $pkgs) {
      Log ("Removing UWP: " + $p.PackageFullName)
      try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue } catch {}
      $removed = $true
    }
  } catch {}
  try {
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
      Where-Object { $_.PackageFamilyName -eq $family } |
      ForEach-Object { try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue } catch {} }
  } catch {}
  return $removed
}

function Invoke-QuietUninstall($q) {
  if (-not $q) { return $false }
  try { Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$q`"" -Wait -WindowStyle Hidden; return $true } catch { return $false }
}

function Get-ProfileRootForUser([string]$user) {
  if (-not $user) { return $null }
  $p = "C:\Users\{0}" -f $user
  if (Test-Path $p) { return $p }
  return $null
}

function Get-PresenceZonesForUser([string]$user) {
  $root = Get-ProfileRootForUser $user
  if (-not $root) { return @() }
  $zones = @()
  $od = Join-Path $root 'OneDrive - Riverview School District'
  $deskOD = Join-Path $od 'Desktop'
  $docOD  = Join-Path $od 'Documents'
  $deskL  = Join-Path $root 'Desktop'
  $docL   = Join-Path $root 'Documents'
  $dl     = Join-Path $root 'Downloads'
  $pic    = Join-Path $root 'Pictures'
  if (Test-Path $deskOD) { $zones += $deskOD } elseif (Test-Path $deskL) { $zones += $deskL }
  if (Test-Path $docOD)  { $zones += $docOD }  elseif (Test-Path $docL)  { $zones += $docL }
  if (Test-Path $dl) { $zones += $dl }
  if (Test-Path $pic){ $zones += $pic }
  return ($zones | Select-Object -Unique)
}

function Get-ShallowCDrives() {
  $skip = @(
    'windows','program files','program files (x86)','programdata','users','recovery',
    'classpolicy','documents and settings','hp','inetpub','onedrivetemp','swsetup','system.sav',
    'perflogs','system volume information','$recycle.bin','msocache'
  )
  $out = @()
  try {
    Get-ChildItem -Path 'C:\' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $n = $_.Name.ToLowerInvariant()
      if ($skip -notcontains $n) { $out += $_.FullName }
    }
  } catch {}
  return $out
}

function Get-SignatureValue($signature, [string]$name) {
  if (-not $signature -or -not $name) { return $null }
  try {
    $prop = $signature.PSObject.Properties[$name]
    if ($prop) { return $prop.Value }
  } catch {}
  return $null
}

function Build-Stems($t) {
  $stems = New-Object System.Collections.Generic.List[string]
  foreach ($sig in @($t.PortableExeSignatures, $t.InstallerSignatures)) {
    if (-not $sig) { continue }
    $pn = Get-SignatureValue $sig 'ProductName'
    $of = Get-SignatureValue $sig 'OriginalFilename'
    $ifn = Get-SignatureValue $sig 'InstallerFileName'
    $ipath = Get-SignatureValue $sig 'InstallerPath'

    foreach ($candidate in @($pn, $of, $ifn, $ipath)) {
      if (-not $candidate) { continue }
      try {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFileName([string]$candidate))
        if ($base) {
          $stems.Add($base)
          $stems.Add(($base -replace '[\s\.\-_]',''))
        }
      } catch {}
      if ($candidate -is [string] -and $candidate.Length -ge 4) {
        $stems.Add($candidate)
        $stems.Add(($candidate -replace '[\s\.\-_\\:]',''))
      }
    }
  }
  return @($stems | Where-Object { $_ -and $_.Length -ge 4 } | Select-Object -Unique | Select-Object -First 10)
}


function Get-InstallerPathCandidates($t) {
  $paths = New-Object System.Collections.Generic.List[string]
  foreach ($sig in @($t.PortableExeSignatures, $t.InstallerSignatures)) {
    if (-not $sig) { continue }
    $p = Get-SignatureValue $sig "InstallerPath"
    if (-not $p) { continue }
    if ($p -is [System.Array]) {
      foreach ($one in $p) { if ($one) { $paths.Add([string]$one) } }
    } else {
      $paths.Add([string]$p)
    }
  }
  return @($paths | Where-Object { $_ } | Select-Object -Unique)
}


function Get-InstallerPathCandidates($t) {
  $paths = New-Object System.Collections.Generic.List[string]
  foreach ($sig in @($t.PortableExeSignatures, $t.InstallerSignatures)) {
    if (-not $sig) { continue }
    $p = Get-SignatureValue $sig "InstallerPath"
    if (-not $p) { continue }
    if ($p -is [System.Array]) {
      foreach ($one in $p) { if ($one) { $paths.Add([string]$one) } }
    } else {
      $paths.Add([string]$p)
    }
  }
  return @($paths | Where-Object { $_ } | Select-Object -Unique)
}

function Index-Files($roots, $maxDepth) {
  $idx = @{}
  $exts = @('exe','msi','zip','7z','rar','msix','appx','appxbundle','msixbundle')
  foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@($r, 0))
    while ($queue.Count -gt 0) {
      $it = $queue.Dequeue()
      $p = $it[0]; $d = [int]$it[1]
      foreach ($e in $exts) {
        try {
          Get-ChildItem -LiteralPath $p -File -Force -Filter "*.$e" -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name.ToLowerInvariant()
            if (-not $idx.ContainsKey($name)) { $idx[$name] = @() }
            $idx[$name] += $_.FullName
          }
        } catch {}
      }
      if ($d -ge $maxDepth) { continue }
      try {
        Get-ChildItem -LiteralPath $p -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
          if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return }
          $queue.Enqueue(@($_.FullName, $d + 1))
        }
      } catch {}
    }
  }
  return $idx
}

function Find-MatchingFiles($fileIndex, [string[]]$stems) {
  $hits = @()
  $stems = @($stems)
  if ($stems.Length -eq 0) { return $hits }
  foreach ($k in $fileIndex.Keys) {
    foreach ($s in $stems) {
      $ss = $s.ToLowerInvariant()
      if ($ss.Length -le 6) { if ($k -like ($ss + '*')) { $hits += $fileIndex[$k] } }
      else { if ($k -like ('*' + $ss + '*')) { $hits += $fileIndex[$k] } }
    }
  }
  return ($hits | Select-Object -Unique)
}

function Remove-Paths([string[]]$paths) {
  foreach ($p in $paths) {
    try { if (Test-Path $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
  }
}

function Remove-QuickLaunchMatches([string]$user, [string[]]$stems) {
  $stems = @($stems)
  if (-not $user -or $stems.Length -eq 0) { return $false }
  $root = "C:\Users\{0}\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -f $user
  if (-not (Test-Path $root)) { return $false }

  $removed = $false
  try {
    Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $n = $_.Name.ToLowerInvariant()
      foreach ($s in $stems) {
        $needle = $s.ToLowerInvariant()
        if ($needle.Length -lt 4) { continue }
        if ($n -like ('*' + $needle + '*')) {
          try {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            $removed = $true
            Log ("Removed Quick Launch shortcut: " + $_.FullName)
          } catch {}
          break
        }
      }
    }
  } catch {}

  return $removed
}

# MAIN
$scriptExitCode = 0
$mutexName = 'Global\\RSDCleanAgentMutex'
$mutex = $null
$mutexOwned = $false

try {
  try {
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $mutexOwned = $mutex.WaitOne(0, $false)
    if (-not $mutexOwned) { return }
  } catch {}

  $state = Read-JsonFile $StateFile @{ phase=0; phaseStart=(Get-Date).ToString('o'); lastDetect=(Get-Date).ToString('o'); lastRun=(Get-Date).ToString('o'); lastFound=@(); incidentOpen=$false; incidentApps=@(); lastExitCode=0; lastSweepSucceeded=$true }
  $state = Advance-PhaseIfTime $state

  if (-not (Is-DueToRun $state)) {
    $state.lastRun = (Get-Date).ToString('o')
    Write-JsonFile $StateFile $state
    return
  }

  $activeUser = Get-ActiveUser
  Log ("Active user: " + $activeUser)
  Disable-OneDriveDeletePrompt $activeUser
  Log "OneDrive delete prompt policy stage complete"

  $targets = @(Get-Targets)
  Log ("Target count loaded: " + $targets.Length)
  if ($targets.Length -eq 0) {
    Log "targets.json missing/empty." "WARN"
    $state.lastRun = (Get-Date).ToString('o')
    Write-JsonFile $StateFile $state
    return
  }

  Log "Starting UWP snapshot (all users)"
  $uwpStart = Get-Date
  $uwpSet = Snapshot-Uwp
  Log (("Completed UWP snapshot. Package families indexed={0} elapsedSec={1}" -f $uwpSet.Count, [int](New-TimeSpan -Start $uwpStart -End (Get-Date)).TotalSeconds))

  Log "Starting ARP snapshot"
  $arpStart = Get-Date
  $arpList = @(Snapshot-Arp)
  Log (("Completed ARP snapshot. Entries indexed={0} elapsedSec={1}" -f @($arpList).Count, [int](New-TimeSpan -Start $arpStart -End (Get-Date)).TotalSeconds))

  $foundThisRun = @()
  $removedThisRun = @()

  # Pass 1: remove UWP + quiet ARP
  foreach ($t in $targets) {
    $tName = Get-TargetValue $t 'Name'
    if (-not $tName) { $tName = '<unnamed-target>' }
    $tUwpFamily = Get-TargetValue $t 'UWPFamily'
    $tArpName = Get-TargetValue $t 'ARPName'

    $present = $false
    if ($tUwpFamily -and $uwpSet.ContainsKey($tUwpFamily.ToLowerInvariant())) { $present = $true; $foundThisRun += $tName }
    if (-not $present -and $tArpName) {
      $arpMatches = @(Match-Arp $arpList $tArpName)
      if ($arpMatches.Length -gt 0) { $present = $true; $foundThisRun += $tName }
    }
    if (-not $present) { continue }

    $did = $false
    if ($tUwpFamily) { $did = (Remove-UwpFamily $tUwpFamily) -or $did }

    if ($tArpName) {
      $matches = Match-Arp $arpList $tArpName
      foreach ($e in $matches) {
        if ($e.QuietUninstallString) {
          Log ("Quiet uninstall ARP: " + $e.DisplayName)
          $ok = Invoke-QuietUninstall $e.QuietUninstallString
          if ($ok) { $did = $true } else { Log -m ("Quiet uninstall failed: " + $e.DisplayName) -lvl "WARN" }
        } else {
          Log -m ("No QuietUninstallString for: " + $e.DisplayName) -lvl "WARN"
        }
      }

      if ($did) { $removedThisRun += $tName }
    }

    if ($did) { $removedThisRun += $tName }
  }
  Log "Completed Pass 1"

  # Refresh & residual filesystem pass (portable/installer artifacts)
  Log "Starting post-removal UWP snapshot"
  $uwp2Start = Get-Date
  $uwpSet2 = Snapshot-Uwp
  Log (("Completed post-removal UWP snapshot. Package families indexed={0} elapsedSec={1}" -f $uwpSet2.Count, [int](New-TimeSpan -Start $uwp2Start -End (Get-Date)).TotalSeconds))

  Log "Starting post-removal ARP snapshot"
  $arp2Start = Get-Date
  $arpList2 = @(Snapshot-Arp)
  Log (("Completed post-removal ARP snapshot. Entries indexed={0} elapsedSec={1}" -f @($arpList2).Count, [int](New-TimeSpan -Start $arp2Start -End (Get-Date)).TotalSeconds))

  $residual = @()
  foreach ($t in $targets) {
    $tUwpFamily = Get-TargetValue $t 'UWPFamily'
    $tArpName = Get-TargetValue $t 'ARPName'
    $tPortable = Get-TargetValue $t 'PortableExeSignatures'
    $tInstaller = Get-TargetValue $t 'InstallerSignatures'

    $still = $false
    if ($tUwpFamily -and $uwpSet2.ContainsKey($tUwpFamily.ToLowerInvariant())) { $still = $true }
    if (-not $still -and $tArpName) {
      $arpMatches2 = @(Match-Arp $arpList2 $tArpName)
      if ($arpMatches2.Length -gt 0) { $still = $true }
    }
    if ($still -or $tPortable -or $tInstaller) { $residual += $t }
  }

  $roots = @()
  if ($activeUser) { $roots += (Get-PresenceZonesForUser $activeUser) }
  $roots += (Get-ShallowCDrives)
  $roots = $roots | Where-Object { $_ } | Select-Object -Unique

  Log ("Index roots: " + ($roots -join '; '))
  Log "Starting filesystem index pass"
  $idxStart = Get-Date

  $fileIndex = Index-Files $roots 2
  Log (("Completed filesystem index pass. Indexed file keys={0} elapsedSec={1}" -f $fileIndex.Keys.Count, [int](New-TimeSpan -Start $idxStart -End (Get-Date)).TotalSeconds))

  $portableVerifiedGone = $true
  $foundAnyArtifacts = $false

  foreach ($t in $residual) {
    $tName = Get-TargetValue $t 'Name'
    if (-not $tName) { $tName = '<unnamed-target>' }

    $directInstallerPaths = @(Get-InstallerPathCandidates $t)
    if ($directInstallerPaths.Length -gt 0) {
      $existingDirect = @($directInstallerPaths | Where-Object { Test-Path $_ })
      if ($existingDirect.Length -gt 0) {
        Log ("Removing direct installer paths for " + $tName + " hits=" + $existingDirect.Length)
        Remove-Paths $existingDirect
        $removedThisRun += $tName
        $foundAnyArtifacts = $true
        foreach ($p in $existingDirect) { if (Test-Path $p) { $portableVerifiedGone = $false } }
      }
    }

    $stems = @(Build-Stems $t)
    if ($stems.Length -eq 0) { continue }
    if ($activeUser) {
      $shortcutRemoved = Remove-QuickLaunchMatches $activeUser $stems
      if ($shortcutRemoved) {
        $removedThisRun += $tName
      }
    }
    $hits = @(Find-MatchingFiles $fileIndex $stems)
    if ($hits.Length -gt 0) {
      $foundAnyArtifacts = $true
      Log ("Removing artifacts for " + $tName + " hits=" + $hits.Count)
      Remove-Paths $hits
      $removedThisRun += $tName
      foreach ($p in $hits) { if (Test-Path $p) { $portableVerifiedGone = $false } }
    }
  }

  $foundAny = @($foundThisRun | Select-Object -Unique)
  $runFoundForbidden = ($foundAny.Length -gt 0 -or $foundAnyArtifacts)

  if ($runFoundForbidden) {
    $state = Reset-Phase $state
    $state.lastDetect = (Get-Date).ToString('o')
    $state.lastFound = $foundAny

    $incidentAppsThisRun = @($foundThisRun + $removedThisRun | Select-Object -Unique)
    $isNewIncident = (-not [bool]$state.incidentOpen)
    if ($isNewIncident) {
      $state.incidentApps = @($incidentAppsThisRun)
    } else {
      $state.incidentApps = @($state.incidentApps + $incidentAppsThisRun | Select-Object -Unique)
    }
    $state.incidentOpen = $true

    Update-Receipt $state.incidentApps $isNewIncident
  } else {
    $state = Advance-PhaseIfTime $state
    $state.lastFound = @()
  }

  if (-not $portableVerifiedGone) {
    Log -m "Portable verification failed (some artifacts remain)." -lvl "WARN"
    $scriptExitCode = 1
  }

  if ($scriptExitCode -eq 0 -and -not $runFoundForbidden) {
    $state.incidentOpen = $false
    $state.incidentApps = @()
  }

  $state.lastRun = (Get-Date).ToString('o')
  $state.lastExitCode = $scriptExitCode
  $state.lastSweepSucceeded = ($scriptExitCode -eq 0)
  Write-JsonFile $StateFile $state
}
catch {
  $scriptExitCode = 1
  $errText = $_ | Out-String
  Log -m ("Unhandled exception in cleanAGENT main: " + $errText.Trim()) -lvl "ERROR"
}
finally {
  if ($mutexOwned -and $mutex) {
    try { $mutex.ReleaseMutex() | Out-Null } catch {}
  }
  if ($mutex) {
    try { $mutex.Dispose() } catch {}
  }
}

exit $scriptExitCode

'@

# Replace this payload with your current targets.json (or let the agent use an external managed file)
$TargetsPayload = @'
[
    {
        "Name": "AJClassic",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "AJ Classic",
            "CompanyName": "WildWorks",
            "OriginalFilename": "AJClassicInstaller.exe",
            "CertThumbprint": "C44A7BB7A6B412DCEE5C225DCC0B7239964150FC",
            "SignerSimpleName": "WildWorks",
            "FileDescriptions": "AJ Classic for Desktop AJClassic Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": null
    },
    {
        "Name": "Alderon Games",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Alderon Games Launcher",
            "CompanyName": "Alderon Games Pty Ltd",
            "OriginalFilename": "Alderon Games Launcher Setup *.exe",
            "CertThumbprint": "84394F0EA137ABD0FCD8C9DD6A84E784876E787C",
            "SignerSimpleName": "Alderon Games Canada Corporation",
            "FileDescriptions": "Alderon Games Launcher Alderon Games Launcher Setup *.exe"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "alderon-games-launcher",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "alderon-games-launcher"
        },
        "PathAnchors": [
            "alderon-games-launcher",
            "alderon-games-launcher-updater"
        ]
    },
    {
        "Name": "Angry Birds 2",
        "UWPFamily": "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Store Installer",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "Angry Birds 2 Installer.exe",
            "CertThumbprint": "A85A56572A16C89BE458C5B22D11877071586023",
            "SignerSimpleName": "Microsoft Corporation",
            "FileDescriptions": "Store Installer Angry Birds 2 Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2"
    },
    {
        "Name": "Animal Jam",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "AnimalJamInstaller.exe",
            "CertThumbprint": "52AD99650911E7047D8EC3191A47BFD883E610CD",
            "SignerSimpleName": "WildWorks",
            "InstallerFileName": "AnimalJamInstaller.exe",
            "InstallerPath": "C:\\Users\\callahans\\Downloads\\AnimalJamInstaller.exe",
            "FileDescriptions": "Animal Jam Installer.exe"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "Animal Jam",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Animal Jam"
        },
        "PathAnchors": [
            "Animal Jam",
            "WildWorks"
        ]
    },
    {
        "Name": "Autoclicker",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "OP Auto Clicker",
            "CompanyName": null,
            "OriginalFilename": "AutoClicker-*.exe",
            "CertThumbprint": "562E77844B63A3EAB2B2B6D77A76DCFA52DD9846",
            "SignerSimpleName": "AMSTION LIMITED",
            "FileDescriptions": "OP Auto Clicker Auto Clicker-*.exe"
        },
        "PortableExeSignatures": {
            "ProductName": "OP Auto Clicker",
            "CompanyName": null,
            "OriginalFilename": null,
            "CertThumbprint": "562E77844B63A3EAB2B2B6D77A76DCFA52DD9846",
            "SignerSimpleName": "AMSTION LIMITED",
            "FileDescriptions": "OP Auto Clicker"
        },
        "PathAnchors": null
    },
    {
        "Name": "AVG Secure Browser",
        "UWPFamily": null,
        "ARPName": "AVG Secure Browser*",
        "Publisher": "Gen Digital Inc.",
        "InstallerSignatures": {
            "ProductName": "AVG Secure Browser Setup",
            "CompanyName": "Gen Digital Inc.",
            "OriginalFilename": "avg_secure_browser_setup.exe",
            "CertThumbprint": "79A1F7262575EC7D1304F9CDAC161C91DA814B87",
            "SignerSimpleName": "AVG Technologies USA",
            "FileDescriptions": "AVG Secure Browser Setupavg_secure_browser_setup.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "AVG Secure Browser",
            "Gen Digital Inc."
        ]
    },
    {
        "Name": "BlueStacks",
        "UWPFamily": null,
        "ARPName": "BlueStacks*",
        "Publisher": "now.gg, Inc.",
        "InstallerSignatures": {
            "ProductName": "BlueStacks 5",
            "CompanyName": "now.gg, Inc.",
            "OriginalFilename": "BlueStacksInstaller_*_native_b2a81b8bb*e90d9fc*_MzsxNSwwOzUsMTsxNSw0OzE1LDU7MTU=.exe",
            "CertThumbprint": "19FE0C50C1E150B1C044D1AC3AC2E8E886E00AA1",
            "SignerSimpleName": "Now.gg",
            "FileDescriptions": "Blue Stacks Setup Blue Stacks Installer_*_native_b2a81b8bb*e90d9fc*_Mzsx NSww Oz Us MTsx NSw0Oz E1LDU7MTU=.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "BlueStacks Store",
            "BlueStacks X",
            "BlueStacks_nxt",
            "bluestacks-services",
            "now.gg, Inc."
        ]
    },
    {
        "Name": "Brave",
        "UWPFamily": null,
        "ARPName": "Brave*",
        "Publisher": "Brave Software Inc",
        "InstallerSignatures": {
            "ProductName": "BraveSoftware Update",
            "CompanyName": "BraveSoftware Inc.",
            "OriginalFilename": "BraveBrowserSetup-BRV*.exe",
            "CertThumbprint": "F8AC5F11DE7E26383B7A389FC19A2613835799D7",
            "SignerSimpleName": "Brave Software",
            "FileDescriptions": "Brave Software Update Setup Brave Browser Setup-BRV*.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Brave Browser",
            "Brave Software Inc",
            "Brave Software, Inc.",
            "Brave-Browser",
            "BraveSoftware"
        ]
    },
    {
        "Name": "Burnout",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "Burnout Legends (USA) (En,Fr,De,Es,It,Nl) (v2.00)",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Burnout Legends (USA) (En,Fr,De,Es,It,Nl) (v2.00)"
        },
        "PathAnchors": "Burnout Legends (USA) (En,Fr,De,Es,It,Nl) (v*)"
    },
    {
        "Name": "Craftmine",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": "CraftMine - Definitive Edition",
            "CompanyName": null,
            "OriginalFilename": null,
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": null
        },
        "PathAnchors": [
            "CraftMine - Definitive Edition",
            "minecraft-*-alpha.25.14.craftmine-*",
            "Simply Craftmine"
        ]
    },
    {
        "Name": "CRSED Launcher",
        "UWPFamily": null,
        "ARPName": "CRSED Launcher*",
        "Publisher": "Gaijin Network",
        "InstallerSignatures": {
            "ProductName": "CRSED Launcher",
            "CompanyName": "Gaijin Network",
            "OriginalFilename": "cr_launcher_*-50kyb*.exe",
            "CertThumbprint": "E0FA7813DBA4A69359ABF65238190420A9751936",
            "SignerSimpleName": "GAIJIN NETWORK LTD",
            "FileDescriptions": "CRSED Launcher Setupcr_launcher_*-50kyb*.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "CRSED",
            "Gaijin Network"
        ]
    },
    {
        "Name": "CurseForge",
        "UWPFamily": null,
        "ARPName": "CurseForge*",
        "Publisher": "Overwolf",
        "InstallerSignatures": {
            "ProductName": "Curseforge",
            "CompanyName": "Overwolf Ltd.",
            "OriginalFilename": "CurseForge Windows - Installer.exe",
            "CertThumbprint": "962A9D59796B8C6AE1A7D8FAE72EC3729A898814",
            "SignerSimpleName": "Overwolf Ltd",
            "FileDescriptions": "Curseforge Curse Forge Windows - Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "CurseForge",
            "CurseForge Windows",
            "curseforge-updater",
            "Overwolf"
        ]
    },
    {
        "Name": "Discord",
        "UWPFamily": null,
        "ARPName": "Discord*",
        "Publisher": "Discord Inc.",
        "InstallerSignatures": {
            "ProductName": "Discord - https://discord.com/",
            "CompanyName": "Discord Inc.",
            "OriginalFilename": "DiscordSetup.exe",
            "CertThumbprint": "6C7552617E892DFCA5CEB96FA2870F4F1904820E",
            "SignerSimpleName": "Discord Inc.",
            "FileDescriptions": "Discord - https://discord.com/Discord Setup.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Discord",
            "Discord Inc."
        ]
    },
    {
        "Name": "Dragon City",
        "UWPFamily": "SocialPoint.DragonCityMobile_jahftqv9k5jer",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Store Installer",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "Dragon City Installer.exe",
            "CertThumbprint": "CB603439DC30897FCED64CA353AA902DBD3540E3",
            "SignerSimpleName": "Microsoft Corporation",
            "FileDescriptions": "Store Installer Dragon City Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "DragonCity",
            "Social Point",
            "SocialPoint.DragonCityMobile_*"
        ]
    },
    {
        "Name": "DuckDuckGo",
        "UWPFamily": "DuckDuckGo.DesktopBrowser_ya2fgkz3nks94",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "DuckDuckGo\u00ae Browser Installer",
            "CompanyName": "DuckDuckGo LLC",
            "OriginalFilename": "DuckDuckGo.Installer.exe",
            "CertThumbprint": "69441D863214355EC15AEE0164ACCDEE3CEFC373",
            "SignerSimpleName": "Duck Duck Go",
            "FileDescriptions": "Duck Duck Go.Installer Duck Duck Go.Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": "DuckDuckGo.DesktopBrowser_ya2fgkz3nks94"
    },
    {
        "Name": "Endless Sky",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Endless Sky",
            "CompanyName": null,
            "OriginalFilename": "Endless Sky.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Space exploration and combat game",
                "Endless Sky",
                "Endless Sky.exe"
            ]
        },
        "PortableExeSignatures": {
            "ProductName": "Endless Sky",
            "CompanyName": null,
            "OriginalFilename": "Endless Sky.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Space exploration and combat game",
                "Endless Sky"
            ]
        },
        "PathAnchors": [
            "endless-sky*",
            "EndlessSky-win64-v0.10.16",
            "https_endless-sky.fandom.com_0.indexeddb.leveldb"
        ]
    },
    {
        "Name": "Enlisted Launcher",
        "UWPFamily": null,
        "ARPName": "Enlisted Launcher*",
        "Publisher": "Gaijin Network",
        "InstallerSignatures": {
            "ProductName": "Enlisted Launcher",
            "CompanyName": "Gaijin Network",
            "OriginalFilename": "enlisted_launcher_*-8ghojp2cq.exe",
            "CertThumbprint": "E0FA7813DBA4A69359ABF65238190420A9751936",
            "SignerSimpleName": "GAIJIN NETWORK LTD",
            "FileDescriptions": "Enlisted Launcher Setupenlisted_launcher_*-8ghojp2cq.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Enlisted",
            "Gaijin Network",
            "My Games"
        ]
    },
    {
        "Name": "eve-online",
        "UWPFamily": null,
        "ARPName": "eve-online*",
        "Publisher": "CCP ehf",
        "InstallerSignatures": {
            "ProductName": "A launcher for EVE Online",
            "CompanyName": "CCP ehf",
            "OriginalFilename": "eve-online-latest+Setup.exe",
            "CertThumbprint": "BE688C28E20108AB16E53BA40990765EE8536F2B",
            "SignerSimpleName": "CCP ehf.",
            "FileDescriptions": "A launcher for EVE Onlineeve-online-latest+Setup.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "CCP ehf",
            "EVE Online",
            "eve-online"
        ]
    },
    {
        "Name": "FCEUX",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "fceux.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "fceux.exe"
        },
        "PortableExeSignatures": {
            "ProductName": "fceux",
            "CompanyName": null,
            "OriginalFilename": null,
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": null
        },
        "PathAnchors": "fceux*"
    },
    {
        "Name": "Free Download Manager",
        "UWPFamily": null,
        "ARPName": "Free Download Manager*",
        "Publisher": "Softdeluxe",
        "InstallerSignatures": {
            "ProductName": "Free Download Manager",
            "CompanyName": "Softdeluxe",
            "OriginalFilename": null,
            "CertThumbprint": "F145211219978C65FF322D9C16EC82FA90F88671",
            "SignerSimpleName": "E=administrator@softdeluxe.com",
            "FileDescriptions": "Free Download Manager Setup"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Free Download Manager",
            "Softdeluxe"
        ]
    },
    {
        "Name": "game",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "mkxp-z",
            "CompanyName": null,
            "OriginalFilename": "Game-performance.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Game-performance.exe"
        },
        "PortableExeSignatures": {
            "ProductName": "mkxp-z",
            "CompanyName": null,
            "OriginalFilename": "mkxp-z.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": null
        },
        "PathAnchors": [
            "003_Game processing",
            "004_Game classes",
            "https_count-masters-stickman-games.game-files.crazygames.com_0.indexeddb.leveldb",
            "https_gamesfrog.com_0.indexeddb.leveldb",
            "https_ragdoll-archers.game-files.crazygames.com_0.indexeddb.leveldb",
            "https_survival-rush.game-files.crazygames.com_0.indexeddb.leveldb"
        ]
    },
    {
        "Name": "game-jolt-client",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Game Jolt Client",
            "CompanyName": "Game Jolt Inc.",
            "OriginalFilename": "gamejoltclientsetup.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Game Jolt Client Setup",
                "gamejoltclientsetup.exe"
            ]
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "GameJoltClient",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "GameJoltClient"
        },
        "PathAnchors": [
            "GameJoltClient",
            "game-jolt-client"
        ]
    },
    {
        "Name": "Gang Beasts",
        "UWPFamily": "DoubleFineProductionsInc.GangBeasts_s9zt93y1rpe5a",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": [
            "DoubleFineProductionsInc.GangBeasts_*",
            "Gang Beasts"
        ]
    },
    {
        "Name": "GeometryDash",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "GeometryDash.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Geometry Dash.exe"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "GeometryDash",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "GeometryDash"
        },
        "PathAnchors": "Geometry DashGeometryDash"
    },
    {
        "Name": "Google Play Games",
        "UWPFamily": null,
        "ARPName": "Google Play Games*",
        "Publisher": "Google LLC",
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Apps",
            "Google Play Games",
            "Google.Play.Games",
            "Install-Clash Royale-GooglePlayGames*",
            "Install-Drift Max Pro Car Racing Game-GooglePlayGames*",
            "Install-Geometry Dash Lite-GooglePlayGames*",
            "Install-Hill Climb Racing-GooglePlayGames*",
            "Play Games"
        ]
    },
    {
        "Name": "Hill Climb Racing",
        "UWPFamily": "FINGERSOFT.HILLCLIMBRACING_r6rtpscs7gwyg",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Store Installer",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "Hill Climb Racing Installer.exe",
            "CertThumbprint": "CB603439DC30897FCED64CA353AA902DBD3540E3",
            "SignerSimpleName": "Microsoft Corporation",
            "FileDescriptions": "Store Installer Hill Climb Racing Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "FINGERSOFT.HILLCLIMBRACING_*",
            "HCR-Trainer"
        ]
    },
    {
        "Name": "Instagram",
        "UWPFamily": "Facebook.InstagramBeta_8xx8rvfyw5nnt",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": "Facebook.InstagramBeta_*"
    },
    {
        "Name": "Lively",
        "UWPFamily": "12030rocksdanister.LivelyWallpaper_97hta09mmv6hy",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Store Installer",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "Lively Wallpaper Installer.exe",
            "CertThumbprint": "CB603439DC30897FCED64CA353AA902DBD3540E3",
            "SignerSimpleName": "Microsoft Corporation",
            "FileDescriptions": "Store Installer Lively Wallpaper Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "12030rocksdanister.LivelyWallpaper_*",
            "Lively Wallpaper"
        ]
    },
    {
        "Name": "Lunar Client",
        "UWPFamily": null,
        "ARPName": "Uninstall Lunar Client*",
        "Publisher": "Moonsworth LLC",
        "InstallerSignatures": {
            "ProductName": "Lunar Client",
            "CompanyName": "Overwolf Ltd.",
            "OriginalFilename": "Lunar Client - Installer.exe",
            "CertThumbprint": "962A9D59796B8C6AE1A7D8FAE72EC3729A898814",
            "SignerSimpleName": "Overwolf Ltd",
            "FileDescriptions": "Lunar Client Lunar Client - Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            ".lunarclient",
            "Lunar Client",
            "lunarclient",
            "lunarclient-updater",
            "Moonsworth LLC"
        ]
    },
    {
        "Name": "mGBA",
        "UWPFamily": null,
        "ARPName": "mGBA*",
        "Publisher": "Jeffrey Pfau",
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "mgba",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "mgba"
        },
        "PathAnchors": [
            "Jeffrey Pfau",
            "mGBA",
            "mGBA-*-win32-installer",
            "shaders"
        ]
    },
    {
        "Name": "Minecraft for Windows",
        "UWPFamily": "MICROSOFT.MINECRAFTUWP_8wekyb3d8bbwe",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "MinecraftInstaller",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "MinecraftInstaller.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Minecraft Installer"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Minecraft for Windows",
            "Minecraft Launcher",
            "MinecraftLauncher"
        ]
    },
    {
        "Name": "Minecraft Launcher",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "Minecraft Launcher",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Minecraft Launcher"
        },
        "PathAnchors": "Minecraft Launcher"
    },
    {
        "Name": "ModernWarshipsLauncher",
        "UWPFamily": null,
        "ARPName": "ModernWarshipsLauncher*",
        "Publisher": "Gaijin Network",
        "InstallerSignatures": {
            "ProductName": "ModernWarships Launcher",
            "CompanyName": "Gaijin Network",
            "OriginalFilename": "modern_warships_launcher_*.exe",
            "CertThumbprint": "E0FA7813DBA4A69359ABF65238190420A9751936",
            "SignerSimpleName": "GAIJIN NETWORK LTD",
            "FileDescriptions": [
                "Modern Warships Launcher Setup",
                "modern_warships_launcher_*.exe"
            ]
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Gaijin Network",
            "modern_warships",
            "ModernWarships",
            "My Games"
        ]
    },
    {
        "Name": "Modrinth App",
        "UWPFamily": null,
        "ARPName": "Modrinth App*",
        "Publisher": "ModrinthApp",
        "InstallerSignatures": {
            "ProductName": "Modrinth App",
            "CompanyName": null,
            "OriginalFilename": "Modrinth App_*_x64-setup.exe",
            "CertThumbprint": "F82EABB60BB01A0DB764F4E3A737FC1483EC4434",
            "SignerSimpleName": "Rinth",
            "FileDescriptions": "Modrinth App Modrinth App_*_x64-setup.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Modrinth App",
            "Modrinth App-0.10.15-updater-SJXQCk",
            "ModrinthApp"
        ]
    },
    {
        "Name": "Mozilla Firefox",
        "UWPFamily": null,
        "ARPName": "Mozilla Firefox (x64 en-US)*",
        "Publisher": "Mozilla",
        "InstallerSignatures": {
            "ProductName": "Firefox",
            "CompanyName": "Mozilla",
            "OriginalFilename": "Firefox Installer.exe",
            "CertThumbprint": "40890F2FE1ACAE18072FA7F3C0AE456AACC8570D",
            "SignerSimpleName": "Mozilla Corporation",
            "FileDescriptions": "Firefox Firefox Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Firefox",
            "Mozilla",
            "Mozilla Firefox",
            "Old Firefox Data"
        ]
    },
    {
        "Name": "Opera Air Stable",
        "UWPFamily": null,
        "ARPName": "Opera Air Stable*",
        "Publisher": "Opera Software",
        "InstallerSignatures": {
            "ProductName": "Opera installer",
            "CompanyName": null,
            "OriginalFilename": "OperaAirSetup.exe",
            "CertThumbprint": "25F4C2A374C779AB087B79B7740216416CAF0EE0",
            "SignerSimpleName": "Opera Norway AS",
            "FileDescriptions": [
                "Opera installer SFX",
                "Opera Air Setup.exe"
            ]
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Opera Air",
            "Opera Air Stable",
            "Opera Software"
        ]
    },
    {
        "Name": "Opera GX Stable",
        "UWPFamily": null,
        "ARPName": "Opera GX Stable*",
        "Publisher": "Opera Software",
        "InstallerSignatures": {
            "ProductName": "Opera installer",
            "CompanyName": null,
            "OriginalFilename": "OperaGXSetup.exe",
            "CertThumbprint": "25F4C2A374C779AB087B79B7740216416CAF0EE0",
            "SignerSimpleName": "Opera Norway AS",
            "FileDescriptions": [
                "Opera installer SFX",
                "Opera GXSetup.exe"
            ]
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Opera GX",
            "Opera GX Stable",
            "Opera Software"
        ]
    },
    {
        "Name": "Opera Stable",
        "UWPFamily": null,
        "ARPName": "Opera Stable*",
        "Publisher": "Opera Software",
        "InstallerSignatures": {
            "ProductName": "Opera installer",
            "CompanyName": null,
            "OriginalFilename": "OperaSetup.exe",
            "CertThumbprint": "BF684995EFEA2306448FF2930367C60AC0F7172C",
            "SignerSimpleName": "Opera Norway AS",
            "FileDescriptions": [
                "Opera installer SFX",
                "Opera Setup.exe"
            ]
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Opera Software",
            "Opera Stable"
        ]
    },
    {
        "Name": "pcsx2",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "PCSX2",
            "CompanyName": "PCSX2 Team",
            "OriginalFilename": "pcsx2-v*-windows-x64-installer.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "PCSX2 Setuppcsx2-v*-windows-x64-installer.exe"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "PCSX2",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "PCSX2"
        },
        "PathAnchors": "PCSX2"
    },
    {
        "Name": "PPSSPP",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "ppsspp_win",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "ppsspp_win"
        },
        "PathAnchors": "ppsspp_win"
    },
    {
        "Name": "retroarch",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "RetroArch-MSVC10-Win64",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "RetroArch-MSVC10-Win64"
        },
        "PathAnchors": "RetroArch-MSVC10-Win64"
    },
    {
        "Name": "Riot Client",
        "UWPFamily": null,
        "ARPName": "Riot Client*",
        "Publisher": "Riot Games, Inc",
        "InstallerSignatures": {
            "ProductName": "RiotClient",
            "CompanyName": "Riot Games, Inc.",
            "OriginalFilename": "Install VALORANT.exe",
            "CertThumbprint": "7FEEA8A5B55F34023287495F77CE55B0887CAA05",
            "SignerSimpleName": "Riot Games",
            "FileDescriptions": [
                "Riot Client",
                "Riot",
                "Install VALORANT.exe"
            ]
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "C:\\Riot Games\\Riot Client",
            "Riot",
            "Riot Client",
            "Riot Games",
            "Riot Games, Inc.",
            "RiotClient"
        ]
    },
    {
        "Name": "Roblox",
        "UWPFamily": "ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": "ROBLOXCORPORATION.ROBLOX_*"
    },
    {
        "Name": "Roblox Player",
        "UWPFamily": null,
        "ARPName": "Roblox Player*",
        "Publisher": "Roblox Corporation",
        "InstallerSignatures": {
            "ProductName": "Roblox Bootstrapper",
            "CompanyName": "Roblox Corporation",
            "OriginalFilename": "RobloxPlayerInstaller-JQGXMWMQ6Y.exe",
            "CertThumbprint": "813CA29445456DC3447C173347A0CE5B9494B24C",
            "SignerSimpleName": "Roblox Corporation",
            "FileDescriptions": "Roblox Roblox Player Installer-JQGXMWMQ6Y.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "https_roblox.fandom.com_0.indexeddb.leveldb",
            "https_www.roblox.com_0.indexeddb.leveldb",
            "roblox",
            "Roblox Bootstrapper",
            "Roblox Corporation"
        ]
    },
    {
        "Name": "Roblox Studio",
        "UWPFamily": null,
        "ARPName": "Roblox Studio*",
        "Publisher": "Roblox Corporation",
        "InstallerSignatures": {
            "ProductName": "Roblox Bootstrapper",
            "CompanyName": "Roblox Corporation",
            "OriginalFilename": "RobloxPlayerInstaller-JQGXMWMQ6Y.exe",
            "CertThumbprint": "813CA29445456DC3447C173347A0CE5B9494B24C",
            "SignerSimpleName": "Roblox Corporation",
            "FileDescriptions": "Roblox Roblox Player Installer-JQGXMWMQ6Y.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Roblox",
            "Roblox Bootstrapper",
            "Roblox Corporation",
            "RobloxStudio",
            "roblox-studio"
        ]
    },
    {
        "Name": "Shift Browser",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Shift Browser",
            "CompanyName": "Shift Technologies Inc.",
            "OriginalFilename": "Shift Setup.exe",
            "CertThumbprint": "0C9A1B5FD117CB11BF7D5E624B20E458F6BCFBF4",
            "SignerSimpleName": "Shift Technologies Inc",
            "FileDescriptions": "Shift Browser Setup"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "Shift",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Shift"
        },
        "PathAnchors": "Shift"
    },
    {
        "Name": "Snapchat",
        "UWPFamily": "SnapInc.Snapchat_k1zn018256b8e",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": "SnapInc.Snapchat_*"
    },
    {
        "Name": "SNES",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Snes9x SNES Emulator",
            "CompanyName": "http://www.snes9x.com",
            "OriginalFilename": "Advanced_SNES_ROM_Utility.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Snes9x",
                "Advanced SNES ROM Utility",
                "Advanced_SNES_ROM_Utility.exe"
            ]
        },
        "PortableExeSignatures": {
            "ProductName": "Snes9x SNES Emulator",
            "CompanyName": "http://www.snes9x.com",
            "OriginalFilename": "Snes9x.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Snes9x",
                "Advanced SNES ROM Utility"
            ]
        },
        "PathAnchors": [
            "SNES",
            "snes9x-1.62.3-win32-x64"
        ]
    },
    {
        "Name": "StarConflict Launcher",
        "UWPFamily": null,
        "ARPName": "StarConflict Launcher*",
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "StarConflict Launcher",
            "CompanyName": null,
            "OriginalFilename": "starconf_launcher_*.exe",
            "CertThumbprint": "E0FA7813DBA4A69359ABF65238190420A9751936",
            "SignerSimpleName": "GAIJIN NETWORK LTD",
            "FileDescriptions": "Star Conflict Launcher Setupstarconf_launcher_*.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": "StarConflict"
    },
    {
        "Name": "Stardew Valley",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Stardew Valley",
            "CompanyName": "ConcernedApe",
            "OriginalFilename": "Stardew Valley.dll",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Stardew Valley Stardew Valley.dll"
        },
        "PortableExeSignatures": {
            "ProductName": "Stardew Valley",
            "CompanyName": "ConcernedApe",
            "OriginalFilename": "Stardew Valley.dll",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "Stardew Valley"
        },
        "PathAnchors": [
            "Stardew Valley",
            "StardewValley"
        ]
    },
    {
        "Name": "TASEditor",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "taseditor",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "taseditor"
        },
        "PathAnchors": [
            "luaScripts",
            "taseditor"
        ]
    },
    {
        "Name": "TikTok",
        "UWPFamily": "BytedancePte.Ltd.TikTok_6yccndn6064se",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Store Installer",
            "CompanyName": "Microsoft Corporation",
            "OriginalFilename": "TikTok Installer.exe",
            "CertThumbprint": "CB603439DC30897FCED64CA353AA902DBD3540E3",
            "SignerSimpleName": "Microsoft Corporation",
            "FileDescriptions": "Store Installer Tik Tok Installer.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": "BytedancePte.Ltd.TikTok_*"
    },
    {
        "Name": "Tor Browser",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "Tor Browser",
            "CompanyName": "Mozilla Foundation",
            "OriginalFilename": "tor-browser-windows-x86_64-portable-*.exe",
            "CertThumbprint": "4DEB8C027FFF4DD8DE3AE9BEFAA7898618ADCF15",
            "SignerSimpleName": "THE TOR PROJECT",
            "FileDescriptions": "Tor Browser Software Updatertor-browser-windows-x86_64-portable-*.exe"
        },
        "PortableExeSignatures": {
            "ProductName": "Tor Browser",
            "CompanyName": "Mozilla Foundation",
            "OriginalFilename": "updater.exe",
            "CertThumbprint": "4DEB8C027FFF4DD8DE3AE9BEFAA7898618ADCF15",
            "SignerSimpleName": "THE TOR PROJECT",
            "FileDescriptions": "Tor Browser Software Updater"
        },
        "PathAnchors": "Tor Browser"
    },
    {
        "Name": "TranslucentTB",
        "UWPFamily": "28017CharlesMilette.TranslucentTB_v826wp6bftszj",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": "28017CharlesMilette.TranslucentTB_*"
    },
    {
        "Name": "Visual Boy Advance",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "VisualBoyAdvance-M",
            "CompanyName": "http://vba-m.com/",
            "OriginalFilename": "VisualBoyAdvance-M.exe",
            "CertThumbprint": "34025714D92839B99F89F8E80BBDDBCC465C7459",
            "SignerSimpleName": "Rafael Kitover",
            "FileDescriptions": "Visual Boy Advance-MVisual Boy Advance-M.exe"
        },
        "PortableExeSignatures": {
            "ProductName": "VisualBoyAdvance-M",
            "CompanyName": "http://vba-m.com/",
            "OriginalFilename": "VisualBoyAdvance-M.exe",
            "CertThumbprint": "34025714D92839B99F89F8E80BBDDBCC465C7459",
            "SignerSimpleName": "Rafael Kitover",
            "FileDescriptions": "Visual Boy Advance-M"
        },
        "PathAnchors": [
            "Emus",
            "visualboyadvance-m",
            "visualboyadvance-m-Win-x86_64"
        ]
    },
    {
        "Name": "Vivaldi",
        "UWPFamily": null,
        "ARPName": "Vivaldi*",
        "Publisher": "Vivaldi Technologies AS.",
        "InstallerSignatures": {
            "ProductName": "Vivaldi Installer",
            "CompanyName": "Vivaldi Technologies AS",
            "OriginalFilename": "Vivaldi.*.x64.exe",
            "CertThumbprint": "F7A524AD45E585F8B71E6204B2583714151A08EF",
            "SignerSimpleName": "Vivaldi Technologies AS",
            "FileDescriptions": "Vivaldi Installer Vivaldi.*.x64.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Vivaldi",
            "Vivaldi Technologies AS.",
            "VivaldiUpdate-0mzooqjxmtnle4oev7sdyw"
        ]
    },
    {
        "Name": "warriors-_untold_tales_v*",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "warriors-_untold_tales_v*.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "warriors-_untold_tales_v*.exe"
        },
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "cfc6be36-c966-468e-9d9e-c3ab6bc6ab45",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "cfc6be36-c966-468e-9d9e-c3ab6bc6ab45"
        },
        "PathAnchors": "cfc6be36-c966-468e-9d9e-c3ab6bc6ab45"
    },
    {
        "Name": "Wave Browser",
        "UWPFamily": null,
        "ARPName": "Wave Browser*",
        "Publisher": "Wavesor Software",
        "InstallerSignatures": {
            "ProductName": "WaveBrowser",
            "CompanyName": "Wavesor Software",
            "OriginalFilename": "Wave Browser.exe",
            "CertThumbprint": "2EA4ADE8719DE01274C5A3BAF694B91E339BDA79",
            "SignerSimpleName": "Wavesor Software (Eightpoint Technologies Ltd. SEZC)",
            "FileDescriptions": "Wave Browser Wave Browser.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "WaveBrowser",
            "Wavesor Software"
        ]
    },
    {
        "Name": "Wesnoth",
        "UWPFamily": "Wesnoth1.18",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": {
            "ProductName": "The Battle for Wesnoth",
            "CompanyName": "The Battle for Wesnoth Project",
            "OriginalFilename": "wesnoth-*-win64.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Wesnoth Game Client",
                "Wesnoth Multiplayer Server",
                "wesnoth-*-win64.exe"
            ]
        },
        "PortableExeSignatures": {
            "ProductName": "The Battle for Wesnoth",
            "CompanyName": "The Battle for Wesnoth Project",
            "OriginalFilename": "wesnoth.exe",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": [
                "Wesnoth Game Client",
                "Wesnoth Multiplayer Server"
            ]
        },
        "PathAnchors": [
            "battle-for-wesnoth-win-stable",
            "https_wesnoth.fandom.com_0.indexeddb.leveldb",
            "Wesnoth1.18"
        ]
    },
    {
        "Name": "WinSCP",
        "UWPFamily": null,
        "ARPName": "WinSCP*",
        "Publisher": "Martin Prikryl",
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": [
            "Martin Prikryl",
            "WinSCP"
        ]
    },
    {
        "Name": "Wizard101",
        "UWPFamily": null,
        "ARPName": "Wizard101*",
        "Publisher": "KingsIsle Entertainment, Inc.",
        "InstallerSignatures": {
            "ProductName": "InstallShield",
            "CompanyName": "Acresso Software Inc.",
            "OriginalFilename": "InstallWizard*.exe",
            "CertThumbprint": "EE9ADBB845E1FC153650AB991EA989BFD6F60401",
            "SignerSimpleName": "KingsIsle Entertainment Inc.",
            "FileDescriptions": "Setup.exe Install Wizard*.exe"
        },
        "PortableExeSignatures": null,
        "PathAnchors": [
            "KingsIsle Entertainment",
            "KingsIsle Entertainment, Inc.",
            "Wizard101"
        ]
    },
    {
        "Name": "WoT Blitz",
        "UWPFamily": "7458BE2C.WorldofTanksBlitz_x4tje2y229k00",
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "7458BE2C.WorldofTanksBlitz_x4tje2y229k00",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "7458BE2C.WorldofTanksBlitz_x4tje2y229k00"
        },
        "PathAnchors": "7458BE2C.WorldofTanksBlitz_x4tje2y229k00"
    },
    {
        "Name": "XboxPcApp",
        "UWPFamily": "Microsoft.GamingApp_8wekyb3d8bbwe",
        "ARPName": null,
        "Publisher": "Microsoft Corporation",
        "InstallerSignatures": null,
        "PortableExeSignatures": null,
        "PathAnchors": "8wekyb3d8bbwe"
    },
    {
        "Name": "XENIA-MASTER",
        "UWPFamily": null,
        "ARPName": null,
        "Publisher": null,
        "InstallerSignatures": null,
        "PortableExeSignatures": {
            "ProductName": null,
            "CompanyName": null,
            "OriginalFilename": "xenia_master",
            "CertThumbprint": null,
            "SignerSimpleName": null,
            "FileDescriptions": "xenia_master"
        },
        "PathAnchors": [
            "xenia_master",
            "xenia-master"
        ]
    }
]
'@

function Ensure-Dir([string]$p) {
  if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null }
}

function Write-FileUtf8([string]$path, [string]$content) {
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $content, $enc)
}

function Set-RsdAclHard([string]$path) {
  # Rebuild ACL from scratch (handles pre-existing permissive explicit ACEs).
  # Target:
  #   - SYSTEM: FullControl
  #   - BUILTIN\Administrators: FullControl
  #   - BUILTIN\Users: Read & Execute (optional)
  #
  # IMPORTANT:
  # We intentionally DO NOT add explicit DENY entries because most admin accounts
  # are also members of BUILTIN\Users; a DENY on Users would block admins too.
  try {
    if (-not (Test-Path $path)) { return }

    # Take ownership to ensure we can rewrite DACL (best-effort).
    try { takeown /F "$path" /A /R /D Y | Out-Null } catch {}

    # 1) Disable inheritance (do not copy inherited ACEs)
    icacls "$path" /inheritance:d | Out-Null

    # 2) Remove broad allow/deny ACEs that could grant write access
    foreach ($g in @('Everyone','Authenticated Users','Users','Domain Users')) {
      try { icacls "$path" /remove:g "$g" | Out-Null } catch {}
      try { icacls "$path" /remove:d "$g" | Out-Null } catch {}
    }

    # 3) Grant only what we want (replace any existing with /grant:r)
    icacls "$path" /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" | Out-Null

    # Optional: allow standard users to read/execute (no write/delete). If you prefer them
    # to have ZERO access, comment out the next line.
    # icacls "$path" /grant:r "BUILTIN\Users:(OI)(CI)(RX)" | Out-Null

    # 4) Apply recursively
    icacls "$path" /T /C | Out-Null
  } catch {
    # Keep remediation resilient; Intune will re-run if needed.
  }
}


function Set-RsdFileAcl([string]$path) {
  try {
    if (-not (Test-Path $path)) { return }
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::None
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None
    $typeAllow    = [System.Security.AccessControl.AccessControlType]::Allow

    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl",$inheritFlags,$propFlags,$typeAllow)
    $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl",$inheritFlags,$propFlags,$typeAllow)
    $ruleUsers  = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute",$inheritFlags,$propFlags,$typeAllow)

    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule($ruleSystem) | Out-Null
    $acl.AddAccessRule($ruleAdmins) | Out-Null
    $acl.AddAccessRule($ruleUsers)  | Out-Null

    try {
      $owner = New-Object System.Security.Principal.NTAccount("SYSTEM")
      $acl.SetOwner($owner)
    } catch {}

    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction SilentlyContinue
  } catch {}
}


function Remediate-Log([string]$m, [string]$lvl='INFO') {
  try {
    $p = Join-Path $LogDir 'remediateAGENT.log'
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $p -Value ("{0} [{1}] {2}" -f $ts, $lvl, $m) -Encoding UTF8
  } catch {}
}

function Register-CleanAgentTask {
  $taskName = 'RSD-CleanAGENT'
  $taskDesc = 'RSD local cleaning agent. Runs hourly; script enforces adaptive backoff schedule.'
  $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$AgentScript`""
  $created = $false

  # If task already exists, keep it (avoid delete/recreate churn on repeated Intune runs).
  try {
    schtasks /Query /TN "$taskName" /FO LIST | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Remediate-Log ("Existing task already present: " + $taskName)
      return $true
    }
  } catch {}

  Import-Module ScheduledTasks -ErrorAction SilentlyContinue

  $useScheduledTasksModule = $true
  foreach ($cmd in @('New-ScheduledTaskTrigger','New-ScheduledTaskAction','New-ScheduledTaskSettingsSet','New-ScheduledTaskPrincipal','New-ScheduledTask','Register-ScheduledTask')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { $useScheduledTasksModule = $false; break }
  }

  if (-not $useScheduledTasksModule) {
    Remediate-Log "ScheduledTasks cmdlets unavailable after import; expected in Intune/SYSTEM context. Using schtasks.exe as primary path."
  } else {
    Remediate-Log "ScheduledTasks cmdlets detected after import; schtasks.exe remains primary path for reliability."
  }

  # Primary reliable path for Intune/SYSTEM contexts
  if (-not $created) {
    try {
      $tr = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$AgentScript`""
      Remediate-Log ("Creating scheduled task via schtasks: " + $taskName)
      schtasks /Create /F /RU "SYSTEM" /RL HIGHEST /SC HOURLY /MO 1 /TN "$taskName" /TR "$tr" | Out-Null
      if ($LASTEXITCODE -eq 0) {
        $created = $true
        Remediate-Log "Registered task via schtasks.exe"
      }
    } catch {
      Remediate-Log -m "schtasks.exe /Create threw an exception" -lvl 'ERROR'
    }
  }

  if ((-not $created) -and $useScheduledTasksModule) {
    try {
      $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
      $trigger.RepetitionInterval = (New-TimeSpan -Hours 1)
      $trigger.RepetitionDuration = ([TimeSpan]::MaxValue)

      $action = New-ScheduledTaskAction -Execute $ps -Argument $args
      $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew
      $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
      $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDesc

      Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
      $created = $true
      Remediate-Log "Registered task via ScheduledTasks module"
    } catch {
      Remediate-Log -m "ScheduledTasks registration failed after schtasks.exe attempt" -lvl 'WARN'
    }
  }

  # Exact verification pass
  try {
    schtasks /Query /TN "$taskName" /FO LIST | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Remediate-Log "Task present after registration: $taskName"
      $fullTaskName = "\\$taskName"
      $queryOutput = @(schtasks /Query /TN "$taskName" /V /FO LIST 2>&1)
      if ($LASTEXITCODE -ne 0) {
        Remediate-Log -m ("Task query failed for ${fullTaskName}: " + (($queryOutput | Out-String).Trim())) -lvl 'WARN'
      } else {
        foreach ($field in @('TaskName','Next Run Time','Last Run Time','Last Result','Task To Run','Schedule Type')) {
          $line = $queryOutput | Where-Object { $_ -like ("${field}:*") } | Select-Object -First 1
          if ($line) {
            Remediate-Log ("TaskDiagnostics " + $line.Trim())
          } else {
            Remediate-Log -m ("TaskDiagnostics ${field}: <missing>") -lvl 'WARN'
          }
        }
      }
      return $true
    }

    $err = (schtasks /Query /TN "$taskName" /FO LIST 2>&1 | Out-String)
    if ($err) { Remediate-Log -m ("Task query error: " + $err.Trim()) -lvl 'ERROR' }
  } catch {}

  Remediate-Log -m "Task registration verification failed: $taskName" -lvl 'ERROR'
  return $false
}

function Invoke-CleanAgentNow {
  try {
    if (-not (Test-Path $AgentScript)) { Remediate-Log -m "cleanAGENT script missing at runtime" -lvl 'ERROR'; return }
    $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $p = Start-Process -FilePath $ps -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$AgentScript`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    if ($p) {
      $done = $p.WaitForExit(600000)
      if ($done) { Remediate-Log ("Immediate cleanAGENT run finished with exit code " + $p.ExitCode) }
      else {
        try { $p.Kill() } catch {}
        Remediate-Log -m "Immediate cleanAGENT run timed out after 10 minutes" -lvl 'WARN'
      }
    } else {
      Remediate-Log -m "Failed to start immediate cleanAGENT run process" -lvl 'ERROR'
    }
  } catch {
    Remediate-Log -m "Immediate cleanAGENT run threw an exception" -lvl 'ERROR'
  }
}

Ensure-Dir $AgentRoot
$RsdRoot = 'C:\ProgramData\RSD'
Ensure-Dir $RsdRoot
Ensure-Dir $LogDir

Write-FileUtf8 $AgentScript $AgentPayload
Write-FileUtf8 $TargetsPath $TargetsPayload
Write-FileUtf8 $VersionFile $ThisVersion

if (-not (Test-Path $StateFile)) {
   $initObj = @{ phase=0; phaseStart=(Get-Date).ToString("o"); lastDetect=(Get-Date).ToString("o"); lastRun=(Get-Date).ToString("o"); lastFound=@(); incidentOpen=$false; incidentApps=@(); lastExitCode=0; lastSweepSucceeded=$true }
  $init = ($initObj | ConvertTo-Json -Depth 6)
  Write-FileUtf8 $StateFile $init
}

Set-RsdAclHard $RsdRoot
Set-RsdAclHard $AgentRoot
Set-RsdFileAcl $AgentScript
Set-RsdFileAcl $TargetsPath
Set-RsdFileAcl $VersionFile
Set-RsdFileAcl $StateFile

Remediate-Log "Starting remediation deployment version $ThisVersion"
$taskName = "RSD-CleanAGENT"
$taskOk = Register-CleanAgentTask
if (-not $taskOk) {
  Remediate-Log -m "Remediation deployment completed with task registration failure" -lvl "ERROR"
  exit 1
}
Invoke-CleanAgentNow
Remediate-Log "Remediation deployment complete"
exit 0
