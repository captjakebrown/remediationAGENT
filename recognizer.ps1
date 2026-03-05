
<#  recognizer.ps1

Usage:

powershell -ExecutionPolicy Bypass -File "D:\recognizer.ps1" -AppName "Opera Air"

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$AppName,

  # Internal: when set, the script performs a UWP-only scan in *user* context and writes
  # the results to -OutJson. This is primarily invoked via the SYSTEM-context fallback.
  [switch]$UserUwpOnly,

  # Internal: output path used with -UserUwpOnly.
  [string]$OutJson
)

function Get-ActiveUserProfile {
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $sam = $null
    $principal = $null
    if ($cs -and $cs.UserName) {
      $principal = $cs.UserName
      $sam = $cs.UserName.Split('\')[-1]
    }
    if (-not $sam) {
      $expl = Get-CimInstance Win32_Process -Filter "name='explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($expl) {
        $o = $expl | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($o -and $o.User) {
          $sam = $o.User
          if ($o.Domain) { $principal = "$($o.Domain)\\$($o.User)" }
        }
      }
    }
    if (-not $sam) { return $null }
    $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in Get-ChildItem $pl -ErrorAction SilentlyContinue) {
      $pi = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
      if ($pi -and $pi.ProfileImagePath -match "\\Users\\$([regex]::Escape($sam))$") {
        return [pscustomobject]@{
          User    = $sam
          Principal = $principal
          SID     = $k.PSChildName
          Profile = $pi.ProfileImagePath
        }
      }
    }
  } catch {}
  $null
}

function Get-HkuSids {
  $sids = @()
  try {
    foreach ($u in (Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue)) {
      $sid = $u.PSChildName
      if ($sid -and ($sid -notmatch '_Classes$')) { $sids += $sid }
    }
  } catch {}
  $sids
}

function Get-ArpEntriesAll {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  )

  foreach ($sid in (Get-HkuSids)) {
    $paths += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $paths += "Registry::HKEY_USERS\$sid\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  }

  $arp = @()

  foreach ($p in $paths) {
    try {
      foreach ($k in Get-ChildItem -Path $p -ErrorAction SilentlyContinue) {
        $displayName     = $null
        $displayVersion  = $null
        $publisher       = $null
        $installLocation = $null
        $displayIcon     = $null

        try {
          # Use SilentlyContinue so we still get a props object even if some values are odd
          $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
          if ($props) {
            $displayName     = $props.DisplayName
            $displayVersion  = $props.DisplayVersion
            $publisher       = $props.Publisher
            $installLocation = $props.InstallLocation
            $displayIcon     = $props.DisplayIcon
          }
        } catch {
          # If anything goes wrong reading properties, we still keep the key itself
        }

        $arp += [pscustomobject]@{
          HivePath        = $p
          KeyName         = $k.PSChildName
          DisplayName     = $displayName
          DisplayVersion  = $displayVersion
          Publisher       = $publisher
          InstallLocation = $installLocation
          DisplayIcon     = $displayIcon
        }
      }
    } catch {}
  }

  $arp
}

function ToAlpha {
  param([string]$s)
  if (-not $s) { return '' }
  ($s -replace '[^A-Za-z0-9]','').ToLower()
}

function Get-NameTokens {
  param([string]$s)
  if (-not $s) { return @() }
  # Split on non-alphanumeric boundaries and filter tokens.  Require at least
  # two characters and drop tokens consisting solely of digits (e.g. version numbers)
  $s -split '[^A-Za-z0-9]+' |
    Where-Object {
      $_ -and $_.Length -ge 2 -and ($_ -notmatch '^[0-9]+$')
    }
}

function Matches-OrderedTokens {
  param(
    [string]$text,
    [string[]]$tokens
  )

  if (-not $text -or -not $tokens -or $tokens.Count -eq 0) { return $false }

  # Boundary-aware ordered token matching.
  # Requirement:
  #   - Tokens must start at a word boundary (no leading alphanumeric).
  #   - Tokens may have trailing alphanumerics (Steam -> SteamSetup) but NOT leading (Steam !-> MSTeams).
  # This prevents common false positives while keeping your "version suffix" behavior.

  # Quick block for known protected alpha roots (Teams, etc.) to avoid junk matches.
  $tAlpha = ToAlpha $text
  if (-not $tAlpha) { return $false }
  foreach ($root in $ProtectedAppAlphaRoots) {
    if ($tAlpha -like "*$root*") { return $false }
  }

  $pos = 0
  $alphaPos = 0
  $alphaText = ToAlpha $text
  foreach ($tok in $tokens) {
    if (-not $tok) { return $false }
    $needle = $tok.ToString()
    if (-not $needle) { return $false }

    # For 3-char ALL-CAPS tokens (e.g. NZP), allow prefix-of-word with suffix chars.
    # For everything else (including "Steam"), enforce left boundary and allow suffix.
    $escaped = [regex]::Escape($needle)
    if ($tok -cmatch '^[A-Z0-9]{3}$') {
      $pattern = '(?i)(?<![a-z0-9])' + $escaped + '[a-z0-9]*'
    }
    else {
      $pattern = '(?i)(?<![a-z0-9])' + $escaped + '[a-z0-9]*'
    }

    $rx = New-Object System.Text.RegularExpressions.Regex($pattern)
    $m = $rx.Match($text, $pos)

    if (-not $m.Success) {
      # Relaxation for subsequent tokens only:
      # Some identifiers collapse words (HILLCLIMBRACING). We still require the
      # FIRST token to start at a word boundary, but allow later tokens to appear
      # inside the same alphanumeric run.
      if ($alphaText -and $alphaPos -ge 0 -and ($tokens[0] -ne $tok)) {
        $needleAlpha = ToAlpha $needle
        if ($needleAlpha) {
          $i = $alphaText.IndexOf($needleAlpha, $alphaPos)
          if ($i -ge 0) {
            $alphaPos = $i + $needleAlpha.Length
            continue
          }
        }
      }
      return $false
    }

    $pos = $m.Index + $m.Length
    if ($alphaText) {
      $needleAlpha2 = ToAlpha $needle
      if ($needleAlpha2) {
        $i2 = $alphaText.IndexOf($needleAlpha2, $alphaPos)
        if ($i2 -ge 0) { $alphaPos = $i2 + $needleAlpha2.Length }
      }
    }
  }

  return $true
}

function Is-StrongTokenSet {
  param([string[]]$tokens)

  if (-not $tokens -or $tokens.Count -eq 0) { return $false }

  foreach ($t in $tokens) {
    if ($t -and $t.Length -ge 4) { return $true }
  }

  if ($tokens.Count -ge 2) { return $true }

  if ($tokens.Count -eq 1 -and $tokens[0] -and $tokens[0].Length -ge 3) {
    return $true
  }

  $false
}

function Contains-AllTokensBoundary {
  <#
    Returns $true if every token is present in $text using safe word-start semantics:
      - token must not have a leading alphanumeric
      - token may have trailing alphanumerics
    This prevents false positives like "Steam" matching "MSTeams" while still
    allowing "SteamSetup".
  #>
  param(
    [string]$text,
    [string[]]$tokens
  )

  if (-not $text -or -not $tokens -or $tokens.Count -eq 0) { return $false }

  foreach ($tok in $tokens) {
    if (-not $tok) { return $false }
    $needle = $tok.ToString()
    if (-not $needle) { return $false }
    $pattern = '(?i)(?<![a-z0-9])' + [regex]::Escape($needle) + '[a-z0-9]*'
    if (-not [regex]::IsMatch($text, $pattern)) { return $false }
  }
  return $true
}

$StopWords = @(
  'program files','program files (x86)','programdata','common files','windows','system32','syswow64',
  'users','public','default','default user','all users','onedrive','documents','downloads','desktop',
  'pictures','music','videos','temp','tmp','installer','package cache','packages','windowsapps',
  'appdata','local','locallow','roaming','programs','startup','teams','msteams','microsoft teams','microsoftteams',
  'bin','lib','libs','include','res','resources','resource','assets','data','cache','logs','runtime','update',
  'updates','updater','autoupdate','backup','backups','framework','helpers','modules','module','plugins','plugin',
  'tools','tool','scripts','script','themes','theme','widgets','widget','samples','sample','examples','example',
  'config','configs','configuration','settings','profiles','profile','crashdumps','crash','dump',
  'net','assistant','host','h o s t','copyright','rights','reserved','authors','teams machine installer',
  'software','lastchange_year','digital','google','google llc','teams machine-wide installer',
  'application','app','games','new folder','folder',
  'store','storeinstaller','store installer','microsoft store','ms store'
  ,'xboxgames'
  ,'programfilesx86'
  ,'indexeddb','reportarchive','leveldb','apphang','appcrash'
  ,'browser'
) | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

# Protected UWP names and families.  These entries are considered critical system
# or sanctioned apps and should not be targeted for removal.  When a search
# would otherwise match one of these by name or package family, the entry
# will be ignored.  You can extend this list as needed to cover additional
# protected education or platform titles.  Note: matching is case-sensitive
# on the literal strings provided here.
$ProtectedUwpNames = @(
  'Minecraft Education',
  'Minecraft Education Edition'
)
$ProtectedUwpFamilies = @(
  'Microsoft.MinecraftEducationEdition_8wekyb3d8bbwe',
  'Microsoft.MinecraftEducationEdition'
)


$ProtectedAppAlphaRoots = @(
  'microsoftteams','msteams','teamsmachineinstaller','teamsmachinewideinstaller','teams','windowsteam'
)

function Clean-Anchor {
  param([string]$s)

  if (-not $s) { return $null }
  $s = $s.Trim()
  if (-not $s) { return $null }

  # Strip quotes and trailing slashes (preserves your existing behavior)
  $s = $s.Trim([char]34,[char]39,[char]92)
  if (-not $s) { return $null }
  if ($s.EndsWith('\')) { $s = $s.TrimEnd('\') }
  if ($s.EndsWith('/')) { $s = $s.TrimEnd('/') }
  $s = $s.Trim()
  if (-not $s) { return $null }

  # Basic length / numeric / version filters
  if ($s.Length -lt 3) { return $null }
  if ($s -match '^\d+$') { return $null }
  if ($s -match '^\d+(\.\d+)+$') { return $null }

  # Drop executable / binary / shortcut file names
  if ($s -match '\.(exe|dll|lnk|bat|cmd|msi|com|zip)$') { return $null }

  # Skip Windows Error Reporting (WER) crash identifiers.  Anchors like
  # "AppCrash_xyz" originate from crash report keys and are not meaningful
  # application identifiers.  Filtering them prevents false positives
  # downstream (e.g., Geometry Dash was misidentified as a UWP family).
  if ($s -like 'AppCrash_*') { return $null }

  # Skip Windows Error Reporting (WER) hang identifiers.  Similar to AppCrash,
  # "AppHang_xyz" entries stem from hang reports and should not be treated
  # as legitimate application anchors.
  if ($s -like 'AppHang_*') { return $null }

  # Skip anchors that look like URL or domain identifiers (e.g. "http_" or
  # "https_").  These can appear in browser cache folders (IndexedDB, leveldb,
  # ReportArchive, etc.) and are not application packages.  This filter
  # prevents names like "https_example.com_db" from being promoted as UWP
  # families.
  if ($s -match '^(https?|ftp)[_.]') { return $null }

  $lower = $s.ToLowerInvariant()

  # Skip anchors that contain generic browser cache or error-reporting
  # substrings.  These names (e.g. indexeddb, reportarchive, leveldb)
  # originate from browser cache or telemetry folders and are not
  # meaningful application identifiers.  Filtering them here prevents
  # them from appearing in the PathAnchors list or being promoted as
  # UWP families.
  if ($lower -match 'indexeddb|reportarchive|leveldb') { return $null }
  if ($StopWords -contains $lower) { return $null }

  # Treat the XboxGames root directory as a protected anchor.  The Xbox
  # application itself should not be removed, but games installed within
  # its content directories are still discoverable.  By filtering it here
  # we prevent the top-level folder name from being treated as an anchor
  # while still allowing deeper paths to surface as hits.
  if ($lower -eq 'xboxgames') { return $null }

  return $s
}


# Resolve-IndirectString
# UWP registry often stores DisplayName/Description as indirect resource strings (e.g. "@{...}" or "ms-resource:...").
# Explorer resolves these, but raw registry reads do not. This helper attempts to resolve them using SHLoadIndirectString.
$script:__IndirectResolverReady = $false
function Initialize-IndirectStringResolver {
  if ($script:__IndirectResolverReady) { return }
  try {
    Add-Type -Namespace Win32 -Name IndirectString -MemberDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class IndirectString {
  [DllImport("shlwapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, uint cchOutBuf, IntPtr pvReserved);
}
"@ -ErrorAction Stop | Out-Null
    $script:__IndirectResolverReady = $true
  } catch {
    $script:__IndirectResolverReady = $false
  }
}

function Resolve-IndirectString {
  param([string]$Value)
  if (-not $Value) { return $Value }
  $v = $Value.Trim()
  if ($v -notmatch '^(?i)(@\{|ms-resource:|ms-resource://)') { return $v }

  Initialize-IndirectStringResolver
  if (-not $script:__IndirectResolverReady) { return $v }

  try {
    $sb = New-Object System.Text.StringBuilder 2048
    $rc = [Win32.IndirectString]::SHLoadIndirectString($v, $sb, 2048, [IntPtr]::Zero)
    if ($rc -eq 0) {
      $out = $sb.ToString()
      if ($out -and $out.Trim()) { return $out.Trim() }
    }
  } catch { }
  return $v
}


function Get-ExeFromDisplayIcon {
  param([string]$displayIcon)

  if (-not $displayIcon) { return $null }

  $s = $displayIcon.Trim()
  if (-not $s) { return $null }

  # Common formats:
  #   "C:\Path\App.exe,0"
  #   C:\Path\App.exe,0
  #   "C:\Path\App.exe" --arg1 --arg2
  # We want the first existing file path, without quotes and without ",0"/arguments.
  $candidate = $null

  if ($s.StartsWith('"')) {
    # Grab the first quoted segment.
    $m = [regex]::Match($s, '^"(?<p>[^"]+)"')
    if ($m.Success) { $candidate = $m.Groups['p'].Value }
  }

  if (-not $candidate) {
    # If there is a comma suffix, keep the first part.
    $candidate = ($s -split ',')[0].Trim()
    # If there are arguments, keep the first token (ending in a typical executable extension).
    if ($candidate -match '^(?<p>[^\s]+\.(exe|dll|com|bat|cmd))\b') {
      $candidate = $Matches['p']
    }
  }

  if (-not $candidate) { return $null }

  # Remove any lingering quotes.
  $candidate = $candidate.Trim().Trim('"')

  try {
    if (-not (Test-Path -LiteralPath $candidate)) { return $null }
  } catch {
    return $null
  }

  return $candidate
}


function To-StringArray {
  param($v)
  if ($null -eq $v) { return @() }
  # If already an array (native .NET array), enumerate elements and coerce each to string
  if ($v -is [System.Array]) {
    $out = @()
    foreach ($i in $v) {
      if ($null -ne $i) { $out += $i.ToString() }
    }
    return $out
  }

  # If the value is an enumerable collection (e.g. ArrayList, List<T>) but not a string,
  # enumerate its items and convert each element to string.  This prevents collections
  # from being treated as a single scalar which would collapse multiple values into a
  # single concatenated string.
  if ($v -is [System.Collections.IEnumerable] -and ($v -isnot [string])) {
    $out = @()
    foreach ($i in $v) {
      if ($null -ne $i) { $out += $i.ToString() }
    }
    return $out
  }

  # Fallback: treat the value as a single scalar string.  Wrap in an array to
  # preserve array semantics downstream.
  @($v.ToString())
}

function UniqueNonEmpty {
  param([object]$arr)
  if ($null -eq $arr) { return @() }
  if ($arr -is [string]) {
    if ($arr) {
      return @($arr)
    } else {
      return @()
    }
  }
  if ($arr -isnot [System.Collections.IEnumerable]) {
    return @($arr)
  }
  $out = @()
  foreach ($item in $arr) {
    if ($item) { $out += $item }
  }
  $out | Sort-Object -Unique
}

function UniqueStrings {
  param([string[]]$arr)
  if (-not $arr) { return @() }
  ($arr | Where-Object { $_ } | Group-Object | ForEach-Object { $_.Name })
}

function Get-ArpEntryKey {
  param($Entry)

  if (-not $Entry) { return $null }

  $dn  = if ($Entry.DisplayName) { $Entry.DisplayName.ToString().Trim().ToLowerInvariant() } else { '' }
  $kv  = if ($Entry.KeyName) { $Entry.KeyName.ToString().Trim().ToLowerInvariant() } else { '' }
  $pub = if ($Entry.Publisher) { $Entry.Publisher.ToString().Trim().ToLowerInvariant() } else { '' }
  $ver = if ($Entry.DisplayVersion) { $Entry.DisplayVersion.ToString().Trim().ToLowerInvariant() } else { '' }
  $loc = if ($Entry.InstallLocation) { $Entry.InstallLocation.ToString().Trim().ToLowerInvariant() } else { '' }

  # Ignore hive/source path so HKCU and HKU\SID mirrors collapse to one entry.
  return "$dn|$kv|$pub|$ver|$loc"
}

function Get-UniqueArpEntries {
  param([object[]]$Entries)

  if (-not $Entries) { return @() }

  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $out = @()
  foreach ($e in $Entries) {
    if (-not $e) { continue }
    $k = Get-ArpEntryKey $e
    if (-not $k) { continue }
    if ($seen.Add($k)) { $out += $e }
  }

  return @($out)
}

function Get-UwpEntryKey {
  param($Entry)

  if (-not $Entry) { return $null }

  if ($Entry.PSObject.Properties['PackageFamilyName'] -and $Entry.PackageFamilyName) {
    return ('pfn:' + $Entry.PackageFamilyName.ToString().Trim().ToLowerInvariant())
  }
  if ($Entry.PSObject.Properties['PackageFullName'] -and $Entry.PackageFullName) {
    return ('pfnfull:' + $Entry.PackageFullName.ToString().Trim().ToLowerInvariant())
  }

  $name = if ($Entry.PSObject.Properties['Name'] -and $Entry.Name) { $Entry.Name.ToString().Trim().ToLowerInvariant() } else { '' }
  return ('name:' + $name)
}

function Get-UniqueUwpEntries {
  param([object[]]$Entries)

  if (-not $Entries) { return @() }

  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $out = @()
  foreach ($e in $Entries) {
    if (-not $e) { continue }
    $k = Get-UwpEntryKey $e
    if (-not $k) { continue }
    if ($seen.Add($k)) { $out += $e }
  }

  return @($out)
}

function Union-StringArrays {
  param($a,$b)
  # Always return an array, even when there are zero elements. Without wrapping, an empty
  # pipeline will return $null which can cause later union operations to concatenate
  # strings instead of building an array. Wrapping ensures we preserve array semantics.
  $out = @((To-StringArray $a) + (To-StringArray $b)) | Where-Object { $_ } | Sort-Object -Unique
  return @($out)
}


function Get-IdentityKey {
  param($Identity)

  if (-not $Identity) { return $null }

  $src = $null
  try { $src = $Identity.SourcePath } catch { $src = $null }
  if ($src) { return ('src:' + $src.ToString().ToLowerInvariant()) }

  $parts = @()
  foreach ($p in @('FileName','OriginalFilename','ProductName','CompanyName','CertThumbprint')) {
    $v = $null
    try { $v = $Identity.$p } catch { $v = $null }
    if ($v) { $parts += $v.ToString().ToLowerInvariant() } else { $parts += '' }
  }
  return ('meta:' + ($parts -join '|'))
}

function Get-UniqueIdentities {
  param([object[]]$Identities)

  if (-not $Identities) { return @() }
  $seen = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)
  $out  = New-Object System.Collections.Generic.List[object]

  foreach ($id in $Identities) {
    if (-not $id) { continue }
    $k = Get-IdentityKey $id
    if (-not $k) { continue }
    if ($seen.Add($k)) { [void]$out.Add($id) }
  }

  return @($out.ToArray())
}

function Get-AuthenticodeInfo {
  param([string]$Path)
  try {
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    if ($sig -and $sig.SignerCertificate) {
      $thumb  = $sig.SignerCertificate.Thumbprint
      $simple = $sig.SignerCertificate.Subject.Split(',')[0].Trim()
      $simple = $simple -replace '^CN\s*=\s*"?(.+?)"?$', '$1'
      return [pscustomobject]@{
        IsSigned       = ($sig.Status -eq 'Valid')
        CertThumbprint = $thumb
        SignerSimple   = $simple
      }
    }
  } catch {}
  [pscustomobject]@{
    IsSigned       = $false
    CertThumbprint = $null
    SignerSimple   = $null
  }
}

function Get-FileIdentityBasic {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path $Path)) { return $null }
  try {
    $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $sig = Get-AuthenticodeInfo $Path
    [pscustomobject]@{
      FileName         = (Split-Path $Path -Leaf)
      ProductName      = $fvi.ProductName
      FileDescription  = $fvi.FileDescription
      CompanyName      = $fvi.CompanyName
      OriginalFilename = $fvi.OriginalFilename
      ProductVersion   = $fvi.ProductVersion
      FileVersion      = $fvi.FileVersion
      IsSigned         = $sig.IsSigned
      CertThumbprint   = $sig.CertThumbprint
      SignerSimpleName = $sig.SignerSimple
      SourcePath       = $Path
    }
  } catch { $null }
}

function Get-ShortcutTarget {
  <#
    Resolve a .lnk file to its target path and arguments.
    Returns $null if not resolvable.
  #>
  param([Parameter(Mandatory=$true)][string]$LnkPath)
  try {
    if (-not (Test-Path -LiteralPath $LnkPath)) { return $null }
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($LnkPath)
    $t  = $sc.TargetPath
    $a  = $sc.Arguments
    if (-not $t) { return $null }
    [pscustomobject]@{ LinkPath=$LnkPath; TargetPath=$t; Arguments=$a }
  } catch {
    $null
  }
}

function Find-ExeViaStartMenu {
  <#
    Breadcrumb method for Win32 apps:
    Scan Start Menu .lnk files and follow matching shortcuts to their real exe targets.

    Returns a PSCustomObject:
      ExePath, Evidence (link name/path), Score
  #>
  param(
    [Parameter(Mandatory=$true)][string[]]$Tokens,
    [string]$UserProfilePath
  )

  $startDirs = @(
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
  )
  if ($UserProfilePath) {
    $startDirs += (Join-Path $UserProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
  }
  $startDirs = $startDirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
  if (-not $startDirs) { return $null }

  $badTargetPattern = '(?i)unins|uninstall|setup|install|updater|update|repair|remove|launcherhelper|crashreport|crashpad'
  $candidates = @()

  foreach ($sd in $startDirs) {
    $lnks = @()
    try { $lnks = Get-ChildItem -LiteralPath $sd -Filter *.lnk -File -Recurse -ErrorAction SilentlyContinue } catch {}
    foreach ($lnk in $lnks) {
      $linkName = [IO.Path]::GetFileNameWithoutExtension($lnk.Name)
      # Cheap prefilter on link name/path.
      if (-not (Matches-OrderedTokens -text $linkName -tokens $Tokens) -and -not (Matches-OrderedTokens -text $lnk.FullName -tokens $Tokens)) {
        continue
      }
      $t = Get-ShortcutTarget -LnkPath $lnk.FullName
      if (-not $t) { continue }

      # Store apps often launch through explorer.exe shell:AppsFolder\PFN!App.
      # For Win32 breadcrumbing we primarily want direct exe targets.
      if ($t.TargetPath -match '^explorer\.exe$') {
        continue
      }
      if ($t.TargetPath -match $badTargetPattern) {
        continue
      }

      if (-not (Test-Path -LiteralPath $t.TargetPath)) {
        continue
      }

      # Score: token match + shallow path preference.
      $score = 0
      if (Matches-OrderedTokens -text $linkName -tokens $Tokens) { $score += 30 }
      if (Matches-OrderedTokens -text $t.TargetPath -tokens $Tokens) { $score += 20 }

      # Prefer shallower paths (fewer separators after drive root)
      $depth = ($t.TargetPath -split '[\\/]').Count
      $score += [math]::Max(0, 30 - $depth)

      $candidates += [pscustomobject]@{
        ExePath  = $t.TargetPath
        Evidence = $lnk.FullName
        Score    = $score
      }
    }
  }

  if (-not $candidates -or $candidates.Count -eq 0) { return $null }
  $candidates | Sort-Object Score -Descending | Select-Object -First 1
}

function Select-BestExeInDirectory {
  <#
    Improved exe selection:
    - Avoid "fattest fish" selection.
    - Score executables based on:
        * token matches in file identity fields
        * shallower path depth
        * penalty for installer/auxiliary names
    Limits scan depth to reduce cost.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Dir,
    [Parameter(Mandatory=$true)][string[]]$Tokens
  )
  if (-not (Test-Path -LiteralPath $Dir)) { return $null }

  $badNamePattern = '(?i)unins|uninstall|setup|install|updater|update|repair|remove|crashreport|crashpad|helper|service'

  $exeList = @()
  try {
    # depth-limited: top + one subdir
    $exeList += Get-ChildItem -LiteralPath $Dir -Filter *.exe -File -ErrorAction SilentlyContinue
    $subdirs = Get-ChildItem -LiteralPath $Dir -Directory -ErrorAction SilentlyContinue
    foreach ($sd in $subdirs) {
      try { $exeList += Get-ChildItem -LiteralPath $sd.FullName -Filter *.exe -File -ErrorAction SilentlyContinue } catch {}
    }
  } catch {}

  if (-not $exeList -or $exeList.Count -eq 0) { return $null }

  $scored = @()
  foreach ($exe in $exeList) {
    $leaf = $exe.Name
    if ($leaf -match $badNamePattern) { continue }
    $id = Get-FileIdentityBasic $exe.FullName
    $score = 0
    if (Matches-OrderedTokens -text $leaf -tokens $Tokens) { $score += 25 }
    if ($id) {
      if ($id.ProductName -and (Matches-OrderedTokens -text $id.ProductName -tokens $Tokens)) { $score += 35 }
      if ($id.FileDescription -and (Matches-OrderedTokens -text $id.FileDescription -tokens $Tokens)) { $score += 35 }
      if ($id.OriginalFilename -and (Matches-OrderedTokens -text $id.OriginalFilename -tokens $Tokens)) { $score += 20 }
      if ($id.CompanyName -and (Matches-OrderedTokens -text $id.CompanyName -tokens $Tokens)) { $score += 10 }
    }
    $depth = ($exe.FullName -split '[\\/]').Count
    $score += [math]::Max(0, 30 - $depth)
    # Mild size bias (but no longer the primary selector)
    $score += [math]::Min([math]::Round($exe.Length / 1048576), 10)

    $scored += [pscustomobject]@{ Exe=$exe; Identity=$id; Score=$score }
  }

  if (-not $scored -or $scored.Count -eq 0) { return $null }
  $scored | Sort-Object Score -Descending | Select-Object -First 1
}

function Clean-CompactText {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $s = ($s -replace '[\r\n\t]+',' ') -replace '\s{2,}',' '
  $s = $s.Trim()
  if ($s.Length -eq 0) { return $null }
  return $s
}

function Join-CleanedList {
  param([object]$items)

  $arr = @()
  foreach ($i in (To-StringArray $items)) {
    $c = Clean-CompactText $i
    if ($c) { $arr += $c }
  }

  $arr = $arr | Sort-Object -Unique
  if ($arr.Count -eq 0) { return $null }
  return ($arr -join ', ')
}

function Normalize-InstallerSignature {
  param($sig)
  if (-not $sig) { return $null }

  foreach ($p in 'ProductName','CompanyName','OriginalFilename','CertThumbprint','SignerSimpleName','InstallerFileName','InstallerPath') {
    if ($sig.PSObject.Properties[$p]) {
      $sig.$p = Clean-CompactText ([string]$sig.$p)
      if ($p -eq 'OriginalFilename' -and $sig.$p) {
        $sig.$p = Strip-DuplicateSuffix $sig.$p
      }
    }
  }

  if ($sig.PSObject.Properties['FileDescriptions']) {
    $sig.FileDescriptions = Normalize-FileDescriptions -Value $sig.FileDescriptions
  }
  return $sig
}

function Build-InstallerSignature {
  param([object[]]$ids)
  $ids = @($ids | Where-Object { $_ })
  $prodNames = $ids | ForEach-Object { $_.ProductName }
  $coNames   = $ids | ForEach-Object { $_.CompanyName }
  $origFiles = $ids | ForEach-Object { $_.OriginalFilename }
  $thumbs    = $ids | ForEach-Object { $_.CertThumbprint }
  $descs     = $ids | ForEach-Object { $_.FileDescription }
  $signers   = $ids | ForEach-Object { $_.SignerSimpleName }
  $fileNames = $ids | ForEach-Object { $_.FileName }
  $srcPaths  = $ids | ForEach-Object { $_.SourcePath }
  $prodNames = @(UniqueStrings $prodNames)
  $coNames   = @(UniqueStrings $coNames)
  $origFiles = @(UniqueStrings $origFiles)
  $thumbs    = @(UniqueStrings $thumbs)
  $descs     = @(UniqueStrings $descs)
  $signers   = @(UniqueStrings $signers)
  $fileNames = @(UniqueStrings $fileNames)
  $srcPaths  = @(UniqueStrings $srcPaths)
  $prod = $null; if ($prodNames.Count -gt 0) { $prod = $prodNames[0] }
  $co   = $null; if ($coNames.Count   -gt 0) { $co   = $coNames[0] }
  $orig = $null; if ($origFiles.Count -gt 0) { $orig = $origFiles[0] }
  $thumb= $null; if ($thumbs.Count    -gt 0) { $thumb= $thumbs[0] }
  $sign = $null; if ($signers.Count   -gt 0) { $sign = $signers[0] }
  $file = $null; if ($fileNames.Count -gt 0) { $file = $fileNames[0] }
  $path = $null; if ($srcPaths.Count  -gt 0) { $path = $srcPaths[0] }
  Normalize-InstallerSignature ([pscustomobject]@{
    ProductName      = $prod
    CompanyName      = $co
    OriginalFilename = $orig
    CertThumbprint   = $thumb
    SignerSimpleName = $sign
    InstallerFileName= $file
    InstallerPath    = $path
    FileDescriptions = $descs
  })
}

function Merge-InstallerSignature {
  param($old,$new)
  if ($null -eq $old) { return $new }
  if ($null -eq $new) { return $old }
  $prod = $old.ProductName
  if ($new.ProductName) {
    if (-not $prod -or ($new.ProductName.Length -gt $prod.Length)) { $prod = $new.ProductName }
  }
  $co = $old.CompanyName
  if ($new.CompanyName) {
    if (-not $co -or ($new.CompanyName.Length -gt $co.Length)) { $co = $new.CompanyName }
  }
  $orig = $old.OriginalFilename
  if ($new.OriginalFilename) {
    if (-not $orig -or ($new.OriginalFilename.Length -gt $orig.Length)) { $orig = $new.OriginalFilename }
  }
  $thumb = $old.CertThumbprint
  if ($new.CertThumbprint) {
    if (-not $thumb -or ($new.CertThumbprint.Length -gt $thumb.Length)) { $thumb = $new.CertThumbprint }
  }
  $sign = $old.SignerSimpleName
  if ($new.SignerSimpleName) {
    if (-not $sign -or ($new.SignerSimpleName.Length -gt $sign.Length)) { $sign = $new.SignerSimpleName }
  }
  $ifn = $old.InstallerFileName
  if ($new.InstallerFileName) {
    if (-not $ifn -or ($new.InstallerFileName.Length -gt $ifn.Length)) { $ifn = $new.InstallerFileName }
  }
  $ipath = $old.InstallerPath
  if ($new.InstallerPath) {
    if (-not $ipath -or ($new.InstallerPath.Length -gt $ipath.Length)) { $ipath = $new.InstallerPath }
  }

  $descsOld = To-StringArray $old.FileDescriptions
  $descsNew = To-StringArray $new.FileDescriptions
  $descs = if ($descsNew.Count -gt 0) { UniqueStrings $descsNew } else { UniqueStrings $descsOld }

  return (Normalize-InstallerSignature ([pscustomobject]@{
    ProductName      = $prod
    CompanyName      = $co
    OriginalFilename = $orig
    CertThumbprint   = $thumb
    SignerSimpleName = $sign
    InstallerFileName= $ifn
    InstallerPath    = $ipath
    FileDescriptions = $descs
  }))
}

function Find-ArpMatchesByTokens {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$arpAll,

        [Parameter(Mandatory = $true)]
        [string]$name,

        [switch]$DebugMode
    )

    $hits = @()

    if (-not $arpAll -or [string]::IsNullOrWhiteSpace($name)) {
        if ($DebugMode) {
            Write-Host "ARP DEBUG: no ARP entries or empty name, skipping ARP matching." -ForegroundColor Yellow
        }
        return ,$hits
    }

    $tokens = Get-NameTokens $name

    # Require at least one non-trivial token
    if (-not (Is-StrongTokenSet $tokens)) {
        if ($DebugMode) {
            Write-Host "ARP DEBUG: token set for '$name' is not considered strong; skipping ARP search." -ForegroundColor Yellow
        }
        return ,$hits
    }

    foreach ($e in $arpAll) {
        if (-not $e) { continue }

        # Build a list of text fields to test against the search tokens.  In addition
        # to the DisplayName, KeyName, and InstallLocation, include the Publisher
        # value.  Some installers set the vendor in Publisher even when the
        # display name is generic.  Adding Publisher improves hit rates
        # without changing existing behaviour.
        $texts = @()
        if ($e.DisplayName)     { $texts += $e.DisplayName }
        if ($e.KeyName)         { $texts += $e.KeyName }
        if ($e.InstallLocation) { $texts += $e.InstallLocation }
        if ($e.Publisher)       { $texts += $e.Publisher }

        $hit = $false
        # Primary match: ordered token matching using the existing helper.  This
        # requires the tokens to appear in order within the text.  If this
        # match succeeds we skip the fallback.
        foreach ($t in $texts) {
            if ($t -and (Matches-OrderedTokens -text $t -tokens $tokens)) {
                $hit = $true
                break
            }
        }
        # Fallback match: require all tokens to appear somewhere in the text
        # regardless of order.  This helps catch cases where the display name
        # includes the tokens but the ordering or punctuation prevents
        # Matches-OrderedTokens from triggering (e.g. vendor names like 'Rovio
        # Entertainment Oy' and titles like 'Angry Birds 2').
        if (-not $hit) {
            foreach ($t in $texts) {
                if (-not $t) { continue }
                if (Contains-AllTokensBoundary -text $t -tokens $tokens) {
                    $hit = $true
                    break
                }
            }
        }

        # Additional fallback: perform a simple case‑insensitive substring
        # match on the entire search phrase.  This helps catch cases where
        # the ordered token logic fails because of punctuation or numbers in
        # the display name (e.g. 'Angry Birds 2' when searching for
        # 'Angry Birds').
        if (-not $hit -and $tokens.Count -eq 1 -and $tokens[0] -and $tokens[0].Length -ge 4) {
            # Safe single-token fallback: require a word-start boundary.
            $pattern = '(?i)(?<![a-z0-9])' + [regex]::Escape($tokens[0]) + '[a-z0-9]*'
            foreach ($t in $texts) {
                if (-not $t) { continue }
                if ([regex]::IsMatch($t.ToString(), $pattern)) {
                    $hit = $true
                    break
                }
            }
        }

        if ($hit) {
            $dn = if ($e.DisplayName) { $e.DisplayName } else { $e.KeyName }

            if ($dn -and $dn -match 'Minecraft.*Education') { continue }

            if ($DebugMode) {
                Write-Host ("ARP DEBUG: matched '{0}' (Key='{1}')" -f $dn, $e.KeyName) -ForegroundColor DarkYellow
            }

            $hits += $e
        }
    }

    ,$hits
}


function Find-ArpMatchesStaged {
    <#
      Staged ARP search:
        Stage 1: ordered token match (fast, precise)
        Stage 2: boundary all-tokens match (still precise, more tolerant)
        Stage 3: single-token word-start match (e.g. "Steam" => "Steam*" but not "*Steam")
        Stage 4: alpha-only contains match (slowest / loosest; last resort)
      Returns the first non-empty hit set to keep runtime efficient.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$arpAll,
        [Parameter(Mandatory = $true)][string]$name,
        [ref]$StageUsed,
        [switch]$DebugMode
    )

    $StageUsed.Value = $null
    if (-not $arpAll) { return @() }

    $tokens = Get-NameTokens $name
    if (-not (Is-StrongTokenSet $tokens)) { return @() }

    # Stage 1 (existing primary logic)
    $hits = @()
    foreach ($e in $arpAll) {
        if (-not $e) { continue }
        $texts = @()
        if ($e.DisplayName)     { $texts += $e.DisplayName }
        if ($e.KeyName)         { $texts += $e.KeyName }
        if ($e.InstallLocation) { $texts += $e.InstallLocation }
        if ($e.Publisher)       { $texts += $e.Publisher }

        $hit = $false
        foreach ($t in $texts) {
            if ($t -and (Matches-OrderedTokens -text $t -tokens $tokens)) { $hit = $true; break }
        }
        if ($hit) { $hits += $e }
    }
    if ($hits.Count -gt 0) { $StageUsed.Value = 1; return ,$hits }

    # Stage 2 (boundary all tokens, any order)
    $hits = @()
    foreach ($e in $arpAll) {
        if (-not $e) { continue }
        $texts = @()
        if ($e.DisplayName)     { $texts += $e.DisplayName }
        if ($e.KeyName)         { $texts += $e.KeyName }
        if ($e.InstallLocation) { $texts += $e.InstallLocation }
        if ($e.Publisher)       { $texts += $e.Publisher }

        $hit = $false
        foreach ($t in $texts) {
            if (-not $t) { continue }
            if (Contains-AllTokensBoundary -text $t -tokens $tokens) { $hit = $true; break }
        }
        if ($hit) { $hits += $e }
    }
    if ($hits.Count -gt 0) { $StageUsed.Value = 2; return ,$hits }

    # Stage 3 (safe single-token word-start; prevents Steam => MSTeams)
    if ($tokens.Count -eq 1 -and $tokens[0] -and $tokens[0].Length -ge 4) {
        $needle = $tokens[0]
        $pattern = '(?i)(?<![a-z0-9])' + [regex]::Escape($needle) + '[a-z0-9]*'
        $hits = @()
        foreach ($e in $arpAll) {
            if (-not $e) { continue }
            $texts = @()
            if ($e.DisplayName) { $texts += $e.DisplayName }
            if ($e.KeyName)     { $texts += $e.KeyName }

            $hit = $false
            foreach ($t in $texts) {
                if (-not $t) { continue }
                if ([regex]::IsMatch($t.ToString(), $pattern)) { $hit = $true; break }
            }
            if ($hit) { $hits += $e }
        }
        if ($hits.Count -gt 0) { $StageUsed.Value = 3; return ,$hits }
    }

    # Stage 4 (alpha-only contains; last resort)
    $needleAlpha = ToAlpha $name
    if ($needleAlpha) {
        $hits = @()
        foreach ($e in $arpAll) {
            if (-not $e) { continue }
            foreach ($s in @($e.DisplayName, $e.KeyName, $e.InstallLocation)) {
                if (-not $s) { continue }
                $alpha = ToAlpha $s
                if ($alpha -and $alpha.Contains($needleAlpha)) { $hits += $e; break }
            }
        }
        if ($hits.Count -gt 0) { $StageUsed.Value = 4; return ,$hits }
    }

    @()
}


function Get-PackageFamilyFromFullName {
  param([string]$packageFullName)
  if (-not $packageFullName) { return $null }
  $parts = $packageFullName -split '_'
  if ($parts.Count -ge 2) { return ($parts[0] + '_' + $parts[-1]) }
  return $packageFullName
}

function Is-OpaqueUwpName {
  param([string]$s)
  if (-not $s) { return $false }
  $t = $s.Trim()
  if (-not $t) { return $false }
  if ($t -match '\s') { return $false } # spaces usually mean human-friendly
  if ($t -match '^[A-Z0-9]+(\.[A-Z0-9]+)+$') { return $true }  # VENDOR.APP style
  if ($t -match '^[A-Z0-9\.]{8,}$' -and $t -match '\.') { return $true }
  return $false
}

function Find-UwpByBackgroundTasksTokens_RegExe {
  <#
    reg.exe fallback for BackgroundTasks discovery.
    Some environments (notably SYSTEM context or provider quirks) fail to
    enumerate HKCR/HKLM Classes keys reliably via the PowerShell registry provider.
    reg.exe query is slower but far more consistent.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$name
  )

  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }

  $roots = @(
    'HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId'
  )

  $hits = @()

  foreach ($root in $roots) {
    $lines = @()
    try { $lines = & reg.exe query $root /s 2>$null } catch { $lines = @() }
    if (-not $lines -or $lines.Count -eq 0) { continue }

    $curKey = $null
    $display = $null; $desc = $null; $vendor = $null; $pkgFullName = $null

    foreach ($line in $lines) {
      if (-not $line) { continue }

      if ($line -match '^HKEY_') {
        # Flush previous block
        if ($curKey -and $pkgFullName) {
          $cands = @($display, $desc, $vendor, $pkgFullName) | Where-Object { $_ }
          $matched = $false
          foreach ($c in $cands) {
            if (Matches-OrderedTokens -text $c -tokens $tokens) { $matched = $true; break }
          }
          if (-not $matched) {
            foreach ($c in $cands) {
              if (-not $c) { continue }
              if (Contains-AllTokensBoundary -text $c -tokens $tokens) { $matched = $true; break }
            }
          }
          if ($matched) {
            $pfn = Get-PackageFamilyFromFullName $pkgFullName
            $hits += [pscustomobject]@{
              Name                 = $(if ($display) { $display } else { $name })
              Description          = $desc
              PackageFamilyName    = $pfn
              PackageFullName      = $pkgFullName
              PublisherDisplayName = $vendor
              RegistryDisplayName  = $display
              Source               = 'Registry-BackgroundTasks-RegExe'
            }
          }
        }

        # Reset for new key
        $curKey = $line.Trim()
        $display = $null; $desc = $null; $vendor = $null; $pkgFullName = $null
        if ($curKey -match '\\PackageId\\([^\\]+)(\\|$)') { $pkgFullName = $matches[1] }
        continue
      }

      if ($line -match '^\s*DisplayName\s+REG_\w+\s+(.*)$') { $display = Resolve-IndirectString $matches[1].Trim() ; continue }
      if ($line -match '^\s*Description\s+REG_\w+\s+(.*)$') { $desc = Resolve-IndirectString $matches[1].Trim() ; continue }
      if ($line -match '^\s*Vendor\s+REG_\w+\s+(.*)$') { $vendor = Resolve-IndirectString $matches[1].Trim() ; continue }
    }

    # Flush final block
    if ($curKey -and $pkgFullName) {
      $cands = @($display, $desc, $vendor, $pkgFullName) | Where-Object { $_ }
      $matched = $false
          foreach ($c in $cands) {
            if (Matches-OrderedTokens -text $c -tokens $tokens) { $matched = $true; break }
          }
          if (-not $matched) {
            foreach ($c in $cands) {
              if (-not $c) { continue }
              if (Contains-AllTokensBoundary -text $c -tokens $tokens) { $matched = $true; break }
            }
          }
          if ($matched) {
        $pfn = Get-PackageFamilyFromFullName $pkgFullName
        $hits += [pscustomobject]@{
          Name                 = $(if ($display) { $display } else { $name })
          Description          = $desc
          PackageFamilyName    = $pfn
          PackageFullName      = $pkgFullName
          PublisherDisplayName = $vendor
          RegistryDisplayName  = $display
          Source               = 'Registry-BackgroundTasks-RegExe'
        }
      }
    }
  }

  if ($hits.Count -gt 0) {
    # De-dupe by PFN
    $out = @()
    foreach ($h in $hits) {
      if (-not $h.PackageFamilyName) { continue }
      if (-not ($out | Where-Object { $_.PackageFamilyName -eq $h.PackageFamilyName })) {
        $out += $h
      }
    }
    return $out
  }

  return @()
}


function Find-UwpByContractIdTokens_RegExe {
  <#
    Deep registry fallback for "special" Store/UWP packages that do not show up
    reliably via Get-AppxPackage / Appx provider views from SYSTEM.
    We intentionally stage the scan:
      Stage 1: Windows.BackgroundTasks PackageId subtree (fastest / most common)
      Stage 2: Full HKCR Extensions\ContractId scan (slow; last resort)
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$name,
    [int]$MaxLines = 0,
    [switch]$DebugMode
  )

  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }

  function _Match-AnyText {
    param([string[]]$Texts)
    foreach ($t in $Texts) {
      if (-not $t) { continue }
      if (Matches-OrderedTokens -text $t -tokens $tokens) { return $true }
      if (Contains-AllTokensBoundary -text $t -tokens $tokens) { return $true }
      if ($tokens.Count -eq 1 -and $tokens[0].Length -ge 4) {
        $pat = '(?i)(?<![a-z0-9])' + [regex]::Escape($tokens[0]) + '[a-z0-9]*'
        if ([regex]::IsMatch($t, $pat)) { return $true }
      }
    }
    return $false
  }

  function _Scan-RegText {
    param([string[]]$Lines, [string]$SourceTag)

    $hits = @()
    $curKey = $null
    $display = $null

    foreach ($line in $Lines) {
      if (-not $line) { continue }

      # Key lines begin with HKEY...
      if ($line -match '^(HKEY_[A-Z_\\]+)$') {
        # finalize prior key
        if ($curKey) {
          if (_Match-AnyText -Texts @($display, $curKey)) {
            $pfn = $null
            if ($curKey -match '\\PackageId\\([^\\]+)') { $pfn = $Matches[1] }
            if (-not $pfn) { $pfn = $curKey }

            $pkgFull = $pfn
            $pkgFam  = Get-PackageFamilyFromFullName $pkgFull

            $obj = [pscustomobject]@{
              Source            = $SourceTag
              RegistryKey       = $curKey
              DisplayName       = $display
              PackageFullName   = $pkgFull
              PackageFamilyName = $pkgFam
            }
            $hits += $obj
          }
        }

        $curKey = $line.Trim()
        $display = $null
        continue
      }

      # Values: DisplayName REG_SZ data OR DisplayName REG_EXPAND_SZ ...
      if ($line -match '^\s*DisplayName\s+REG_\w+\s+(.+)$') {
        $display = $Matches[1].Trim()
        try { $display = Resolve-IndirectString $display } catch {}
        continue
      }
    }

    # finalize last key
    if ($curKey) {
      if (_Match-AnyText -Texts @($display, $curKey)) {
        $pfn = $null
        if ($curKey -match '\\PackageId\\([^\\]+)') { $pfn = $Matches[1] }
        if (-not $pfn) { $pfn = $curKey }
        $pkgFull = $pfn
        $pkgFam  = Get-PackageFamilyFromFullName $pkgFull
        $hits += [pscustomobject]@{
          Source            = $SourceTag
          RegistryKey       = $curKey
          DisplayName       = $display
          PackageFullName   = $pkgFull
          PackageFamilyName = $pkgFam
        }
      }
    }

    return ,$hits
  }

  # Stage 1: BackgroundTasks PackageId (HKCR + explicit HKLM/HKCU classes)
  $roots = @(
    'HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId',
    'HKLM\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId',
    'HKCU\Software\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId'
  )

  foreach ($root in $roots) {
    try {
      $out = & reg.exe query $root /s 2>$null
      if ($out) {
        $lines = @($out)
        if ($MaxLines -gt 0 -and $lines.Count -gt $MaxLines) {
          $lines = $lines[0..($MaxLines-1)]
        }
        $hits = _Scan-RegText -Lines $lines -SourceTag ("ContractId:" + $root)
        if ($hits -and $hits.Count -gt 0) { return ,$hits }
      }
    } catch {}
  }

  # Stage 2: Full ContractId scan (slow) – only if the fast scan returned nothing
  try {
    $out2 = & reg.exe query 'HKCR\Extensions\ContractId' /s 2>$null
    if ($out2) {
      $lines2 = @($out2)
      if ($MaxLines -gt 0 -and $lines2.Count -gt $MaxLines) {
        $lines2 = $lines2[0..($MaxLines-1)]
      }
      $hits2 = _Scan-RegText -Lines $lines2 -SourceTag 'ContractId:HKCR\Extensions\ContractId'
      if ($hits2 -and $hits2.Count -gt 0) { return ,$hits2 }
    }
  } catch {}

  @()
}


function Find-UwpByBackgroundTasksTokens {
  <#
    Scan HKCR/HKLM Classes for UWP packages registered for background tasks:
      HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\<PackageFullName>\ActivatableClassId\<...>
    This location commonly contains DisplayName/Description/Vendor even when
    AppModel\Repository entries are absent or access-restricted.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$name
  )

  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }

  $roots = @(
    'Registry::HKEY_CLASSES_ROOT\Extensions\ContractId\Windows.BackgroundTasks\PackageId',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId'
  )

  $hits = @()

  foreach ($root in $roots) {
    try {
      $pkgKeys = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)
      foreach ($pkgKey in $pkgKeys) {
        $pkgFullName = $pkgKey.PSChildName
        if (-not $pkgFullName) { continue }

        $actRoot = Join-Path $pkgKey.PSPath 'ActivatableClassId'
        $actKeys = @()
        try { $actKeys = @(Get-ChildItem -Path $actRoot -ErrorAction SilentlyContinue) } catch {}
        if (-not $actKeys -or $actKeys.Count -eq 0) { $actKeys = @($pkgKey) } # fallback to package key

        foreach ($k in $actKeys) {
          $props = $null
          try { $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue } catch {}
          $display = $null; $desc = $null; $vendor = $null
          if ($props) {
            if ($props.PSObject.Properties['DisplayName']) { $display = Resolve-IndirectString $props.DisplayName }
            if ($props.PSObject.Properties['Description']) { $desc = $props.Description }
            if ($props.PSObject.Properties['Vendor'])      { $vendor = $props.Vendor }
          }

          $candidates = @()
          if ($display) { $candidates += $display }
          if ($desc)    { $candidates += $desc }
          if ($vendor)  { $candidates += $vendor }
          $candidates += $pkgFullName
          $candidates = $candidates | Where-Object { $_ } | Sort-Object -Unique

          $matched = $false
          foreach ($c in $candidates) {
            if (Matches-OrderedTokens -text $c -tokens $tokens) { $matched = $true; break }
          }
          if (-not $matched) {
            foreach ($c in $candidates) {
              if (-not $c) { continue }
              if (Contains-AllTokensBoundary -text $c -tokens $tokens) { $matched = $true; break }
            }
          }
          if (-not $matched) { continue }
          $pfn = Get-PackageFamilyFromFullName $pkgFullName
          $hits += [pscustomobject]@{
            Name                 = $(if ($display) { $display } else { $name })
            Description          = $desc
            PackageFamilyName    = $pfn
            PackageFullName      = $pkgFullName
            PublisherDisplayName = $vendor
            RegistryDisplayName  = $display
            Source               = 'Registry-BackgroundTasks'
          }
        }
      }
    } catch {}
  }

  # reg.exe fallback (provider enumeration is unreliable in some contexts).
  if ($hits.Count -eq 0) {
    try { $hits += Find-UwpByBackgroundTasksTokens_RegExe -name $name } catch {}
  }

  if ($hits.Count -gt 0) {
    # De-dupe by PFN
    $out = @()
    foreach ($h in $hits) {
      if (-not $h.PackageFamilyName) { continue }
      $exists = $false
      foreach ($o in $out) {
        if ($o.PackageFamilyName -eq $h.PackageFamilyName) { $exists = $true; break }
      }
      if (-not $exists) { $out += $h }
    }
    return $out
  }

  return @()
}

function Find-UwpByTokens {
  param(
    [string]$name,
    [string]$activeSid
  )
  $results = @()
  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return $results }
  $pkgs = @()
  # In Windows PowerShell 5.1 the -User parameter on Get-AppxPackage accepts a username,
  # not a SID, so we avoid using it here. Instead, enumerate packages for all users,
  # then fall back to the current user context if needed.
  try {
    $pkgs += Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
  } catch {}
  try {
    $pkgs += Get-AppxPackage -ErrorAction SilentlyContinue
  } catch {}
  # Include registry-discovered packages as a secondary source.
  try {
    $pkgs += Find-UwpByRegistryTokens -name $name -activeSid $activeSid
  } catch {}
  # Also scan BackgroundTasks registrations; these often carry DisplayName/Description
  # even when the main AppModel repositories are missing or access-restricted.
  try {
    $pkgs += Find-UwpByBackgroundTasksTokens -name $name
  } catch {}
  if (-not $pkgs) { return $results }
  foreach ($p in $pkgs) {
    # Build a list of candidate text fields.  Include Name, PackageFamilyName,
    # PublisherDisplayName, Description and Publisher.  Some Store packages
    # set only the publisher property or omit a display name entirely; by
    # including Publisher we improve hit rates without changing existing
    # behaviour.
    # Include RegistryDisplayName for registry-derived packages (e.g. games with opaque PFN).
    $texts = @($p.Name, $p.PackageFamilyName, $p.PublisherDisplayName, $p.Description, $p.RegistryDisplayName)
    if ($p.Publisher) { $texts += $p.Publisher }
    $hit = $false
    # Primary match: ordered token matching using the Matches-OrderedTokens
    # helper.  This preserves the original matching semantics.
    foreach ($t in $texts) {
      if ($t -and (Matches-OrderedTokens -text $t -tokens $tokens)) {
        $hit = $true
        break
      }
    }
    # Fallback match: require all tokens to appear somewhere in the text
    # regardless of order.  This assists in scenarios where the package
    # display name contains the tokens but the order or spacing prevents
    # ordered matching (e.g. certain game titles or vendor tags).
    if (-not $hit) {
      foreach ($t in $texts) {
        if (-not $t) { continue }
        if (Contains-AllTokensBoundary -text $t -tokens $tokens) {
          $hit = $true
          break
        }
      }
    }

    # Additional fallback: perform a simple case‑insensitive substring
    # match on the entire search phrase.  This helps catch cases where
    # the ordered token logic fails because of punctuation or numbers in
    # the display name (e.g. 'Angry Birds 2' when searching for
    # 'Angry Birds').
    if (-not $hit -and $tokens.Count -eq 1 -and $tokens[0] -and $tokens[0].Length -ge 4) {
      $pattern = '(?i)(?<![a-z0-9])' + [regex]::Escape($tokens[0]) + '[a-z0-9]*'
      foreach ($t in $texts) {
        if (-not $t) { continue }
        if ([regex]::IsMatch($t.ToString(), $pattern)) {
          $hit = $true
          break
        }
      }
    }
    # Additional fallback for multi-token phrases: match collapsed token forms within candidate texts.
    if (-not $hit) {
      $flatTokens = @()
      if ($tokens -and $tokens.Count -gt 1) {
        $concat = ($tokens -join '').ToLowerInvariant()
        if ($concat.Length -ge 6) { $flatTokens += $concat }
        $concatNoDigits = ($concat -replace '\d','')
        if ($concatNoDigits -and $concatNoDigits.Length -ge 6) { $flatTokens += $concatNoDigits }
      }
      if ($flatTokens.Count -gt 0) {
        foreach ($ft in $flatTokens) {
          foreach ($txt in $texts) {
            if (-not $txt) { continue }
            $cAlpha = ToAlpha $txt
            if ($cAlpha -and ($cAlpha.ToLowerInvariant().Contains($ft))) {
              $hit = $true
              break
            }
          }
          if ($hit) { break }
        }
      }
    }
    if ($hit) {
      # Skip protected UWP packages by name or family.
      $skipEntry = $false
      # Determine candidate name and family fields on the package object.  Not all
      # packages expose the same property names, so try common ones in order.
      $pkgNameField = $null
      if ($p.PSObject.Properties['Name']) { $pkgNameField = $p.Name }
      if (-not $pkgNameField -and $p.PSObject.Properties['PackageFamilyName']) { $pkgNameField = $p.PackageFamilyName }
      $pkgFamilyField = $null
      if ($p.PSObject.Properties['PackageFamilyName']) { $pkgFamilyField = $p.PackageFamilyName }
      if ($pkgNameField) {
        foreach ($__pn in $ProtectedUwpNames) {
          if ($__pn -and ($pkgNameField -eq $__pn)) { $skipEntry = $true; break }
        }
      }
      if (-not $skipEntry -and $pkgFamilyField) {
        foreach ($__pf in $ProtectedUwpFamilies) {
          if ($__pf -and ($pkgFamilyField -eq $__pf)) { $skipEntry = $true; break }
        }
      }
      if (-not $skipEntry) {
        $results += $p
      }
    }
  }
  $results
}

function Invoke-UserContextUwpScan {
  <#
    Runs a UWP-only scan in the currently active *interactive* user context (via schtasks /IT),
    and returns the discovered UWP hits as objects (ConvertFrom-Json).

    This is a fallback when SYSTEM-context UWP + ARP searches return no matches.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$SearchName,
    [Parameter()][int]$TimeoutSeconds = 75,
    [Parameter()][string]$ScriptPath,
    [Parameter(Mandatory=$true)][object]$Active
  )

  try {
    if (-not $ScriptPath) {
      $ScriptPath = $PSCommandPath
      if (-not $ScriptPath) { $ScriptPath = $MyInvocation.MyCommand.Path }
    }

    if (-not $Active) { return @() }

    # Determine the user to run as (must be an interactive session user)
    $runUser = $null
    if ($Active.PSObject.Properties.Name -contains 'Username') { $runUser = $Active.Username }
    if (-not $runUser -and ($Active.PSObject.Properties.Name -contains 'UserName')) { $runUser = $Active.UserName }
    if (-not $runUser) { return @() }

    # Where the user-context run will emit JSON
    $outJson = Join-Path $env:TEMP ("recognizer_useruwp_{0}.json" -f ([Guid]::NewGuid().ToString('N')))
    try { Remove-Item -LiteralPath $outJson -Force -ErrorAction SilentlyContinue } catch {}

    # Make a PowerShell command that is immune to schtasks quoting issues by using -EncodedCommand.
    $safeScript = $ScriptPath.Replace("'", "''")
    $safeName   = $SearchName.Replace("'", "''")
    $safeOut    = $outJson.Replace("'", "''")
    $psInner    = "& '$safeScript' -AppName '$safeName' -UserUwpOnly -OutJson '$safeOut'"

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($psInner)
    $b64   = [System.Convert]::ToBase64String($bytes)

    $pwsh  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $tr    = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -EncodedCommand $b64"

    # Schedule task to run 1 minute from now (schtasks requires HH:mm in local time)
    $dt = (Get-Date).AddMinutes(1)
    $st = $dt.ToString('HH:mm')

    $taskName = "Recognizer_UwpUserScan_{0}" -f ([Guid]::NewGuid().ToString('N'))

    $createArgs = @('/Create','/F','/TN',$taskName,'/SC','ONCE','/ST',$st,'/RL','LIMITED','/RU',$runUser,'/IT','/TR',$tr)
    $null = & schtasks.exe @createArgs 2>$null

    $runArgs = @('/Run','/TN',$taskName)
    $null = & schtasks.exe @runArgs 2>$null

    # Wait for the user-context scan to emit its JSON
    $deadline = (Get-Date).AddSeconds([Math]::Max(5,$TimeoutSeconds))
    while ((Get-Date) -lt $deadline) {
      if (Test-Path -LiteralPath $outJson) {
        try {
          $fi = Get-Item -LiteralPath $outJson -ErrorAction SilentlyContinue
          if ($fi -and $fi.Length -gt 10) { break }
        } catch {}
      }
      Start-Sleep -Milliseconds 500
    }

    # Cleanup task
    $deleteArgs = @('/Delete','/F','/TN',$taskName)
    $null = & schtasks.exe @deleteArgs 2>$null

    if (-not (Test-Path -LiteralPath $outJson)) { return @() }

    try {
      $raw = Get-Content -LiteralPath $outJson -Raw -ErrorAction Stop
      if (-not $raw) { return @() }
      $obj = $raw | ConvertFrom-Json -ErrorAction Stop
      if ($null -eq $obj) { return @() }
      if ($obj -is [System.Array]) { return @($obj) }
      return @($obj)
    } catch {
      return @()
    } finally {
      try { Remove-Item -LiteralPath $outJson -Force -ErrorAction SilentlyContinue } catch {}
    }
  }
  catch {
    return @()
  }
}


function Find-UwpByStartApps {
  <#
    DisplayName-focused UWP discovery for the *current interactive user*.

    Get-StartApps returns resolved Start Menu names. For Store apps whose package names
    are opaque (e.g., '1ED5AEA5.4160926B82DB_...') and/or whose registry values are
    indirect resource strings, this method is often the only reliable source that
    contains the human-friendly title.

    We extract PackageFamilyName from AppID by taking the portion before '!'.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Name
  )

  $tokens = Get-NameTokens $Name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }

  $apps = @()
  try { $apps = @(Get-StartApps -ErrorAction SilentlyContinue) } catch { $apps = @() }
  if (-not $apps -or $apps.Count -eq 0) { return @() }

  $hits = @()
  foreach ($a in $apps) {
    $dn = $null
    $id = $null
    try { $dn = $a.Name } catch {}
    try { $id = $a.AppID } catch {}
    if (-not $dn -or -not $id) { continue }

    $matched = $false
    if (Matches-OrderedTokens -text $dn -tokens $tokens) { $matched = $true }
    elseif (Contains-AllTokensBoundary -text $dn -tokens $tokens) { $matched = $true }

    if (-not $matched) { continue }

    $pfn = $id.Split('!')[0]
    if (-not $pfn) { continue }

    $hits += [pscustomobject]@{
      Name                 = $dn
      PackageFamilyName    = $pfn
      PackageFullName      = $null
      PublisherDisplayName = $null
      Description          = $null
      RegistryDisplayName  = $dn
      Source               = 'StartApps'
    }
  }

  # De-dupe by PFN
  if ($hits.Count -gt 1) {
    $out = @()
    foreach ($h in $hits) {
      $exists = $false
      foreach ($o in $out) { if ($o.PackageFamilyName -eq $h.PackageFamilyName) { $exists = $true; break } }
      if (-not $exists) { $out += $h }
    }
    return $out
  }

  return $hits
}

function Invoke-UserUwpOnlyMode {
  param(
    [Parameter(Mandatory=$true)][string]$SearchName,
    [Parameter(Mandatory=$true)][string]$OutPath
  )

  $active = Get-ActiveUserProfile
  $sid = $null
  if ($active -and $active.SID) { $sid = $active.SID }

  $hits = @()
  try {
    $hits = Find-UwpByTokens -name $SearchName -activeSid $sid
  } catch { $hits = @() }

  # DisplayName-first fallback: Get-StartApps returns *resolved* Start Menu names for the
  # current interactive user, and its AppID includes the Package Family Name (PFN).
  # This catches Store apps where the friendly name exists only via per-user registrations
  # (or resource-backed strings) and therefore fails registry/value matching.
  if (-not $hits -or $hits.Count -eq 0) {
    try {
      $hits = Find-UwpByStartApps -name $SearchName
    } catch { }
  }

  # Normalise to a small, stable schema for merging.
  $out = @()
  foreach ($h in $hits) {
    $out += [pscustomobject]@{
      Name              = $h.Name
      PackageFamilyName = $h.PackageFamilyName
      PackageFullName   = $h.PackageFullName
      RegistryDisplayName = $h.RegistryDisplayName
      Publisher         = $h.Publisher
      PublisherDisplayName = $h.PublisherDisplayName
      IsFramework       = $h.IsFramework
      IsResourcePackage = $h.IsResourcePackage
    }
  }
  try {
    $out | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutPath -Encoding UTF8
  } catch {
    # Best effort.
  }
}

function Find-DirsForName {
  param(
    [string]$name,
    [string[]]$roots
  )
  $dirs = New-Object System.Collections.Generic.List[string]
  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    if (Test-IsExcludedScanPath -Path $root) { continue }
    try {
      $candidates = Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue
      foreach ($d in $candidates) {
        if (Test-IsExcludedScanPath -Path $d.FullName) { continue }
        $leaf = $d.Name
        if ($leaf -and (Matches-OrderedTokens -text $leaf -tokens $tokens)) {
          $dirs.Add($d.FullName) | Out-Null
        }
      }
    } catch {}
  }
  $all = $dirs.ToArray() | Sort-Object Length
  $top = New-Object System.Collections.Generic.List[string]
  foreach ($h in $all) {
    $isChild = $false
    foreach ($kept in $top) {
      if ($h.StartsWith($kept, [System.StringComparison]::OrdinalIgnoreCase)) {
        $isChild = $true
        break
      }
    }
    if (-not $isChild) { $top.Add($h) | Out-Null }
  }
  @($top.ToArray())
}

function Test-IsExcludedScanPath {
  param([string]$Path)

  if (-not $Path) { return $false }
  $normalized = $Path.ToLowerInvariant()

  # Explicitly skip the Windows recovery root.
  if ($normalized -eq 'c:\recovery' -or $normalized.StartsWith('c:\recovery\')) {
    return $true
  }

  # Skip "Recovery Drives" content under user Downloads folders.
  if ($normalized -match '\\downloads\\recovery drives(\\|$)') {
    return $true
  }

  return $false
}


function Test-CanPromptUser {
  try {
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Console]::IsInputRedirected) { return $false }
    return $true
  } catch {
    return $false
  }
}

function Get-ComparableNameKey {
  param([string]$Name)

  if (-not $Name) { return '' }
  $n = $Name.ToLowerInvariant()
  # Remove explicit version fragments such as 1.2.3, v15, _2024 and similar.
  $n = [regex]::Replace($n, '(?i)\bv?\d+(?:[\._-]\d+)+\b', ' ')
  $n = [regex]::Replace($n, '(?i)\bv\d+\b', ' ')
  $n = [regex]::Replace($n, '(?i)\b\d{4}\b', ' ')
  # Normalize punctuation and whitespace.
  $n = [regex]::Replace($n, '[^a-z0-9]+', ' ')
  $n = [regex]::Replace($n, '\s+', ' ').Trim()
  return $n
}

function Select-ArpCandidateInteractive {
  param(
    [Parameter(Mandatory=$true)]$Candidates,
    $Recommended
  )

  $result = [pscustomobject]@{ Selected = $Recommended; Aborted = $false }
  if (-not $Candidates -or $Candidates.Count -le 1) { return $result }
  if (-not (Test-CanPromptUser)) { return $result }

  Write-Host ''
  Write-Host 'Multiple ARP matches were found. Choose which one to target:' -ForegroundColor Cyan

  for ($i = 0; $i -lt $Candidates.Count; $i++) {
    $c = $Candidates[$i]
    $dn = if ($c.DisplayName) { $c.DisplayName } else { $c.KeyName }
    $ver = if ($c.DisplayVersion) { $c.DisplayVersion } else { '-' }
    $pub = if ($c.Publisher) { $c.Publisher } else { '-' }
    $recMark = ''
    if ($Recommended -and ($c.KeyName -eq $Recommended.KeyName) -and ($c.HivePath -eq $Recommended.HivePath)) { $recMark = ' [recommended]' }
    Write-Host ("  [{0}] {1} | Version: {2} | Publisher: {3}{4}" -f ($i+1), $dn, $ver, $pub, $recMark)
  }
  Write-Host '  [0] Abort (no selection; adjust search parameters)'

  while ($true) {
    $raw = Read-Host 'Select ARP entry number (Enter keeps recommended)'
    if ([string]::IsNullOrWhiteSpace($raw)) { return $result }
    $num = 0
    if (-not [int]::TryParse($raw, [ref]$num)) {
      Write-Host 'Invalid input. Enter a number from the list.' -ForegroundColor DarkYellow
      continue
    }
    if ($num -eq 0) {
      $result.Aborted = $true
      return $result
    }
    if ($num -ge 1 -and $num -le $Candidates.Count) {
      $result.Selected = $Candidates[$num - 1]
      return $result
    }
    Write-Host 'Selection out of range. Try again.' -ForegroundColor DarkYellow
  }
}

function Select-UwpCandidateInteractive {
  param([Parameter(Mandatory=$true)]$Candidates)

  $result = [pscustomobject]@{ Selected = $null; Aborted = $false }
  if (-not $Candidates -or $Candidates.Count -le 1) {
    $result.Selected = if ($Candidates -and $Candidates.Count -gt 0) { $Candidates[0] } else { $null }
    return $result
  }
  if (-not (Test-CanPromptUser)) {
    $result.Selected = $Candidates[0]
    return $result
  }

  Write-Host ''
  Write-Host 'Multiple UWP matches were found. Choose which one to target:' -ForegroundColor Cyan
  for ($i = 0; $i -lt $Candidates.Count; $i++) {
    $u = $Candidates[$i]
    $nm = if ($u.Name) { $u.Name } elseif ($u.RegistryDisplayName) { $u.RegistryDisplayName } else { $u.PackageFamilyName }
    Write-Host ("  [{0}] {1} | PFN: {2}" -f ($i+1), $nm, $u.PackageFamilyName)
  }
  Write-Host '  [0] Abort (no selection; adjust search parameters)'

  while ($true) {
    $raw = Read-Host 'Select UWP entry number'
    $num = 0
    if (-not [int]::TryParse($raw, [ref]$num)) {
      Write-Host 'Invalid input. Enter a number from the list.' -ForegroundColor DarkYellow
      continue
    }
    if ($num -eq 0) {
      $result.Aborted = $true
      return $result
    }
    if ($num -ge 1 -and $num -le $Candidates.Count) {
      $result.Selected = $Candidates[$num - 1]
      return $result
    }
    Write-Host 'Selection out of range. Try again.' -ForegroundColor DarkYellow
  }
}

function Is-GenericProductName {
  param([string]$name)
  if (-not $name) { return $true }
  $n = $name.Trim()
  if (-not $n) { return $true }
  if ($n.Length -le 2) { return $true }
  $lower = $n.ToLower()
  $generic = @(
    'application','setup','installer','bootstrapper','update','updater',
    'store installer','microsoft store','product name','app'
  )
  $generic -contains $lower
}

function Expand-CamelName {
  param([string]$s)
  if (-not $s) { return $null }
  [regex]::Replace($s, '([a-z])([A-Z])', '$1 $2')
}

function Derive-Name-From-Pfn {
  param([string]$pfn)
  if (-not $pfn) { return $null }
  $beforeUnderscore = $pfn.Split('_')[0]
  $parts = $beforeUnderscore -split '\.'
  if ($parts.Count -ge 2) {
    $publisherPart = $parts[0]
    $appPart       = $parts[$parts.Count - 1]
    $pubName = Expand-CamelName $publisherPart
    $appName = Expand-CamelName $appPart
    $candidates = @($appName, ("$pubName $appName").Trim(), $pubName)
  } else {
    $single = Expand-CamelName $beforeUnderscore
    $candidates = @($single)
  }
  foreach ($c in $candidates) {
    if ($c -and $c.Length -ge 3 -and -not (Is-GenericProductName $c)) {
      return $c
    }
  }
  $null
}

function Compress-UwpAnchors {
  param([string[]]$anchors)
  if (-not $anchors -or $anchors.Count -eq 0) { return @() }
  $prefixMap = @{}
  $others    = New-Object System.Collections.Generic.List[string]
  foreach ($a in $anchors) {
    if ($a -match '^(.+?)_.*__.+$') {
      $prefix = $matches[1]
      if (-not $prefixMap.ContainsKey($prefix)) {
        $prefixMap[$prefix] = 1
      } else {
        $prefixMap[$prefix] = $prefixMap[$prefix] + 1
      }
    } else {
      $others.Add($a) | Out-Null
    }
  }
  foreach ($k in $prefixMap.Keys) {
    $others.Add("$k`_*") | Out-Null
  }
  @($others.ToArray() | Sort-Object -Unique)
}

function Sanitize-ArpBaseName {
  param([string]$s)

  if (-not $s) { return $null }
  $s = $s.Trim()
  if (-not $s) { return $null }

  $s = $s -replace '\s+[-_]?[\d\.]+(\-\d+)?$',''
  $s = $s.Trim()

  $s = $s -replace '(?i)\s+version\s*$',''
  $s = $s.Trim()

  if (-not $s) { return $null }
  $s
}


function Strings-Compatible {
  param([string]$a,[string]$b)
  if (-not $a -or -not $b) { return $false }
  $aa = ToAlpha $a
  $bb = ToAlpha $b
  if (-not $aa -or -not $bb) { return $false }
  if ($aa -eq $bb) { return $true }
  $short = if ($aa.Length -le $bb.Length) { $aa } else { $bb }
  $long  = if ($aa.Length -gt  $bb.Length) { $aa } else { $bb }
  if ($short.Length -lt 4) { return $false }
  $long.Contains($short)
}

function Has-StrongTie {
  param($a,$b)
  if (-not $a -or -not $b) { return $false }
  $pubMatch = $false
  if ($a.Publisher -and $b.Publisher) {
    if ($a.Publisher.ToString().ToLower() -eq $b.Publisher.ToString().ToLower()) {
      $pubMatch = $true
    }
  }
  $arpBaseA = $null
  if ($a.ARPName) {
    $base = $a.ARPName.ToString().TrimEnd('*')
    $arpBaseA = Sanitize-ArpBaseName $base
  }
  $arpBaseB = $null
  if ($b.ARPName) {
    $base = $b.ARPName.ToString().TrimEnd('*')
    $arpBaseB = Sanitize-ArpBaseName $base
  }
  if ($pubMatch -and $arpBaseA -and $arpBaseB -and ($arpBaseA.ToLower() -eq $arpBaseB.ToLower())) {
    if ($a.InstallerSignatures -and $b.InstallerSignatures) {
      $ta = $a.InstallerSignatures.CertThumbprint
      $tb = $b.InstallerSignatures.CertThumbprint
      if ($ta -and $tb -and ($ta.ToString().ToLower() -eq $tb.ToString().ToLower())) {
        return $true
      }
    }
    return $true
  }
  $paA = To-StringArray $a.PathAnchors
  $paB = To-StringArray $b.PathAnchors
  if ($paA.Count -gt 0 -and $paB.Count -gt 0) {
    $setB = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($x in $paB) { if ($x) { [void]$setB.Add($x) } }
    $overlap = 0
    foreach ($x in $paA) {
      if ($x -and $setB.Contains($x)) {
        $overlap++
        if ($overlap -ge 2) { return $true }
      }
    }
  }
  if ($a.InstallerSignatures -and $b.InstallerSignatures) {
    $pA = $a.InstallerSignatures.ProductName
    $pB = $b.InstallerSignatures.ProductName
    if (Strings-Compatible $pA $pB) { return $true }
  }
  $false
}

function Is-EmptyTarget {
  param($e)
  if (-not $e) { return $true }

  $uwp = To-StringArray $e.UWPFamily
  $uwpEmpty = ($uwp.Count -eq 0)

  $arpEmpty = (-not $e.ARPName)
  $pubEmpty = (-not $e.Publisher)

  $pa = To-StringArray $e.PathAnchors
  $paEmpty = ($pa.Count -eq 0)

  $sigEmpty = $true

  if ($e.InstallerSignatures) {
    $sig = $e.InstallerSignatures
    if ($sig.ProductName -or $sig.CompanyName -or $sig.OriginalFilename -or $sig.CertThumbprint -or $sig.SignerSimpleName) {
      $sigEmpty = $false
    }
  }

  if ($e.PortableExeSignatures) {
    $ps = $e.PortableExeSignatures
    if ($ps.ProductName -or $ps.CompanyName -or $ps.OriginalFilename -or $ps.CertThumbprint -or $ps.SignerSimpleName) {
      $sigEmpty = $false
    }
  }

  ($arpEmpty -and $uwpEmpty -and $pubEmpty -and $paEmpty -and $sigEmpty)
}

function Simplify-Anchors {
  param([string[]]$anchors)
  $anchors = $anchors | Sort-Object -Unique

  $wildPrefixes = @()
  foreach ($a in $anchors) {
    if ($a -match '^(.+?)\*\s*$') {
      $wildPrefixes += $matches[1]
    }
  }

  $out = @()
  foreach ($a in $anchors) {
    $covered = $false
    foreach ($p in $wildPrefixes) {
      if ($a -like "$p*" -and $a -ne "$p*") {
        $covered = $true
        break
      }
    }
    if (-not $covered) {
      $out += $a
    }
  }

  # Ensure the result is always returned as an array. Without wrapping, a zero-element
  # pipeline can return $null which leads to unexpected string concatenation when
  # anchors are later unioned. Wrapping with @() forces an array even if empty.
  $out = $out | Sort-Object -Unique
  return @($out)
}

function Load-ExistingEntries {
  param([string]$path)
  # Load existing target entries from a JSON file.
  # Returns an array of non-empty entry objects.
  if (-not (Test-Path $path)) { return @() }

  $jsonStr = Get-Content $path -Raw -ErrorAction SilentlyContinue
  if (-not $jsonStr) { return @() }

  # Attempt to parse JSON. If the JSON contains trailing commas, fix them and retry.
  $entries = $null
  try {
    $entries = $jsonStr | ConvertFrom-Json -ErrorAction Stop
  } catch {
    $fixed = $jsonStr -replace ',(\s*[\]\}])','$1'
    try {
      $entries = $fixed | ConvertFrom-Json -ErrorAction Stop
    } catch {
      Write-Host "*** Warning: failed to parse existing JSON, backing up and starting fresh ***" -ForegroundColor Yellow
      try {
        Copy-Item -Path $path -Destination ($path + '.bak') -ErrorAction SilentlyContinue
      } catch {}
      return @()
    }
  }

  if ($entries -isnot [System.Array]) {
    $entries = @($entries)
  }

  # Remove blank entries (entries with no key properties).
  $cleaned = @()
  foreach ($e in $entries) {
    $isBlank = $true
    foreach ($prop in 'Name','UWPFamily','ARPName','Publisher','InstallerSignatures','PortableExeSignatures','PathAnchors') {
      if ($e.$prop) {
        $isBlank = $false
        break
      }
    }
    if (-not $isBlank) {
      $cleaned += $e
    }
  }

  return @($cleaned)
}

function Dejam-Text {
  param([string]$s)
  if (-not $s) { return $null }
  $s = [regex]::Replace($s, '([a-z])([A-Z])', '$1 $2')
  $s = [regex]::Replace($s.Trim(), '\s+', ' ')
  return $s
}

function Strip-DuplicateSuffix {
  param([string]$s)
  if (-not $s) { return $null }
  $s = [regex]::Replace($s, '\s\(\d+\)(?=\.[^\\\/\.]+$)', '')
  $s = [regex]::Replace($s, '\s\(\d+\)$', '')

  return $s
}

function Normalize-StringField {
    param(
        [string]$Value
    )

    if (-not $Value) { return $null }

    # Trim and collapse all whitespace runs to a single space
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return $null }

    return [System.Text.RegularExpressions.Regex]::Replace($trimmed, '\s+', ' ')
}

function Normalize-FileDescriptions {
    param([object]$Value)
    if (-not $Value) { return @() }

    $parts = @()
    if ($Value -is [string]) {
        $s = Dejam-Text $Value
        if ($s) {
            $split = [System.Text.RegularExpressions.Regex]::Split($s, '\s{2,}|,\s*')
            foreach ($piece in $split) {
                $p = Dejam-Text $piece
                if ($p) { $parts += $p }
            }
        }
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            if ($item) {
                $p = Dejam-Text ($item.ToString())
                if ($p) { $parts += $p }
            }
        }
    }
    else {
        $p = Dejam-Text ($Value.ToString())
        if ($p) { $parts += $p }
    }

    if ($parts.Count -eq 0) { return @() }

    $seen = @{}
    $unique = @()
    foreach ($p in $parts) {
        if (-not $seen.ContainsKey($p)) {
        $seen[$p] = $true
        $unique += $p
        }
    }

    return $unique
}

function Clean-Signature {
    param(
        [object]$Signature
    )

    if (-not $Signature) { return $null }

    foreach ($prop in $Signature.PSObject.Properties) {
        $name = $prop.Name
        $val  = $prop.Value
        if ($name -eq 'FileDescriptions') {
            # Normalize FileDescriptions to an array
            $prop.Value = Normalize-FileDescriptions -Value $val
        }
        elseif ($val -is [string]) {
            # Normalize other string fields
            $prop.Value = Normalize-StringField -Value $val
        }
    }

    return $Signature
}


function Get-TargetsJsonPath {
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) {
    $scriptPath = $MyInvocation.MyCommand.Path
  }
  if ($scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
    $root = [System.IO.Path]::GetPathRoot($scriptPath)
    $drive = $root.TrimEnd('\')
    $dir   = Split-Path $scriptPath -Parent
    if ($drive -and $drive -ne 'C:') {
      return (Join-Path $dir 'targets.json')
    }
  }
  $downloads = Join-Path $env:USERPROFILE 'Downloads'
  if (-not (Test-Path -LiteralPath $downloads)) { $downloads = $env:USERPROFILE }
  Join-Path $downloads 'targets.json'
}

Write-Host "=== Recognizer start ==="
Write-Host "Target App: '$AppName'"

if ($UserUwpOnly) {
  if (-not $OutJson) { exit 2 }
  Invoke-UserUwpOnlyMode -SearchName $AppName -OutPath $OutJson
  exit 0
}

$active = Get-ActiveUserProfile
$profilePath = if ($active) { $active.Profile } else { $env:USERPROFILE }

$arpAll  = Get-ArpEntriesAll
$DebugArp = $false

$arpStage = $null
$arpHits  = Find-ArpMatchesStaged -arpAll $arpAll -name $AppName -StageUsed ([ref]$arpStage) -DebugMode:$DebugArp
$arpHits  = Get-UniqueArpEntries -Entries $arpHits

if ($arpHits.Count -gt 0) {
  Write-Host ("ARP hits found (stage {0}):" -f $arpStage) -ForegroundColor Yellow
  foreach ($e in $arpHits) {
    $dn = if ($e.DisplayName) { $e.DisplayName } else { $e.KeyName }
    Write-Host "ARP: $dn | Publisher: $($e.Publisher) | InstallLocation: $($e.InstallLocation)"
  }
} else {
  Write-Host "ARP: No uninstall entry found for '$AppName'." -ForegroundColor DarkYellow
}

$displayIconExe = $null
$displayIconCandidate = $null

$arpNameFinal = $null
$pubFinal     = $null
$bestArp      = $null     # will be used later to pick the most "real" app name
if ($arpHits.Count -gt 0) {
  $baseNames = @()
  foreach ($e in $arpHits) {
    $n = $e.DisplayName
    if (-not $n) { $n = $e.KeyName }
    $n2 = Sanitize-ArpBaseName $n
    if ($n2) { $baseNames += $n2 }
  }
  if ($baseNames.Count -gt 0) {
    $grp = $baseNames | Group-Object | Sort-Object Count -Descending | Select-Object -First 1
    $arpNameFinal = ($grp.Name + '*')
  }

  $pubs = $arpHits | ForEach-Object { $_.Publisher } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending
  if ($pubs -and $pubs[0].Name) { $pubFinal = $pubs[0].Name }

  $helperPattern   = '(?i)helper|update|updater|maintenance|component|service'
  $bestArpScore    = [double]::NegativeInfinity
  $nameTokensForArp = Get-NameTokens $AppName

  # Prefer ARP entries whose base DisplayName exactly matches the search term.  If
  # any such match exists, select it immediately as the primary ARP.
  $searchBase = $null
  try { $searchBase = Sanitize-ArpBaseName $AppName } catch { $searchBase = $null }
  if ($searchBase) {
    $exactArps = @()
    foreach ($candidate in $arpHits) {
      $dnCand = $candidate.DisplayName
      if (-not $dnCand) { $dnCand = $candidate.KeyName }
      if ($dnCand) {
        $candBase = $null
        try { $candBase = Sanitize-ArpBaseName $dnCand } catch { $candBase = $null }
        if ($candBase -and ($candBase.ToLower() -eq $searchBase.ToLower())) {
          $exactArps += $candidate
        }
      }
    }
    if ($exactArps.Count -gt 0) {
      # If multiple ARP entries share the exact same sanitized base name as the
      # search term, choose the one with the highest version number when
      # possible.  Falling back to the first entry maintains compatibility if
      # version parsing fails.  This ensures that when the user requests
      # "AppName" and multiple entries exist (e.g. Opera Stable 120.x and
      # Opera Stable 127.x), the most recent version is selected instead of
      # inadvertently picking a different edition (like "Opera Air Stable").
      $selected = $exactArps[0]
      try {
        # Attempt to sort the exact matches by DisplayVersion (descending)
        $sorted = $exactArps | Sort-Object -Property @{ Expression = { [version]($_.DisplayVersion) } ; Descending = $true }
        if ($sorted -and $sorted.Count -gt 0) { $selected = $sorted[0] }
      } catch {
        # If version parsing fails, keep the first entry as a fallback
      }
      $bestArp = $selected
    }
  }

  # If no exact match has been selected, score the candidates.  Shorter names that
  # closely match the search tokens are preferred.  Extra words beyond the search
  # tokens incur a penalty.
  if (-not $bestArp) {
    foreach ($e in $arpHits) {
      $dn = $e.DisplayName
      if (-not $dn) { $dn = $e.KeyName }
      if (-not $dn) { continue }

      $score = 0

      # Reward ordered token match in display name
      if ($nameTokensForArp -and (Matches-OrderedTokens -text $dn -tokens $nameTokensForArp)) {
        $score += 20
      }

      # Prefer shorter names; subtract length beyond 0..40
      $len = $dn.Length
      if ($len -gt 0) {
        $score += [math]::Max(0, 40 - [math]::Min($len, 40))
      }

      # Penalize extra tokens beyond the search tokens
      $dnBase = $null
      try { $dnBase = Sanitize-ArpBaseName $dn } catch { $dnBase = $null }
      $candTok = @()
      if ($dnBase) { $candTok = Get-NameTokens $dnBase }
      $searchTok = @()
      if ($searchBase) {
        try { $searchTok = Get-NameTokens $searchBase } catch { $searchTok = @() }
      }
      if ($candTok -and $searchTok) {
        foreach ($tok in $candTok) {
          if (-not ($searchTok -contains $tok)) { $score -= 3 }
        }
      }

      # Penalize helper/service/update component names
      if ($dn -match $helperPattern) {
        $score -= 12
      }

      if ($score -gt $bestArpScore) {
        $bestArpScore = $score
        $bestArp      = $e
      }
    }
  }

  # If multiple ARP entries are present and they differ by more than version-like
  # text, prompt the operator to select which package should drive the search.
  if ($arpHits.Count -gt 1) {
    $arpComparable = @{}
    foreach ($a in $arpHits) {
      $dnA = if ($a.DisplayName) { $a.DisplayName } else { $a.KeyName }
      $k = Get-ComparableNameKey $dnA
      if (-not $arpComparable.ContainsKey($k)) { $arpComparable[$k] = $true }
    }

    if ($arpComparable.Keys.Count -gt 1) {
      $arpChoice = Select-ArpCandidateInteractive -Candidates $arpHits -Recommended $bestArp
      if ($arpChoice.Aborted) {
        Write-Host 'Selection aborted by user. No changes were recorded.' -ForegroundColor Yellow
        Write-Host '=== Recognizer done ==='
        exit 0
      }
      if ($arpChoice.Selected) { $bestArp = $arpChoice.Selected }
    }
  }

  if ($bestArp) {
    $chosenDn   = if ($bestArp.DisplayName) { $bestArp.DisplayName } else { $bestArp.KeyName }
    $chosenBase = $null
    if ($chosenDn) {
      $chosenBase = Sanitize-ArpBaseName $chosenDn
    }

    if ($chosenBase) {
      $arpNameFinal = "$chosenBase*"
    }

    if ($bestArp.Publisher) {
      $pubFinal = $bestArp.Publisher
    }

    Write-Host "Chosen primary ARP: $chosenDn (Publisher='$($bestArp.Publisher)')" -ForegroundColor Yellow

    if ($bestArp.DisplayIcon) {
      try {
        $iconRaw = $bestArp.DisplayIcon.ToString()
        if ($iconRaw) {
          $pathPart = $iconRaw.Split(',')[0].Trim()
          # Defer processing of the DisplayIcon until after ARP and UWP searches.  If the
          # DisplayIcon points to an executable, record it as a candidate for later
          # portable detection.  Do not resolve or process it here to avoid
          # triggering duplicate DisplayIcon lookups.
          if ($pathPart -and ($pathPart.ToLower().EndsWith('.exe'))) {
            $displayIconCandidate = $pathPart
          }
        }
      } catch {}
    }
  }
}

# Always search for UWP packages regardless of whether an active user was detected.
# Determine the SID to use for the registry scan; when no active SID is found
# we pass `$null` so that `Find-UwpByTokens` will inspect all available
# per‑user and machine‑wide repositories. This resolves cases where a
# package’s display name (e.g. "Angry Birds 2") exists only in the registry
# and would otherwise be skipped when `$active` is `$null`.
$uwpSid  = $null
if ($active -and $active.SID) {
  $uwpSid = $active.SID
}
$uwpHits = Find-UwpByTokens -name $AppName -activeSid $uwpSid
$uwpHits = Get-UniqueUwpEntries -Entries $uwpHits

    # Also perform a simplified substring-based search across registry entries.  This
    # helper scans the same package repositories but matches the search term as a
    # case-insensitive substring in any string property.  It catches titles
    # where the display name contains extra characters (e.g. 'Angry Birds 2'
    # when searching for 'Angry Birds').  Any new hits are merged by
    # PackageFamilyName to avoid duplicates.
    try {
      $uwpNameHits = Find-UwpByName -search $AppName
    } catch { $uwpNameHits = @() }
    if ($uwpNameHits -and $uwpNameHits.Count -gt 0) {
      foreach ($nh in $uwpNameHits) {
        $exists = $false
        foreach ($uh in $uwpHits) {
          if ($uh.PackageFamilyName -and $nh.PackageFamilyName -and ($uh.PackageFamilyName -eq $nh.PackageFamilyName)) {
            $exists = $true; break
          }
        }
        if (-not $exists) { $uwpHits = @($uwpHits) + @($nh) }
      }
    }

# Deep registry-based UWP discovery (ContractId / BackgroundTasks) – only if we have no UWP hits yet.
if ($uwpHits.Count -eq 0) {
  try {
    $uwpRegHits = Find-UwpByContractIdTokens_RegExe -name $AppName -MaxLines 250000
  } catch { $uwpRegHits = @() }

  if ($uwpRegHits -and $uwpRegHits.Count -gt 0) {
    foreach ($rh in $uwpRegHits) {
      # Normalize to the same shape we use elsewhere
      $obj = [pscustomobject]@{
        Source            = $rh.Source
        DisplayName       = $rh.DisplayName
        PackageFullName   = $rh.PackageFullName
        PackageFamilyName = $rh.PackageFamilyName
        RegistryKey       = $rh.RegistryKey
      }

      $exists = $false
      foreach ($uh in $uwpHits) {
        if ($uh.PackageFamilyName -and $obj.PackageFamilyName -and ($uh.PackageFamilyName -eq $obj.PackageFamilyName)) { $exists = $true; break }
        if ($uh.PackageFullName -and $obj.PackageFullName -and ($uh.PackageFullName -eq $obj.PackageFullName)) { $exists = $true; break }
      }
      if (-not $exists) { $uwpHits = @($uwpHits) + @($obj) }
    }
  }
}

# If we found nothing in ARP and nothing in UWP while running as SYSTEM, re-run the UWP
# discovery in the logged-on user's context. Certain Store packages expose human-readable
# DisplayName strings only through HKCU/HKCR class registrations (e.g. BackgroundTasks,
# Extensions\ContractId), which are not visible from SYSTEM's HKCR view.
if (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0) -and $active) {
  try {
    $userUwp = Invoke-UserContextUwpScan -SearchName $AppName -Active $active -TimeoutSeconds 75
    if ($userUwp -and $userUwp.Count -gt 0) {
      foreach ($nu in $userUwp) {
        $exists = $false
        foreach ($uu in $uwpHits) {
          if ($uu.PackageFamilyName -and $nu.PackageFamilyName -and ($uu.PackageFamilyName -eq $nu.PackageFamilyName)) {
            $exists = $true; break
          }
        }
        if (-not $exists) { $uwpHits = @($uwpHits) + @($nu) }
      }
    }
  } catch {}
}

# Final deterministic UWP discovery: load each local profile's UsrClass.dat under SYSTEM
# and scan the user Classes registry for AppModel\Repository and ContractId\BackgroundTasks.
# This is only attempted when ARP and all other UWP strategies produced no results.
if (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0)) {
  try {
    $usrHits = Find-UwpByUsrClassHives -name $AppName -MaxProfiles 12
  } catch { $usrHits = @() }
  if ($usrHits -and $usrHits.Count -gt 0) {
    foreach ($nu in $usrHits) {
      $exists = $false
      foreach ($uu in $uwpHits) {
        if ($uu.PackageFamilyName -and $nu.PackageFamilyName -and ($uu.PackageFamilyName -eq $nu.PackageFamilyName)) { $exists = $true; break }
        if ($uu.PackageFullName -and $nu.PackageFullName -and ($uu.PackageFullName -eq $nu.PackageFullName)) { $exists = $true; break }
      }
      if (-not $exists) { $uwpHits = @($uwpHits) + @($nu) }
    }
  }
}

# If multiple UWP packages were matched and they are not simply version variants,
# allow an operator to explicitly choose which package to keep.
if ($uwpHits.Count -gt 1) {
  $uwpComparable = @{}
  foreach ($uCand in $uwpHits) {
    $nCand = if ($uCand.Name) { $uCand.Name } elseif ($uCand.RegistryDisplayName) { $uCand.RegistryDisplayName } else { $uCand.PackageFamilyName }
    $kCand = Get-ComparableNameKey $nCand
    if (-not $uwpComparable.ContainsKey($kCand)) { $uwpComparable[$kCand] = $true }
  }

  if ($uwpComparable.Keys.Count -gt 1) {
    $uwpChoice = Select-UwpCandidateInteractive -Candidates $uwpHits
    if ($uwpChoice.Aborted) {
      Write-Host 'Selection aborted by user. No changes were recorded.' -ForegroundColor Yellow
      Write-Host '=== Recognizer done ==='
      exit 0
    }
    if ($uwpChoice.Selected) {
      $uwpHits = @($uwpChoice.Selected)
    }
  }
}

if ($uwpHits.Count -gt 0) {
  foreach ($u in $uwpHits) {
    Write-Host "UWP: $($u.Name) | PFN: $($u.PackageFamilyName)" -ForegroundColor Yellow
  }
} else {
  Write-Host "UWP: No matching packages for '$AppName'." -ForegroundColor DarkYellow
}

$ScanRoots = @(
  'C:\Program Files',
  'C:\Program Files (x86)',
  'C:\ProgramData',
  'C:\Users\Public\Desktop',
  (Join-Path $profilePath 'AppData\Local'),
  (Join-Path $profilePath 'AppData\Roaming'),
  (Join-Path $profilePath 'AppData\Local\Programs'),
  # AppData\Local\Temp includes browser staging directories such as
  # MicrosoftEdgeDownloads and Google\Chrome.
  (Join-Path $profilePath 'AppData\Local\Temp'),
  (Join-Path $profilePath 'Downloads'),
  (Join-Path $profilePath 'Documents'),
  (Join-Path $profilePath 'Desktop')
)

try {
  $specialFolders = @(
    [Environment+SpecialFolder]::Desktop,
    [Environment+SpecialFolder]::CommonDesktopDirectory,
    [Environment+SpecialFolder]::UserProfile
  )

  foreach ($sf in $specialFolders) {
    try {
      $p = [Environment]::GetFolderPath($sf)
      if ($p -and (Test-Path $p)) {
        $ScanRoots += $p
      }
    } catch {}
  }
} catch {}

try {
  $oneDriveRoots = @()

  if ($env:OneDrive -and (Test-Path $env:OneDrive)) {
    $oneDriveRoots += $env:OneDrive
  }

  try {
    Get-ChildItem -Path $profilePath -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -like 'OneDrive*' } |
      ForEach-Object { $oneDriveRoots += $_.FullName }
  } catch {}

  # 3) Add each OneDrive root and its Desktop subfolder to ScanRoots
  foreach ($odRoot in ($oneDriveRoots | Sort-Object -Unique)) {
    if (-not (Test-Path $odRoot)) { continue }

    if ($ScanRoots -notcontains $odRoot) {
      $ScanRoots += $odRoot
    }

    $odDesktop = Join-Path $odRoot 'Desktop'
    if ((Test-Path $odDesktop) -and ($ScanRoots -notcontains $odDesktop)) {
      $ScanRoots += $odDesktop
    }
  }
} catch {}

try {
  $systemRootDirs = @(
    'Windows','Program Files','Program Files (x86)','ProgramData',
    'Users','$Recycle.Bin','Recovery','PerfLogs','System Volume Information','$WinREAgent'
  )
  if (Test-Path 'C:\') {
    Get-ChildItem -Path 'C:\' -Directory -ErrorAction SilentlyContinue |
      Where-Object { $systemRootDirs -notcontains $_.Name } |
      ForEach-Object { $ScanRoots += $_.FullName }
  }
} catch {}
try {
  $appDataRoot = Join-Path $profilePath 'AppData'
  if (Test-Path $appDataRoot) {
    $knownAppData = @('Local','LocalLow','Roaming')
    Get-ChildItem -Path $appDataRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $knownAppData -notcontains $_.Name } |
      ForEach-Object { $ScanRoots += $_.FullName }
  }
} catch {}
$ScanRoots = $ScanRoots | Where-Object { $_ -and (Test-Path $_) -and (-not (Test-IsExcludedScanPath -Path $_)) } | Sort-Object -Unique

$dirHitsList = New-Object System.Collections.Generic.List[string]
$initialDirs = Find-DirsForName -name $AppName -roots $ScanRoots
foreach ($p in $initialDirs) {
  if ($p) { [void]$dirHitsList.Add($p.ToString()) }
}

foreach ($u in $uwpHits) {
  if ($u.PackageFamilyName) {
    $pf = $u.PackageFamilyName
    foreach ($root in @(
      'C:\ProgramData\Packages',
      'C:\ProgramData\Microsoft\Windows\AppRepository\Packages',
      (Join-Path $profilePath 'AppData\Local\Packages'),
      (Join-Path $profilePath 'AppData\Local\Microsoft\WindowsApps')
    )) {
      if (Test-Path $root) {
        try {
          Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*$pf*" } |
            ForEach-Object { [void]$dirHitsList.Add($_.FullName) }
        } catch {}
      }
    }
  }
}

if (($dirHitsList.Count -eq 0) -and ($AppName.Length -le 4)) {
  # Fallback: literal leaf-name match for very short app names
  foreach ($root in $ScanRoots) {
    if (-not (Test-Path $root)) { continue }
    try {
      Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $AppName } |
        ForEach-Object { [void]$dirHitsList.Add($_.FullName) }
    } catch {}
  }
}

 $dirHitsAll = $dirHitsList.ToArray() | Sort-Object Length -Unique
 $dirTop = New-Object System.Collections.Generic.List[string]
 foreach ($h in $dirHitsAll) {
   $isChild = $false
   foreach ($kept in $dirTop) {
     if ($h.StartsWith($kept, [System.StringComparison]::OrdinalIgnoreCase)) {
       $isChild = $true
       break
     }
   }
   if (-not $isChild) { $dirTop.Add($h) | Out-Null }
 }
  $dirHits = @($dirTop.ToArray())

  # Determine whether to perform deep portable scan before referencing this flag.
  # We set $RunDeepPortableScan early because $dirHits may trigger logic that depends on it.
  $RunDeepPortableScan = (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0))
  # Initialize collections used for portable scanning
  $idsMatched            = @()
  $portableExeParentDirs = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($d in $dirHits) {
      Write-Host "DIR: $d"
    }
    # Appending portable parent directories to dirHits occurs after the installer scan.

 $moreDirs = @()
 foreach ($e in $arpHits) {
   if ($e.InstallLocation) {
     try {
       if (Test-Path $e.InstallLocation) {
         $pathItem = Get-Item $e.InstallLocation -ErrorAction SilentlyContinue
         if ($pathItem) { $moreDirs += $pathItem.FullName }
       }
     } catch {}
   }

   # Do not attempt to resolve DisplayIcon paths during the initial ARP scan.  The
   # display icon may point to the primary executable or a launcher for the
   # application, but this should only be processed after ARP and UWP scanning
   # has completed.  Storing the raw DisplayIcon path for later analysis
   # (see $displayIconCandidate) avoids unnecessary directory enumeration here.
 }

 if ($moreDirs.Count -gt 0) {
   $moreDirs = $moreDirs | Sort-Object -Unique
   $dirHits = @($dirHits + $moreDirs | Sort-Object Length -Unique)
 }

 $anchorSet = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)
 function Add-Anchor {
   param([string]$s)
   $clean = Clean-Anchor $s
   if ($clean) { [void]$anchorSet.Add($clean) }
 }
 foreach ($d in $dirHits) {
   $leaf   = Split-Path $d -Leaf
   $parent = Split-Path $d -Parent
   if ($leaf)   { Add-Anchor $leaf }
   if ($parent) {
     $pLeaf = Split-Path $parent -Leaf
     if ($pLeaf) { Add-Anchor $pLeaf }
   }
 }
 foreach ($e in $arpHits) {
   if ($e.InstallLocation) {
     $leaf   = Split-Path $e.InstallLocation -Leaf
     $parent = Split-Path $e.InstallLocation -Parent
     if ($leaf)   { Add-Anchor $leaf }
     if ($parent) {
       $pLeaf = Split-Path $parent -Leaf
       if ($pLeaf) { Add-Anchor $pLeaf }
     }
   }
 }
 if ($pubFinal) { Add-Anchor $pubFinal }

 $AppExeIdentities      = @()
 $PrimaryExeIdentity    = $null
 $PortableExeSignatures = $null

# Do not process the DisplayIcon candidate until after ARP/UWP detection
# completes.  See below for deferred handling.

 # Breadcrumb method: use Start Menu shortcuts to identify the core Win32 exe.
 # This is preferred over "largest exe in directory" heuristics.
 if (-not $PrimaryExeIdentity) {
   try {
     $smHit = Find-ExeViaStartMenu -Tokens $appTokens -UserProfilePath $profilePath
     if ($smHit -and $smHit.ExePath -and (Test-Path -LiteralPath $smHit.ExePath)) {
       $smId = Get-FileIdentityBasic $smHit.ExePath
       if ($smId) {
         Write-Host "AppExe (StartMenu): $($smHit.ExePath)  [via $($smHit.Evidence)]" -ForegroundColor Yellow
         Add-Anchor (Split-Path $smHit.ExePath -Parent)
         Add-Anchor $smId.ProductName
         Add-Anchor $smId.CompanyName
         Add-Anchor $smId.FileDescription
         Add-Anchor $smId.OriginalFilename
         $AppExeIdentities += $smId
         $PrimaryExeIdentity = $smId
       }
     }
   } catch {}
 }

 foreach ($d in $dirHits) {
   try {
     $bestExe = Select-BestExeInDirectory -Dir $d -Tokens $appTokens
     if ($bestExe -and $bestExe.ExePath) {
       $id = Get-FileIdentityBasic $bestExe.ExePath
       if ($id) {
         Write-Host "AppExe: $($bestExe.ExePath) (Product='$($id.ProductName)', Company='$($id.CompanyName)')" -ForegroundColor Yellow
         Add-Anchor $id.ProductName
         Add-Anchor $id.CompanyName
         Add-Anchor $id.FileDescription
         Add-Anchor $id.OriginalFilename
         $AppExeIdentities += $id

         if (-not $PrimaryExeIdentity) { $PrimaryExeIdentity = $id }
       }
     }
   } catch {}
}

# -----------------------------------------------------------------------------
# Deferred DisplayIcon processing
#
# Some applications expose a DisplayIcon registry value that points to the
# primary executable (or a launcher) even when there is no uninstall entry
# and no UWP package.  Rather than resolving this during the initial ARP
# enumeration (which can trigger multiple lookups and confuse identity
# detection), we defer handling until after ARP and UWP discovery and after
# scanning Start Menu shortcuts and directories.  Only when no ARP or UWP hits
# were found and no primary EXE has been identified do we attempt to use the
# DisplayIcon candidate as the app's executable.  This prevents duplicate
# "AppExe (DisplayIcon)" messages and ensures that the DisplayIcon is only
# used as a fallback for portable applications.
if (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0) -and (-not $PrimaryExeIdentity) -and $displayIconCandidate) {
  try {
    if (Test-Path -LiteralPath $displayIconCandidate) {
      $diId = Get-FileIdentityBasic $displayIconCandidate
      if ($diId) {
        Write-Host "AppExe (DisplayIcon): $displayIconCandidate (Product='$($diId.ProductName)', Company='$($diId.CompanyName)')" -ForegroundColor Yellow
        Add-Anchor $diId.ProductName
        Add-Anchor $diId.CompanyName
        Add-Anchor $diId.FileDescription
        Add-Anchor $diId.OriginalFilename
        $AppExeIdentities += $diId
        $PrimaryExeIdentity = $diId
      }
    }
  } catch {}
}


if ($true) { # always run installer scan; deep portable scanning gating handled inside
  $installerNamePattern = '(?i)install|installer|setup|portable|bootstrap|stub|updater'
  $nameTokens = Get-NameTokens $AppName
  $useNameTokens = Is-StrongTokenSet $nameTokens
  $idsMatched = @()
  $seenInstallerPaths = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)
  # Collect directories to search for candidate installer executables.  We focus on
  # locations where a user would typically download setup files: the Desktop,
  # Downloads, and Documents folders.  We intentionally do *not* include
  # InstallLocation directories from ARP entries for installer scanning.  Install
  # locations often contain internal installers (e.g. auto-updaters or self-
  # extractors) that are not representative of the user-facing installer.  By
  # excluding these directories, we avoid spurious matches and prioritize
  # genuine setup executables that live outside the application folder.
  $exeRoots = @(
    'C:\Users\Public\Desktop',
    (Join-Path $profilePath 'Downloads'),
    (Join-Path $profilePath 'Documents'),
    (Join-Path $profilePath 'Desktop'),
    (Join-Path $profilePath 'AppData\Local\Temp')
  )
  # Do not include InstallLocation paths from ARP entries when searching
  # for installers.  These paths often lead to helper executables such as
  # embedded auto-updaters or assistant installers within the application
  # directory.  Searching only in user-centric locations reduces noise and
  # improves installer detection.
  $exeRoots = $exeRoots | Where-Object { $_ -and (Test-Path $_) -and (-not (Test-IsExcludedScanPath -Path $_)) } | Sort-Object -Unique

  foreach ($root in $exeRoots) {
    $exeFiles = @()
    try { $exeFiles += Get-ChildItem -Path $root -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue } catch {}
    try { $exeFiles += Get-ChildItem -Path $root -Filter *.msi -File -Recurse -ErrorAction SilentlyContinue } catch {}
    foreach ($file in $exeFiles) {
      # Skip known excluded locations such as C:\Recovery and
      # Downloads\Recovery Drives.
      if (Test-IsExcludedScanPath -Path $file.FullName) { continue }
      if (-not $seenInstallerPaths.Add($file.FullName)) { continue }
      $leaf = (Split-Path $file.FullName -Leaf)
      $isInstallerish = ($leaf -match $installerNamePattern)
      $isNameHit      = ($useNameTokens -and (Matches-OrderedTokens -text $leaf -tokens $nameTokens))
      # Evaluate whether to consider this file as an installer candidate based on
      # identity metadata and anchor evidence.  Always load the file identity
      # before deciding whether to skip.
      $id = Get-FileIdentityBasic $file.FullName
      if (-not $id) { continue }
      # Determine if any metadata fields match the search tokens (e.g. product name or description)
      $isMetadataMatch = $false
      if ($useNameTokens) {
        foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName, $id.CompanyName)) {
          if ($field -and (Matches-OrderedTokens -text $field -tokens $nameTokens)) {
            $isMetadataMatch = $true
            break
          }
        }
      }
      # Determine if any metadata matches our anchor set or publisher (partial match)
      $isAnchorMatch = $false
      if ($id.ProductName -and ($anchorSet.Contains($id.ProductName))) { $isAnchorMatch = $true }
      elseif ($id.FileDescription -and ($anchorSet.Contains($id.FileDescription))) { $isAnchorMatch = $true }
      elseif ($id.OriginalFilename -and ($anchorSet.Contains($id.OriginalFilename))) { $isAnchorMatch = $true }
      elseif ($id.CompanyName -and ($anchorSet.Contains($id.CompanyName))) { $isAnchorMatch = $true }
      elseif ($pubFinal -and $id.CompanyName -and ($id.CompanyName.ToString().ToLower().Contains($pubFinal.ToString().ToLower()))) { $isAnchorMatch = $true }
      # Determine if any metadata field contains installer-related keywords
      $isMetaInstallerish = $false
      foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename)) {
        if ($field -and ($field -match $installerNamePattern)) {
          $isMetaInstallerish = $true
          break
        }
      }
      # Determine whether this file should be considered as a candidate installer.
      # A candidate must satisfy at least one of the following:
      #   - The file name looks installer-ish (install/setup/etc.)
      #   - The file name matches the search tokens (name hit)
      #   - Metadata matches the search tokens and the metadata indicates installer-related content
      #   - Anchor/publisher match exists and the file name or metadata indicates installer-like content
      $isCandidate = $false
      if ($isInstallerish -or $isNameHit) {
        $isCandidate = $true
      } elseif ($isMetadataMatch -and $isMetaInstallerish) {
        $isCandidate = $true
      } elseif ($isAnchorMatch -and ($isInstallerish -or $isMetaInstallerish)) {
        $isCandidate = $true
      }
      if (-not $isCandidate) { continue }

      # Determine if any metadata or filename contains at least one of the search tokens (partial match)
      $hasAnyToken = $false
      if ($useNameTokens) {
        foreach ($tok in $nameTokens) {
          $tokLC = $tok.ToString().ToLower()
          foreach ($field in @($leaf, $id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName, $id.CompanyName)) {
            if ($field) {
              $fstr = $field.ToString().ToLower()
              if ($fstr -like "*$tokLC*") { $hasAnyToken = $true; break }
            }
          }
          if ($hasAnyToken) { break }
        }
      }

      $hit = $false
      # Treat a file as an installer only when the leaf name itself looks installer-ish (setup, install, etc.) or
      # when strong anchor/company matches exist.  A plain token match (e.g. "GeometryDash.exe") does not
      # automatically classify the file as an installer; those should fall under portable detection when
      # no ARP or UWP entries are found.
      if ($isInstallerish) {
        # For installer-like file names (containing setup/install/etc.), we consider
        # additional evidence to determine whether the file truly belongs to the
        # application being searched.  First, if the filename itself matches all
        # search tokens in order (e.g. "SetupGeometryDash.exe"), it is a strong
        # indication that this is the application's installer.
        if ($useNameTokens -and (Matches-OrderedTokens -text $leaf -tokens $nameTokens)) {
          $hit = $true
        } else {
          # Otherwise, check whether the file's metadata matches the search tokens or anchor/publisher information.
          # Additionally, treat partial token matches as positive evidence when the filename is installer-like.
          if ($isMetadataMatch -or $isAnchorMatch -or $hasAnyToken) {
            $hit = $true
          } elseif ($useNameTokens) {
            foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName)) {
              if ($field -and (Matches-OrderedTokens -text $field -tokens $nameTokens)) {
                $hit = $true
                break
              }
            }
          }
          # If still not a hit, fall back to anchor/publisher matches
          if (-not $hit) {
            if ($isAnchorMatch) { $hit = $true }
            elseif ($pubFinal -and $id.CompanyName -and ($id.CompanyName -eq $pubFinal)) { $hit = $true }
          }
        }
      } else {
        # Non-installerish file: only treat as installer when the company matches the known
        # publisher.  Do not rely on anchor matches (which often originate from the file
        # itself) or token matches on non-installer names, as that leads to portable
        # executables (e.g. GeometryDash.exe) being misclassified as installers.
        if ($pubFinal -and $id.CompanyName -and ($id.CompanyName -eq $pubFinal)) {
          $hit = $true
        } elseif ($isNameHit -or $isMetadataMatch -or $isAnchorMatch) {
          $hit = $true
        } else {
          $hit = $false
        }
      }
      if ($hit) {
        Write-Host "Installer: $($file.FullName) (Product='$($id.ProductName)', Company='$($id.CompanyName)', Version='$($id.ProductVersion)')" -ForegroundColor Yellow
        $idsMatched += $id
        $parentDir  = Split-Path -Path $file.FullName -Parent
        $parentLeaf = if ($parentDir) { (Split-Path -Path $parentDir -Leaf) } else { $null }

        $genericFolderNames = @(
          'new folder','folder','downloads','desktop','documents','temp','tmp','files'
        )

        $parentIsGeneric = $false
        if ($parentLeaf) {
          $parentIsGeneric = ($genericFolderNames -contains $parentLeaf.Trim().ToLowerInvariant())
        }

        $strongExeEvidence = $false

        if ($useNameTokens -and (Matches-OrderedTokens -text $leaf -tokens $nameTokens)) {
          $strongExeEvidence = $true
        }
        elseif ($useNameTokens) {
          foreach ($t in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName)) {
            if ($t -and (Matches-OrderedTokens -text $t -tokens $nameTokens)) {
              $strongExeEvidence = $true
              break
            }
          }
        }

        # Only collect parent directories for portable analysis when a deep scan is appropriate.
        if ($RunDeepPortableScan -and $parentDir -and (-not $parentIsGeneric -or $strongExeEvidence)) {
          [void]$portableExeParentDirs.Add($parentDir)
        }

      }
    }
  }
}

# After scanning installer and portable candidates, append any discovered portable parent directories
# to the list of directories to be scanned further (only when deep portable scan is in effect).
if ($RunDeepPortableScan -and $portableExeParentDirs.Count -gt 0) {
  foreach ($p in $portableExeParentDirs) {
    if ($p -and (Test-Path $p)) {
      $dirHits += $p
    }
  }
  $dirHits = $dirHits | Sort-Object -Unique
}

$InstallerSignatures = $null

$hasArpOrUwp = ($arpHits.Count -gt 0 -or $uwpHits.Count -gt 0)



# Filter out generic Microsoft installers that do not strongly match the app name.
if ($idsMatched.Count -gt 0) {
  $idsMatched = Get-UniqueIdentities $idsMatched
  # Remove generic Microsoft entries unless they strongly match the search tokens.
  $idsMatched = @($idsMatched | Where-Object {
    $id = $_
    if (-not $id) { return $false }
    $company = if ($id.CompanyName) { $id.CompanyName } else { '' }
    $isMicrosoft = ($company -and ($company.ToString().ToLower() -eq 'microsoft corporation'))
    if (-not $isMicrosoft) { return $true }
    $strong = $false
    if ($useNameTokens) {
      foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName)) {
        if ($field -and (Matches-OrderedTokens -text $field -tokens $nameTokens)) { $strong = $true; break }
      }
    }
    return $strong
  })

  # If multiple installer candidates remain, select the one that best matches
  # the app name and publisher using metadata.  Compute a score for each
  # identity based on product name, file description, original filename,
  # company name and filename.  Negative weights are applied to entries that
  # clearly represent helper components (assistant, crash reporter, auto-updater, etc.).
  if ($idsMatched.Count -gt 1) {
    $bestCandidate = $null
    $bestCandidateScore = [double]::NegativeInfinity
    # Define patterns used for scoring
    $badMetaPattern = '(?i)assistant|auto[- ]?updater|crash|reporter|helper|maintenance|component'
    $genericNamePattern = '^(?i)(setup|installer)(\.exe)?$'
    foreach ($id in $idsMatched) {
      if (-not $id) { continue }
      $score = 0
      # Reward metadata fields that match the app name tokens in order
      if ($useNameTokens) {
        if ($id.ProductName -and (Matches-OrderedTokens -text $id.ProductName -tokens $nameTokens)) { $score += 30 }
        if ($id.FileDescription -and (Matches-OrderedTokens -text $id.FileDescription -tokens $nameTokens)) { $score += 20 }
        if ($id.OriginalFilename -and (Matches-OrderedTokens -text $id.OriginalFilename -tokens $nameTokens)) { $score += 10 }
        if ($id.FileName -and (Matches-OrderedTokens -text $id.FileName -tokens $nameTokens)) { $score += 10 }
      }
      # Reward metadata that matches anchor set or publisher
      if ($id.ProductName -and $anchorSet.Contains($id.ProductName)) { $score += 15 }
      if ($id.FileDescription -and $anchorSet.Contains($id.FileDescription)) { $score += 10 }
      if ($id.OriginalFilename -and $anchorSet.Contains($id.OriginalFilename)) { $score += 5 }
      if ($id.CompanyName) {
        $cname = $id.CompanyName.ToString()
        if ($pubFinal -and $cname.ToLower().Contains($pubFinal.ToString().ToLower())) { $score += 15 }
        if ($anchorSet.Contains($id.CompanyName)) { $score += 10 }
      }
      # Reward installer-ish original filename or filename
      if ($id.OriginalFilename -and ($id.OriginalFilename -match $installerNamePattern)) { $score += 10 }
      if ($id.FileName -and ($id.FileName -match $installerNamePattern)) { $score += 10 }
      # Reward partial token matches in any metadata field.  Each occurrence of a
      # search token (regardless of order) adds a small bonus.  This helps
      # differentiate installers whose metadata contains the app name even if
      # the full ordered tokens are not present (e.g. "Opera installer" vs
      # "Opera Stable").
      if ($useNameTokens) {
        foreach ($tok in $nameTokens) {
          $tokLC = $tok.ToString().ToLower()
          foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName, $id.CompanyName)) {
            if ($field) {
              $fieldLC = $field.ToString().ToLower()
              if ($fieldLC -like "*$tokLC*") {
                $score += 4
                break
              }
            }
          }
        }
      }
      # Reward descriptive file names by adding the length of the most relevant
      # filename (capped) to the score.  Longer names like "OperaSetup.exe"
      # outscore generic names like "installer.exe".
      $lengthScore = 0
      if ($id.OriginalFilename) {
        $lengthScore = [math]::Min($id.OriginalFilename.Length, 40)
      } elseif ($id.FileName) {
        $lengthScore = [math]::Min($id.FileName.Length, 40)
      }
      $score += $lengthScore
      # Penalize generic installer names ("installer.exe" or "setup.exe") to favor
      # more descriptive filenames.
      $genericPenalty = $false
      if ($id.FileName -and ($id.FileName -match $genericNamePattern)) { $genericPenalty = $true }
      elseif ($id.OriginalFilename -and ($id.OriginalFilename -match $genericNamePattern)) { $genericPenalty = $true }
      if ($genericPenalty) { $score -= 8 }

      # Apply additional penalties for edition-specific terms that do not appear
      # in the search tokens.  This helps differentiate between variants like
      # "OperaAirSetup.exe" and "OperaSetup.exe" when searching for
      # "Opera Stable".  Edition terms include keywords such as Air, GX, Beta,
      # Dev, Developer, Canary, Nightly, Preview, Portable, Assistant and Browser.
      $editionPenaltyTerms = @('air','gx','beta','dev','developer','canary','nightly','preview','portable','assistant','browser')
      # Lower-case search tokens for comparison
      $searchTokensLower = @()
      if ($nameTokens) {
        foreach ($t in $nameTokens) { if ($t) { $searchTokensLower += $t.ToString().ToLower() } }
      }
      foreach ($term in $editionPenaltyTerms) {
        $termLower = $term.ToLower()
        $found = $false
        # Check if the term exists in any metadata field or filename
        foreach ($fld in @($id.FileName, $id.OriginalFilename, $id.ProductName, $id.FileDescription)) {
          if ($fld) {
            $fLow = $fld.ToString().ToLower()
            if ($fLow -like "*$termLower*") { $found = $true; break }
          }
        }
        if ($found) {
          # Only penalize if the search tokens do not include this term
          if (-not ($searchTokensLower -contains $termLower)) {
            $score -= 20
          }
        }
      }

      # Compute token overlap and difference between the app's search tokens
      # and the candidate's own tokens.  This encourages candidates whose
      # metadata includes all of the search tokens and penalizes extra or
      # missing tokens.  We derive candidate tokens from the first available
      # descriptive field (ProductName, FileDescription, OriginalFilename,
      # FileName).  If the field is unavailable or tokenization fails, no
      # adjustment is made.
      # Collect tokens from all relevant identity fields (ProductName,
      # FileDescription, OriginalFilename and FileName).  By aggregating
      # tokens from multiple fields, we capture edition-specific terms like
      # "GX" or "Air" even when they are absent from the product name.
      $candTok = @()
      foreach ($srcField in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName)) {
        if ($srcField) {
          try {
            $toks = Get-NameTokens $srcField
            if ($toks) { $candTok += $toks }
          } catch {}
        }
      }
      if ($candTok) {
        $candTok = $candTok | Sort-Object -Unique
      }
      if ($candTok -and $nameTokens) {
        # Define generic installer tokens; these represent neutral words that
        # should not be heavily penalized when they appear as extra tokens.
        $genericInstallerTokens = @('setup','install','installer','portable','bootstrap','stub','update','updater','sfx')
        foreach ($tok in $nameTokens) {
          if (-not ($candTok -contains $tok)) { $score -= 10 }
        }
        foreach ($ct in $candTok) {
          if (-not ($nameTokens -contains $ct)) {
            # If the extra token is a generic installer term, apply a smaller penalty.
            if ($genericInstallerTokens -contains $ct) {
              $score -= 1
            } else {
              # Edition-specific tokens (e.g. GX, Air) incur a larger penalty.
              $score -= 10
            }
          }
        }
      }
      # Apply penalties for helper/assistant/updater/crash reporter names in any metadata
      $penalize = $false
      foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName)) {
        if ($field -and ($field -match $badMetaPattern)) { $penalize = $true; break }
      }
      if ($penalize) { $score -= 25 }
      # Prefer entries that have at least one strong field (avoid unidentifiable installers)
      $hasIdentifier = $false
      foreach ($field in @($id.ProductName, $id.FileDescription, $id.OriginalFilename, $id.FileName, $id.CompanyName)) {
        if ($field) { $hasIdentifier = $true; break }
      }
      if (-not $hasIdentifier) { $score -= 20 }
      # Update best candidate
      if ($score -gt $bestCandidateScore) {
        $bestCandidateScore = $score
        $bestCandidate = $id
      }
    }
    if ($bestCandidate) {
      # Keep only the best candidate for signature generation
      $idsMatched = @($bestCandidate)
    }
  }
}

if ($idsMatched.Count -gt 0) {
  $InstallerSignatures = Build-InstallerSignature $idsMatched
}

if ($InstallerSignatures -and $idsMatched.Count -gt 0) {
  $primaryInstaller = $idsMatched | Select-Object -First 1
  if ($primaryInstaller) {
    if ($primaryInstaller.FileName -and (-not $InstallerSignatures.InstallerFileName)) {
      $InstallerSignatures.InstallerFileName = $primaryInstaller.FileName
    }
    if ($primaryInstaller.SourcePath -and (-not $InstallerSignatures.InstallerPath)) {
      $InstallerSignatures.InstallerPath = $primaryInstaller.SourcePath
    }
    if (($primaryInstaller.FileName) -and (-not $InstallerSignatures.OriginalFilename)) {
      $InstallerSignatures.OriginalFilename = $primaryInstaller.FileName
    }
  }

  $nameTokens = Get-NameTokens $AppName

  $bestName  = $null
  $bestScore = -1

  foreach ($id in $idsMatched) {
    if (-not $id) { continue }

    $candidates = @()
    if ($id.OriginalFilename) {
      $candidates += [pscustomobject]@{ Kind = 'Original'; Name = $id.OriginalFilename }
    }
    if ($id.FileName) {
      $candidates += [pscustomobject]@{ Kind = 'File'; Name = $id.FileName }
    }

    foreach ($cand in $candidates) {
      $fn = $cand.Name
      if (-not $fn) { continue }

      $score = 0

      # Installer-ish name like setup/install/updater/etc.
      if ($fn -match $installerNamePattern) { $score += 10 }

      # Prefer longer, more descriptive names (up to a cap)
      $score += [math]::Min($fn.Length, 40)

      # Reward names that match the app name tokens in order
      if ($nameTokens) {
        if (Matches-OrderedTokens -text $fn -tokens $nameTokens) {
          $score += 8
        } else {
          $score -= 10
        }
      }

      # Incorporate metadata similarity to the app.  Reward installers whose metadata
      # matches the search tokens or anchor/publisher information.  This helps
      # prioritize the installer that best corresponds to the core application.
      if ($id) {
        # ProductName
        if ($id.ProductName) {
          if ($nameTokens -and (Matches-OrderedTokens -text $id.ProductName -tokens $nameTokens)) { $score += 20 }
          if ($anchorSet.Contains($id.ProductName)) { $score += 15 }
        }
        # FileDescription
        if ($id.FileDescription) {
          if ($nameTokens -and (Matches-OrderedTokens -text $id.FileDescription -tokens $nameTokens)) { $score += 20 }
          if ($anchorSet.Contains($id.FileDescription)) { $score += 10 }
        }
        # OriginalFilename
        if ($id.OriginalFilename) {
          if ($nameTokens -and (Matches-OrderedTokens -text $id.OriginalFilename -tokens $nameTokens)) { $score += 10 }
        }
        # CompanyName
        if ($id.CompanyName) {
          if ($pubFinal -and ($id.CompanyName.ToString().ToLower().Contains($pubFinal.ToString().ToLower()))) { $score += 15 }
          if ($anchorSet.Contains($id.CompanyName)) { $score += 10 }
        }
      }

      if ($score -gt $bestScore) {
        $bestScore = $score
        $bestName  = $fn
      }
    }
  }

  # Fallback if for some reason we never scored anything
  if (-not $bestName) {
    foreach ($id in $idsMatched) {
      if (-not $id) { continue }
      if ($id.FileName) {
        $bestName = $id.FileName
        break
      }
      if ($id.OriginalFilename) {
        $bestName = $id.OriginalFilename
        break
      }
    }
  }

  if ($bestName) {
    $generalName = $bestName
    $generalName = Strip-DuplicateSuffix $generalName


    # Generalize version-y bits -> wildcards
    $generalName = [regex]::Replace($generalName, '\d+(\.\d+)+', '*')
    $generalName = [regex]::Replace($generalName, '\d{3,}', '*')
    $generalName = $generalName -replace '\*+', '*'

    $InstallerSignatures.OriginalFilename = $generalName

    # Merge the generalized name into FileDescriptions as a unique string array
    $InstallerSignatures.FileDescriptions = UniqueStrings (
      (To-StringArray $InstallerSignatures.FileDescriptions) + $generalName
    )
  }
}

$portableSignals = 0

foreach ($d in $dirHits) {
  if (-not $d) { continue }

  $dlower = $d.ToLowerInvariant()

  if ($dlower -like 'c:\users\*\downloads*' -or
      $dlower -like 'c:\users\*\desktop*'   -or
      $dlower -like 'c:\users\*\documents*' ) {
    $portableSignals++
  }

  if ($dlower -match 'portable') {
    $portableSignals += 2
  }
}

foreach ($id in $idsMatched) {
  if (-not $id) { continue }
  $fn = $id.OriginalFilename
  if (-not $fn) { $fn = $id.FileName }
  if (-not $fn) { continue }
  if ($fn.ToLowerInvariant() -match 'portable') {
    $portableSignals += 2
  }
}

 # If there are no ARP/UWP matches but we did discover one or more primary executables, and
 # no installers were matched, treat this as a portable application.  This covers
 # scenarios like Geometry Dash where the only evidence is an executable in a folder.
 if (-not $hasArpOrUwp) {
   if ($AppExeIdentities.Count -gt 0 -and $idsMatched.Count -eq 0) {
     $portableSignals += 1
   }
 }

# Portable candidate rules:
# - Pure portable: no ARP/UWP and at least 1 portable signal
# - Hybrid: ARP/UWP exists but we see strong portable hints (>=2)
$purePortable   = (-not $hasArpOrUwp -and $portableSignals -gt 0)
$hybridPortable = ($hasArpOrUwp -and $portableSignals -ge 2)

$isPortableCandidate = $purePortable -or $hybridPortable

$portableInputs = @()
$PortableExeSignatures = $null

if ($isPortableCandidate) {
  if ($AppExeIdentities.Count -gt 0) {
    $portableInputs += $AppExeIdentities
  }

  if ($idsMatched.Count -gt 0) {
    $portableInputs += $idsMatched
  }

  if ($portableInputs.Count -gt 0) {
    $portableInputs = Get-UniqueIdentities $portableInputs
    $PortableExeSignatures = Build-InstallerSignature $portableInputs

    if ($PortableExeSignatures -and $PrimaryExeIdentity -and $PrimaryExeIdentity.FileName) {
      $primaryExeName = $PrimaryExeIdentity.FileName
      $origPortable   = $PortableExeSignatures.OriginalFilename

      if ($origPortable) {
        if ($origPortable -match $installerNamePattern) {
          $primaryExeName = Strip-DuplicateSuffix $primaryExeName
          $PortableExeSignatures.OriginalFilename = $primaryExeName
        }
      }
      else {
        $primaryExeName = Strip-DuplicateSuffix $primaryExeName
        $PortableExeSignatures.OriginalFilename = $primaryExeName
      }

      $PortableExeSignatures.FileDescriptions = UniqueStrings (
        (To-StringArray $PortableExeSignatures.FileDescriptions) + $primaryExeName
      )
    }
  }
}

 # Fallback: if no ARP/UWP hits and no portable signatures were built, but we discovered one or more directories
 # associated with the search term, treat the directory name itself as the signature of a portable app.  This
 # handles cases where a game consists solely of a folder without an identifiable installer or EXE (e.g., Geometry Dash).
 if (-not $PortableExeSignatures -and -not $hasArpOrUwp -and $dirHits.Count -gt 0) {
   try {
     $fallbackDir = $dirHits | Sort-Object Length | Select-Object -First 1
     $fnFallback  = $null
     if ($fallbackDir) {
       $fnFallback = (Split-Path -Path $fallbackDir -Leaf)
       if ($fnFallback) {
         # Remove trailing archive extensions (e.g. .zip) and version-like suffixes
         $fnFallback = $fnFallback -replace '\.zip$', ''
         $fnFallback = $fnFallback -replace '\d+(\.\d+)+$', ''
         $fnFallback = $fnFallback.Trim()
       }
     }
     if (-not [string]::IsNullOrWhiteSpace($fnFallback)) {
       $PortableExeSignatures = [pscustomobject]@{
         ProductName      = $null
         CompanyName      = $null
         OriginalFilename = $fnFallback
         CertThumbprint   = $null
         SignerSimpleName = $null
         FileDescriptions = $fnFallback
       }
       # Promote the fallback name into the anchor set so that future scans can leverage it
       Add-Anchor $fnFallback
     }
   } catch {}
 }

 # Additional pass: if no executables were identified yet and there are directory hits,
 # scan deeper within any Launcher\Content folder to locate executables (commonly used
 # by Xbox Games and similar packaging).  This helps identify games distributed via
 # the Xbox launcher as portable applications when no ARP/UWP entries are found.
 if ($AppExeIdentities.Count -eq 0) {
   foreach ($d2 in $dirHits) {
     # Match case-insensitive path containing \Launcher\Content\
     if ($d2 -match '\\Launcher\\Content\\') {
       try {
         $deepExes2 = Get-ChildItem -LiteralPath $d2 -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue
         foreach ($ex in $deepExes2) {
           $id2 = Get-FileIdentityBasic $ex.FullName
           if ($id2) {
             Write-Host "AppExe (Launcher/Content): $($ex.FullName) (Product='$($id2.ProductName)', Company='$($id2.CompanyName)')" -ForegroundColor Yellow
             Add-Anchor $id2.ProductName
             Add-Anchor $id2.CompanyName
             Add-Anchor $id2.FileDescription
             Add-Anchor $id2.OriginalFilename
             $AppExeIdentities += $id2
             if (-not $PrimaryExeIdentity) { $PrimaryExeIdentity = $id2 }
           }
         }
       } catch {}
     }
   }
 }

# Removed duplicate PortableExeSignatures normalization block. The logic is handled
# once within the $isPortableCandidate section above.

if (-not $InstallerSignatures -and $hasArpOrUwp -and $PortableExeSignatures) {
  $InstallerSignatures = $PortableExeSignatures
}

$uwpFamily = $null
if ($uwpHits.Count -gt 0) {
  $families = $uwpHits | ForEach-Object { $_.PackageFamilyName } | Where-Object { $_ } | Sort-Object -Unique
  if ($families.Count -gt 0) { $uwpFamily = $families[0] }
  if ($uwpFamily) {
    Add-Anchor $uwpFamily
  }
}

$NameCandidate = $null

if ($bestArp) {
  $dn = if ($bestArp.DisplayName) { $bestArp.DisplayName } else { $bestArp.KeyName }
  $dn = Sanitize-ArpBaseName $dn
  if ($dn) { $NameCandidate = $dn }
}

if (-not $NameCandidate -and $arpNameFinal) {
  $base = $arpNameFinal.TrimEnd('*')
  $base = Sanitize-ArpBaseName $base
  if ($base) { $NameCandidate = $base }
}

if (-not $NameCandidate -and $PrimaryExeIdentity -and
    $PrimaryExeIdentity.ProductName -and
    -not (Is-GenericProductName $PrimaryExeIdentity.ProductName)) {
  $NameCandidate = $PrimaryExeIdentity.ProductName
}
 # If no candidate name found from ARP or EXE identity, attempt to use UWP hits.
# Prefer human-friendly registry display names / descriptions and avoid opaque PFN-style names.
if (-not $NameCandidate -and $uwpHits -and $uwpHits.Count -gt 0) {
  $appTokens = Get-NameTokens $AppName

  $uwpNameCandidates = @()
  foreach ($u in $uwpHits) {
    foreach ($c in @($u.RegistryDisplayName, $u.Description, $u.Name)) {
      if (-not $c) { continue }
      if (Is-GenericProductName $c) { continue }
      # Skip opaque vendor.package identifiers. These are useful for matching PFNs,
      # but they must NOT override a good user-provided title (e.g. 'Hill Climb Racing').
      # Only allow opaque candidates when the user's search term is itself generic.
      if (Is-OpaqueUwpName $c) {
        if (-not (Is-GenericProductName $AppName)) { continue }
        if (-not (Matches-OrderedTokens -text $c -tokens $appTokens)) { continue }
      }
      $uwpNameCandidates += $c
    }
  }

  if ($uwpNameCandidates.Count -gt 0) {
    # Prefer candidates that look like a title (spaces) and/or match the search tokens.
    $ranked = $uwpNameCandidates |
      Sort-Object -Property @{Expression={ if (Matches-OrderedTokens -text $_ -tokens $appTokens) { 2 } elseif ($_ -match '\s') { 1 } else { 0 } }; Descending=$true}, @{Expression={ $_.Length }; Descending=$true}
    $NameCandidate = $ranked | Select-Object -First 1
  }

  # Also set a publisher if none established yet.
  if (-not $pubFinal) {
    $pubU = $uwpHits |
      ForEach-Object { $_.PublisherDisplayName } |
      Where-Object { $_ } |
      Group-Object |
      Sort-Object Count -Descending
    if ($pubU -and $pubU[0].Name) { $pubFinal = $pubU[0].Name }
  }
}

if (-not $NameCandidate -and $uwpFamily -and (Is-GenericProductName $AppName)) {
  # Only derive a display-like name from PFN when the user-provided search
  # term is itself generic; otherwise this can regress into vendor-style
  # identifiers (e.g., FINGERSOFT.HILLCLIMBRACING) replacing a good title.
  $pfName = Derive-Name-From-Pfn $uwpFamily
  if ($pfName) { $NameCandidate = $pfName }
}
if (-not $NameCandidate) {
  $NameCandidate = $AppName
}

if (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0) -and ($dirHits.Count -gt 0)) {
  $retryNames = @()
  foreach ($a in $anchorSet) {
    if ($a -and -not (Is-GenericProductName $a)) { $retryNames += $a }
  }
  if ($PrimaryExeIdentity) {
    if ($PrimaryExeIdentity.ProductName -and -not (Is-GenericProductName $PrimaryExeIdentity.ProductName)) {
      $retryNames += $PrimaryExeIdentity.ProductName
    }
    if ($PrimaryExeIdentity.FileDescription -and -not (Is-GenericProductName $PrimaryExeIdentity.FileDescription)) {
      $retryNames += $PrimaryExeIdentity.FileDescription
    }
  }
  if ($InstallerSignatures -and $InstallerSignatures.ProductName -and -not (Is-GenericProductName $InstallerSignatures.ProductName)) {
    $retryNames += $InstallerSignatures.ProductName
  }
  $retryNames = $retryNames | Where-Object { $_ } | Sort-Object -Unique
  foreach ($rn in $retryNames) {
    if ($arpHits.Count -eq 0) {
      $st=$null; $hits = Find-ArpMatchesStaged -arpAll $arpAll -name $rn -StageUsed ([ref]$st)
      if ($hits.Count -gt 0) {
        Write-Host "ARP retry using '$rn' found $($hits.Count) entries." -ForegroundColor Yellow
        $arpHits = Get-UniqueArpEntries -Entries $hits
        $baseNames2 = @()
        foreach ($x in $arpHits) {
          $nx = $x.DisplayName
          if (-not $nx) { $nx = $x.KeyName }
          $n2 = Sanitize-ArpBaseName $nx
          if ($n2) { $baseNames2 += $n2 }
        }
        if ($baseNames2.Count -gt 0) {
          $grp2 = $baseNames2 | Group-Object | Sort-Object Count -Descending | Select-Object -First 1
          $arpNameFinal = ($grp2.Name + '*')
        }
        $pubs2 = $arpHits | ForEach-Object { $_.Publisher } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending
        if ($pubs2 -and $pubs2[0].Name) { $pubFinal = $pubs2[0].Name }
        $moreDirs2 = @()
        foreach ($x in $arpHits) {
          if ($x.InstallLocation) {
            try {
              if (Test-Path $x.InstallLocation) {
                $pi2 = Get-Item $x.InstallLocation -ErrorAction SilentlyContinue
                if ($pi2) { $moreDirs2 += $pi2.FullName }
              }
            } catch {}
          }
        }
        if ($moreDirs2.Count -gt 0) {
          $moreDirs2 = $moreDirs2 | Sort-Object -Unique
          $dirHits = @($dirHits + $moreDirs2 | Sort-Object Length -Unique)
          foreach ($d2 in $moreDirs2) {
            $leaf2   = Split-Path $d2 -Leaf
            $parent2 = Split-Path $d2 -Parent
            if ($leaf2) { Add-Anchor $leaf2 }
            if ($parent2) {
              $p2 = Split-Path $parent2 -Leaf
              if ($p2) { Add-Anchor $p2 }
            }
          }
        }
      }
    }
    # If no UWP hits were found so far, retry using alternative name variants.
    # This condition no longer depends on having an active user SID; the
    # subsequent logic will determine whether to pass the SID or `$null`.
    if ($uwpHits.Count -eq 0) {
      # Always retry the UWP search for alternative name variants, even when
      # no active user SID is available.  Use the active SID when present,
      # otherwise pass `$null` so that Find-UwpByTokens scans all users and
      # machine-wide repositories for packages matching `$rn`.
      $tmpSid  = $null
      if ($active -and $active.SID) { $tmpSid = $active.SID }
      $tmpHits = Find-UwpByTokens -name $rn -activeSid $tmpSid
      if ($tmpHits.Count -gt 0) {
        Write-Host "UWP retry using '$rn' found $($tmpHits.Count) packages." -ForegroundColor Yellow
        foreach ($uh in $tmpHits) {
          $uwpHits = Get-UniqueUwpEntries -Entries (@($uwpHits) + @($uh))
        }
      }
      # If no hits from token-based search, and the retry name looks like a package
      # full or family name (two segments separated by a period), perform a
      # package-name specific search.  This catches cases where a directory
      # anchor (e.g. "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2") points to a hidden
      # UWP package whose display name does not contain the original search terms.
      if ($uwpHits.Count -eq 0) {
        # Skip retry for WER crash identifiers (AppCrash_*). These are not
        # legitimate package names and should not trigger registry-based searches.
        if ($rn -like 'AppCrash_*') {
          # do nothing
        }
        # Perform a package-name specific search only if the name looks like
        # a package family or full name: must contain a period and an underscore,
        # must not contain spaces or commas, and must not be a WER identifier.
        elseif (($rn -match '^[A-Za-z0-9][A-Za-z0-9\.]*_[^,\s]+$') -and ($rn -match '\.')) {
          try {
            $tmpHits2 = Find-UwpByRegistryTokens -name $rn -activeSid $tmpSid
          } catch { $tmpHits2 = @() }
          if (-not $tmpHits2 -or $tmpHits2.Count -eq 0) {
            try { $tmpHits2 = Find-UwpByName -search $rn } catch { $tmpHits2 = @() }
          }
          if ($tmpHits2 -and $tmpHits2.Count -gt 0) {
            Write-Host "UWP (anchor) retry using '$rn' found $($tmpHits2.Count) packages." -ForegroundColor Yellow
            foreach ($uh in $tmpHits2) {
              $uwpHits = Get-UniqueUwpEntries -Entries (@($uwpHits) + @($uh))
            }
          }
        }
      }
    }
    if ($arpHits.Count -gt 0 -or $uwpHits.Count -gt 0) { break }
  }
  if ($uwpHits.Count -gt 0) {
    $families2 = $uwpHits | ForEach-Object { $_.PackageFamilyName } | Where-Object { $_ } | Sort-Object -Unique
    if ($families2.Count -gt 0) { $uwpFamily = $families2[0] }
    if ($uwpFamily) {
      Add-Anchor $uwpFamily
    }
  }
  if ($arpHits.Count -gt 0) {
    $base = $arpNameFinal.TrimEnd('*')
    $base = Sanitize-ArpBaseName $base
    if ($base) { $NameCandidate = $base }
  } elseif ($uwpHits.Count -gt 0) {
    if ($uwpFamily) {
      $pf2 = Derive-Name-From-Pfn $uwpFamily
      if ($pf2) { $NameCandidate = $pf2 }
    }
  }
}

if (($arpHits.Count -eq 0) -and ($uwpHits.Count -eq 0) -and ($dirHits.Count -eq 0) -and (-not $InstallerSignatures) -and (-not $PortableExeSignatures)) {
  Write-Host "*** No matching application traces found for '$AppName'. Nothing recorded. ***" -ForegroundColor Red
  Write-Host "=== Recognizer done ==="
  return
}



# Helper: Discover UWP packages in the registry when Get-AppxPackage misses them.

# --- Deterministic UWP discovery for "hidden" Store apps ---
# Some Store apps (games in particular) only expose friendly DisplayName strings inside
# per-user Classes hives (UsrClass.dat). When the script runs as SYSTEM (Intune), those
# hives are typically not loaded, which means HKCR/HKCU views may not contain the
# user's registrations. This helper mounts UsrClass.dat for local profiles and
# scans two high-signal locations:
#   1) Local Settings\...\AppModel\Repository\Packages (often holds DisplayName)
#   2) Extensions\ContractId\Windows.BackgroundTasks\PackageId (your Angry Birds example)

function Get-LocalProfiles {
  $out = @()
  $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  try {
    foreach ($k in Get-ChildItem $pl -ErrorAction SilentlyContinue) {
      $sid = $k.PSChildName
      if (-not $sid) { continue }
      # Skip well-known non-user profiles
      if ($sid -match '^S-1-5-(18|19|20)$') { continue }
      $pi = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
      if (-not $pi -or -not $pi.ProfileImagePath) { continue }
      $profilePath = $pi.ProfileImagePath
      if (-not (Test-Path -LiteralPath $profilePath)) { continue }
      $usrClass = Join-Path $profilePath 'AppData\Local\Microsoft\Windows\UsrClass.dat'
      if (-not (Test-Path -LiteralPath $usrClass)) { continue }
      $out += [pscustomobject]@{ SID = $sid; ProfilePath = $profilePath; UsrClass = $usrClass }
    }
  } catch {}
  $out
}

function Invoke-RegExeQuery {
  param(
    [Parameter(Mandatory=$true)][string]$Key,
    [switch]$Recurse,
    [int]$MaxLines = 250000
  )
  $args = @('query', $Key)
  if ($Recurse) { $args += '/s' }
  $txt = $null
  try { $txt = & reg.exe @args 2>$null } catch { $txt = $null }
  if (-not $txt) { return @() }
  $lines = @($txt)
  if ($MaxLines -gt 0 -and $lines.Count -gt $MaxLines) {
    $lines = $lines[0..($MaxLines-1)]
  }
  $lines
}

function Mount-UsrClassHive {
  param(
    [Parameter(Mandatory=$true)][string]$UsrClassPath,
    [Parameter(Mandatory=$true)][string]$MountName
  )
  # Copy first to avoid file-in-use locks
  $tmp = Join-Path $env:TEMP ("usrclass_{0}.dat" -f ([Guid]::NewGuid().ToString('N')))
  try { Copy-Item -LiteralPath $UsrClassPath -Destination $tmp -Force -ErrorAction Stop } catch { return $null }
  try {
    & reg.exe load ("HKU\{0}" -f $MountName) $tmp 2>$null | Out-Null
    return $tmp
  } catch {
    try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {}
    return $null
  }
}

function Unmount-UsrClassHive {
  param(
    [Parameter(Mandatory=$true)][string]$MountName,
    [string]$TmpCopy
  )
  try { & reg.exe unload ("HKU\{0}" -f $MountName) 2>$null | Out-Null } catch {}
  if ($TmpCopy) { try { Remove-Item -LiteralPath $TmpCopy -Force -ErrorAction SilentlyContinue } catch {} }
}

function Parse-RegExeBlocks {
  param(
    [Parameter(Mandatory=$true)][string[]]$Lines,
    [string[]]$ValueNames = @('DisplayName','Description','Vendor','PublisherDisplayName','PackageID','PackageId','PackageName')
  )
  $blocks = @()
  $curKey = $null
  $vals = @{}
  foreach ($ln in $Lines) {
    if (-not $ln) { continue }
    if ($ln -match '^HKEY_') {
      if ($curKey) {
        $blocks += [pscustomobject]@{ Key=$curKey; Values=$vals }
      }
      $curKey = $ln.Trim()
      $vals = @{}
      continue
    }
    # Value line: "    Name    REG_SZ    Data"
    if ($curKey -and ($ln -match '^\s{2,}([^\s]+)\s+REG_\w+\s+(.*)$')) {
      $n = $Matches[1]
      $d = $Matches[2]
      if ($ValueNames -contains $n) {
        $vals[$n] = $d
      }
    }
  }
  if ($curKey) { $blocks += [pscustomobject]@{ Key=$curKey; Values=$vals } }
  $blocks
}

function Derive-UwpFamilyFromFullName {
  param([string]$PackageFullName)
  if (-not $PackageFullName) { return $null }
  if ($PackageFullName -match '^[^_]+_[^_]+$') { return $PackageFullName }
  $parts = $PackageFullName -split '_'
  if ($parts.Length -ge 2 -and $parts[0] -and $parts[$parts.Length-1]) {
    return "{0}_{1}" -f $parts[0], $parts[$parts.Length-1]
  }
  if ($parts.Length -ge 1) { return $parts[0] }
  $null
}

function Find-UwpByUsrClassHives {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$name,
    [int]$MaxProfiles = 12
  )
  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return @() }

  $profiles = Get-LocalProfiles
  if (-not $profiles) { return @() }
  if ($MaxProfiles -gt 0 -and $profiles.Count -gt $MaxProfiles) {
    $profiles = $profiles | Select-Object -First $MaxProfiles
  }

  $hits = @()

  foreach ($p in $profiles) {
    $mount = "RecognizerUsr_{0}" -f ([Guid]::NewGuid().ToString('N'))
    $tmpCopy = Mount-UsrClassHive -UsrClassPath $p.UsrClass -MountName $mount
    if (-not $tmpCopy) { continue }
    try {
      $root1 = "HKU\{0}\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" -f $mount
      $root2 = "HKU\{0}\Extensions\ContractId\Windows.BackgroundTasks\PackageId" -f $mount

      $lines1 = Invoke-RegExeQuery -Key $root1 -Recurse -MaxLines 150000
      $lines2 = Invoke-RegExeQuery -Key $root2 -Recurse -MaxLines 150000

      $blocks = @()
      if ($lines1 -and $lines1.Count -gt 0) { $blocks += Parse-RegExeBlocks -Lines $lines1 }
      if ($lines2 -and $lines2.Count -gt 0) { $blocks += Parse-RegExeBlocks -Lines $lines2 }

      foreach ($b in $blocks) {
        $v = $b.Values
        $disp = $null
        if ($v.ContainsKey('DisplayName')) { $disp = Resolve-IndirectString $v['DisplayName'] }
        $desc = $null
        if ($v.ContainsKey('Description')) { $desc = Resolve-IndirectString $v['Description'] }
        $vend = $null
        if ($v.ContainsKey('Vendor')) { $vend = Resolve-IndirectString $v['Vendor'] }
        $pkgFull = $null
        if ($b.Key -match '\\Packages\\([^\\]+)$') { $pkgFull = $Matches[1] }
        elseif ($b.Key -match '\\PackageId\\([^\\]+)\\') { $pkgFull = $Matches[1] }
        if (-not $pkgFull -and $v.ContainsKey('PackageID')) { $pkgFull = $v['PackageID'] }
        if (-not $pkgFull -and $v.ContainsKey('PackageId')) { $pkgFull = $v['PackageId'] }
        if (-not $pkgFull) { continue }

        $candTexts = @($disp,$desc,$vend,$pkgFull)
        $matched = $false
        foreach ($t in $candTexts) {
          if (-not $t) { continue }
          if (Contains-AllTokensBoundary -text $t -tokens $tokens) { $matched = $true; break }
          if (Matches-OrderedTokens -text $t -tokens $tokens) { $matched = $true; break }
        }
        # Additional fallback: match concatenated token strings inside the alphanumeric candidate.
        if (-not $matched) {
          $flatTokens = @()
          if ($tokens -and $tokens.Count -gt 1) {
            $concat = ($tokens -join '').ToLowerInvariant()
            if ($concat.Length -ge 6) { $flatTokens += $concat }
            $concatNoDigits = ($concat -replace '\d','')
            if ($concatNoDigits -and $concatNoDigits.Length -ge 6) { $flatTokens += $concatNoDigits }
          }
          if ($flatTokens.Count -gt 0) {
            foreach ($ft in $flatTokens) {
              foreach ($ct in $candTexts) {
                if (-not $ct) { continue }
                $cAlpha = ToAlpha $ct
                if ($cAlpha -and ($cAlpha.ToLowerInvariant().Contains($ft))) {
                  $matched = $true
                  break
                }
              }
              if ($matched) { break }
            }
          }
        }
        if (-not $matched) { continue }

        $fam = Derive-UwpFamilyFromFullName $pkgFull
        $nameField = $disp
        if (-not $nameField) { $nameField = $desc }
        if (-not $nameField) { $nameField = $pkgFull }

        # Skip protected UWP packages by name or family.  Avoid targeting
        # critical apps like Minecraft Education during a search.
        $skipEntry = $false
        if ($nameField) {
          foreach ($__pn in $ProtectedUwpNames) {
            if ($__pn -and ($nameField -eq $__pn)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry -and $fam) {
          foreach ($__pf in $ProtectedUwpFamilies) {
            if ($__pf -and ($fam -eq $__pf)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry) {
          $hits += [pscustomobject]@{
            Name               = $nameField
            PackageFullName    = $pkgFull
            PackageFamilyName  = $fam
            RegistryDisplayName = $disp
            Description        = $desc
            Publisher          = $vend
            Source             = 'UsrClassHive'
            ProfilePath        = $p.ProfilePath
            SID                = $p.SID
            RegistryKey        = $b.Key
          }
        }
      }
    } catch {
      # ignore
    } finally {
      Unmount-UsrClassHive -MountName $mount -TmpCopy $tmpCopy
    }
  }

  # de-dupe by PFN
  $out = @()
  foreach ($h in $hits) {
    if (-not $h.PackageFamilyName) { continue }
    $exists = $false
    foreach ($o in $out) {
      if ($o.PackageFamilyName -eq $h.PackageFamilyName) { $exists = $true; break }
    }
    if (-not $exists) { $out += $h }
  }
  $out
}
function Find-UwpByRegistryTokens {
  param(
    [string]$name,
    [string]$activeSid
  )
  # Search the Windows registry for UWP packages whose names, display names
  # or publishers match the provided tokens.  Unlike the simpler
  # implementation, this version consolidates machine-wide and per-user
  # repositories, derives the correct package family name from the full
  # package name (PFN) and uses the same ordered-token and fallback
  # matching logic as the main UWP search.
  $results = @()
  $tokens = Get-NameTokens $name
  if (-not (Is-StrongTokenSet $tokens)) { return $results }

  # Build the list of registry roots to inspect.  Include the machine-wide
  # repository (installed for all users), the AppxAllUserStore keys and
  # each user-specific repository.  This ensures packages provisioned for
  # all users or individual users are considered.
  $pathsToScan = @(
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications",
    # Classes roots can expose registry-backed UWP packages even when per-user hives are restricted
    "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
  )
  $sidList = @()
  if ($activeSid) { $sidList += $activeSid }
  $sidList += Get-HkuSids
  $sidList = $sidList | Where-Object { $_ } | Sort-Object -Unique
  foreach ($sid in $sidList) {
    $pathsToScan += "Registry::HKEY_USERS\\$sid\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"
    $pathsToScan += "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications"
  }
  foreach ($path in ($pathsToScan | Sort-Object -Unique)) {
    try {
      # Enumerate candidate keys.  Some repositories store the DisplayName
      # one level deeper (e.g. AppxAllUserStore\Applications\<pfn>\<version>).  Walk
      # one additional level when scanning those paths without doing a full
      # recursive scan to keep performance acceptable.
      $items = @()
      $level1 = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue)
      $items += $level1
      if ($path -like '*AppxAllUserStore\\Applications*') {
        foreach ($k1 in $level1) {
          try { $items += @(Get-ChildItem -Path $k1.PSPath -ErrorAction SilentlyContinue) } catch {}
        }
      }
      foreach ($pkg in $items) {
        $keyName = $pkg.PSChildName
        if (-not $keyName) { continue }
        $props = $null
        try { $props = Get-ItemProperty -Path $pkg.PSPath -ErrorAction SilentlyContinue } catch {}
        $display    = $null
        $pkgName    = $null
        $packageId  = $null
        $publisher  = $null
        if ($props) {
          if ($props.PSObject.Properties['DisplayName'])          { $display   = Resolve-IndirectString $props.DisplayName }
          if ($props.PSObject.Properties['PackageName'])          { $pkgName   = $props.PackageName }
          if ($props.PSObject.Properties['PackageID'])            { $packageId = $props.PackageID }
          if ($props.PSObject.Properties['PublisherDisplayName']) { $publisher = $props.PublisherDisplayName }
        }
        # Collect candidate texts for matching.  Include the key name, PackageID,
        # PackageName, display name and publisher, plus all string values in
        # the property bag.  De-dupe later for performance.
        $candidateTexts = New-Object System.Collections.Generic.List[string]
        if ($display)   { $candidateTexts.Add($display)   | Out-Null }
        if ($packageId) { $candidateTexts.Add($packageId) | Out-Null }
        if ($pkgName)   { $candidateTexts.Add($pkgName)   | Out-Null }
        if ($publisher) { $candidateTexts.Add($publisher) | Out-Null }
        $candidateTexts.Add($keyName) | Out-Null
        if ($props) {
          foreach ($pr in $props.PSObject.Properties) {
            try {
              if ($pr.Value -is [string] -and $pr.Value) {
                $candidateTexts.Add($pr.Value) | Out-Null
              }
            } catch {}
          }
        }
        # Remove empty and duplicate candidate texts
        $candidateTexts = @($candidateTexts.ToArray() | Where-Object { $_ } | Sort-Object -Unique)
        # Perform ordered token matching on any candidate
        $hit = $false
        foreach ($t in $candidateTexts) {
          if (-not $t) { continue }
          if (Matches-OrderedTokens -text $t -tokens $tokens) {
            $hit = $true
            break
          }
        }
        # Fallback: all tokens must appear in any candidate, regardless of order
        if (-not $hit) {
          foreach ($t in $candidateTexts) {
            if (-not $t) { continue }
            if (Contains-AllTokensBoundary -text $t -tokens $tokens) {
              $hit = $true
              break
            }
          }
        }
        # Additional fallback: match concatenated token strings inside the alphanumeric candidate.
        # Some UWP packages use collapsed naming (e.g. AngryBirds2) where tokens do not
        # appear separated by punctuation or spaces.  Build concatenated search tokens
        # and check if they appear in the candidate's alphanumeric string.
        if (-not $hit) {
          $flatTokens = @()
          if ($tokens -and $tokens.Count -gt 1) {
            $concat = ($tokens -join '').ToLowerInvariant()
            if ($concat.Length -ge 6) { $flatTokens += $concat }
            $concatNoDigits = ($concat -replace '\d','')
            if ($concatNoDigits -and $concatNoDigits.Length -ge 6) { $flatTokens += $concatNoDigits }
          }
          if ($flatTokens.Count -gt 0) {
            foreach ($ft in $flatTokens) {
              foreach ($ct in $candidateTexts) {
                if (-not $ct) { continue }
                $cAlpha = ToAlpha $ct
                if ($cAlpha -and ($cAlpha.ToLowerInvariant().Contains($ft))) {
                  $hit = $true
                  break
                }
              }
              if ($hit) { break }
            }
          }
        }
        if (-not $hit) { continue }
        # Derive the package family name from the full package name or key name.
        # If the string already looks like a PFN (Name_PublisherId) keep it.  Otherwise
        # derive from a full name like Name_Version_Arch_ResourceId_PublisherId.
        $sourceForFam = $packageId
        if (-not $sourceForFam) { $sourceForFam = $keyName }
        $fam = $null
        if ($sourceForFam -match '^[^_]+_[^_]+$') {
          $fam = $sourceForFam
        } else {
          $parts = $sourceForFam -split '_'
          if ($parts.Length -ge 2 -and $parts[0] -and $parts[$parts.Length-1]) {
            $fam = "$($parts[0])_$($parts[$parts.Length-1])"
          } elseif ($parts.Length -ge 1 -and $parts[0]) {
            $fam = $parts[0]
          }
        }
        # Prefer a friendly display name when the registry provides it.
        $friendly = $null
        if ($display -and -not (Is-GenericProductName $display)) { $friendly = $display }
        elseif ($pkgName -and -not (Is-GenericProductName $pkgName)) { $friendly = $pkgName }
        # Determine fields for the result
        $nameField = $null
        if ($friendly) { $nameField = $friendly }
        elseif ($pkgName) { $nameField = $pkgName }
        elseif ($display) { $nameField = $display }
        else { $nameField = $keyName }
        $descField = $friendly
        if (-not $descField) { $descField = $display }
        if (-not $descField) { $descField = $nameField }
        # Skip protected UWP packages by name or family.  This prevents
        # critical apps like Minecraft Education from being targeted by a search.
        $skipEntry = $false
        if ($nameField) {
          foreach ($__pn in $ProtectedUwpNames) {
            if ($__pn -and ($nameField -eq $__pn)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry -and $fam) {
          foreach ($__pf in $ProtectedUwpFamilies) {
            if ($__pf -and ($fam -eq $__pf)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry) {
          $results += [pscustomobject]@{
            Name                 = $nameField
            PackageFamilyName    = $fam
            PublisherDisplayName = $publisher
            Description          = $descField
            RegistryDisplayName  = $display
          }
        }
      }
    } catch {}
  }
  return $results
}

#
# Find-UwpByName
#
# Performs a simplified search for UWP packages by looking for the search term
# as a case-insensitive substring in any string property of package registry
# entries.  This is a more permissive fallback than token matching and
# helps detect titles like 'Angry Birds 2' when searching for 'Angry Birds'.
function Find-UwpByName {
  param([string]$search)
  $results = @()
  if ([string]::IsNullOrWhiteSpace($search)) { return $results }
  $tokens = Get-NameTokens $search
  if (-not (Is-StrongTokenSet $tokens)) { return $results }

  $searchLower = $search.ToLowerInvariant()

  # Build list of registry paths to scan.  Include machine-wide and per-user
  # package repositories under the AppModel and Appx stores.  Also include
  # the Classes roots (HKCR and HKLM\SOFTWARE\Classes) to cover scenarios
  # where the Local Settings hive is materialized there.  Deduplicate later.
  $pathsToScan = @(
    "Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages",
    "Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications",
    "Registry::HKEY_CLASSES_ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages",
    "Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"
  )
  # Include per-user repositories
  $sidList = Get-HkuSids
  foreach ($sid in $sidList) {
    $pathsToScan += "Registry::HKEY_USERS\\$sid\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"
    $pathsToScan += "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications"
  }
  foreach ($path in ($pathsToScan | Sort-Object -Unique)) {
    try {
      $items = @()
      try {
        $level1 = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue)
      } catch { $level1 = @() }
      $items += $level1
      # For AppxAllUserStore and Repository\Packages paths, walk one additional level
      # because some display values are stored on a nested child key.  Avoid a
      # full recursive traversal for performance.
      if ($path -like '*AppxAllUserStore\\Applications*' -or $path -like '*AppModel\\Repository\\Packages*') {
        foreach ($k1 in $level1) {
          try { $items += @(Get-ChildItem -Path $k1.PSPath -ErrorAction SilentlyContinue) } catch {}
        }
      }
      foreach ($pkg in $items) {
        $keyName = $pkg.PSChildName
        $props = $null
        try { $props = Get-ItemProperty -Path $pkg.PSPath -ErrorAction SilentlyContinue } catch {}
        if (-not $props -and -not $keyName) { continue }
        $candidateTexts = New-Object System.Collections.Generic.List[string]
        # Add all string properties
        if ($props) {
          foreach ($pr in $props.PSObject.Properties) {
            try {
              if ($pr.Value -is [string] -and $pr.Value) {
                $candidateTexts.Add($pr.Value) | Out-Null
              }
            } catch {}
          }
        }
        if ($keyName) { $candidateTexts.Add($keyName) | Out-Null }
        $candidateTexts = @($candidateTexts.ToArray() | Where-Object { $_ } | Sort-Object -Unique)
        $hit = $false
        foreach ($t in $candidateTexts) {
          if (-not $t) { continue }
          $ts = $t.ToString()
          if (-not $ts) { continue }

          if (Matches-OrderedTokens -text $ts -tokens $tokens) { $hit = $true; break }
          if (Contains-AllTokensBoundary -text $ts -tokens $tokens) { $hit = $true; break }

          # Safe single-token fallback for numeric/punctuation variants
          if (-not $hit -and $tokens.Count -eq 1 -and $tokens[0].Length -ge 4) {
            $pat = '(?i)(?<![a-z0-9])' + [regex]::Escape($tokens[0]) + '[a-z0-9]*'
            if ([regex]::IsMatch($ts, $pat)) { $hit = $true; break }
          }
        }
        # Additional fallback: match concatenated token strings inside the alphanumeric candidate.
        # Build concatenated search tokens and check if they appear in the candidate's alphanumeric string.
        if (-not $hit) {
          $flatTokens = @()
          if ($tokens -and $tokens.Count -gt 1) {
            $concat = ($tokens -join '').ToLowerInvariant()
            if ($concat.Length -ge 6) { $flatTokens += $concat }
            $concatNoDigits = ($concat -replace '\d','')
            if ($concatNoDigits -and $concatNoDigits.Length -ge 6) { $flatTokens += $concatNoDigits }
          }
          if ($flatTokens.Count -gt 0) {
            foreach ($ft in $flatTokens) {
              foreach ($ct in $candidateTexts) {
                if (-not $ct) { continue }
                $cAlpha = ToAlpha $ct
                if ($cAlpha -and ($cAlpha.ToLowerInvariant().Contains($ft))) {
                  $hit = $true
                  break
                }
              }
              if ($hit) { break }
            }
          }
        }
        if (-not $hit) { continue }
        # Extract fields similar to Find-UwpByRegistryTokens
        $packageId = $null
        $pkgName   = $null
        $display   = $null
        $publisher = $null
        if ($props) {
          # Some registries use PackageID and some use PackageId.  Prefer the
          # value that exists.  The PSObject accessor treats property names
          # case-insensitively but we explicitly check both for clarity.
          if ($props.PSObject.Properties['PackageID']) { $packageId = $props.PackageID }
          elseif ($props.PSObject.Properties['PackageId']) { $packageId = $props.PackageId }
          if ($props.PSObject.Properties['PackageName']) { $pkgName = $props.PackageName }
          if ($props.PSObject.Properties['DisplayName']) { $display = Resolve-IndirectString $props.DisplayName }
          if ($props.PSObject.Properties['PublisherDisplayName']) { $publisher = $props.PublisherDisplayName }
        }
        # Determine PFN using the same logic as in Find-UwpByRegistryTokens.
        $sourceForFam = $null
        if ($packageId) { $sourceForFam = $packageId }
        else { $sourceForFam = $keyName }
        $fam = $null
        if ($sourceForFam -match '^[^_]+_[^_]+$') {
          $fam = $sourceForFam
        } else {
          $parts = $sourceForFam -split '_'
          if ($parts.Length -ge 2 -and $parts[0] -and $parts[$parts.Length-1]) {
            $fam = "${($parts[0])}_${($parts[$parts.Length-1])}"
          } elseif ($parts.Length -ge 1 -and $parts[0]) {
            $fam = $parts[0]
          }
        }
        $friendly = $null
        if ($display -and -not (Is-GenericProductName $display)) { $friendly = $display }
        elseif ($pkgName -and -not (Is-GenericProductName $pkgName)) { $friendly = $pkgName }
        $nameField = $null
        if ($friendly) { $nameField = $friendly }
        elseif ($pkgName) { $nameField = $pkgName }
        elseif ($display) { $nameField = $display }
        else { $nameField = $keyName }
        $descField = $friendly
        if (-not $descField) { $descField = $display }
        if (-not $descField) { $descField = $nameField }
        # Skip protected UWP packages by name or family to avoid targeting
        # critical apps like Minecraft Education during a search.
        $skipEntry = $false
        if ($nameField) {
          foreach ($__pn in $ProtectedUwpNames) {
            if ($__pn -and ($nameField -eq $__pn)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry -and $fam) {
          foreach ($__pf in $ProtectedUwpFamilies) {
            if ($__pf -and ($fam -eq $__pf)) { $skipEntry = $true; break }
          }
        }
        if (-not $skipEntry) {
          $results += [pscustomobject]@{
            Name                 = $nameField
            PackageFamilyName    = $fam
            PublisherDisplayName = $publisher
            Description          = $descField
            RegistryDisplayName  = $display
          }
        }
      }
    } catch {}
  }
  return $results
}

# --- Build final target entry ---

$uwpFamiliesFinal = @()
if ($uwpHits -and $uwpHits.Count -gt 0) {
  $uwpFamiliesFinal = @(
    $uwpHits |
      ForEach-Object { $_.PackageFamilyName } |
      Where-Object { $_ } |
      ForEach-Object { $_.ToString() } |
      Sort-Object -Unique
  )
}

if (-not $NameFinal -and $bestArp) {
  $dn = if ($bestArp.DisplayName) { $bestArp.DisplayName } else { $bestArp.KeyName }
  $dn = Sanitize-ArpBaseName $dn
  if ($dn) { $NameFinal = $dn }
}

if (-not $NameFinal -and $arpNameFinal) {
  $base = $arpNameFinal.TrimEnd('*')
  $base = Sanitize-ArpBaseName $base
  if ($base) { $NameFinal = $base }
}

if (-not $NameFinal -and $PrimaryExeIdentity -and
    $PrimaryExeIdentity.ProductName -and
    -not (Is-GenericProductName $PrimaryExeIdentity.ProductName)) {
  $NameFinal = $PrimaryExeIdentity.ProductName
}
  # If we have not yet selected a final name and a NameCandidate was set earlier,
  # prefer the candidate (e.g., a UWP display name) before deriving a name from
  # the package family name.  This ensures human-friendly names (like "Angry Birds 2")
  # are chosen over raw PFN-derived names when available.
  if (-not $NameFinal -and $NameCandidate) {
    $NameFinal = $NameCandidate
  }

  # Derive a name from the first UWP family if still no name set.
  if (-not $NameFinal -and $uwpFamiliesFinal.Count -gt 0) {
    $pfNameFinal = Derive-Name-From-Pfn $uwpFamiliesFinal[0]
    if ($pfNameFinal) { $NameFinal = $pfNameFinal }
  }

  # If no UWP families were discovered via Get-AppxPackage or registry search,
  # and no ARP uninstall entry was found, attempt to promote a path anchor
  # that looks like a legitimate package family name.  Valid UWP package
  # family names follow the pattern <name>_<publisherId>, where the
  # publisherId is a derived hash and therefore always includes an underscore.
  # See Microsoft documentation for details.  We
  # therefore require an underscore to be present somewhere after the
  # leading dot-separated segments and avoid promoting generic strings like
  # "now.gg" or other publisher names that happen to contain a dot.  Only
  # the first matching anchor is used.  Additionally, we skip this promotion
  # entirely if a plausible ARP entry exists, since applications rarely
  # present both a classic uninstall entry and a UWP package.
  if ($uwpFamiliesFinal.Count -eq 0 -and -not $bestArp -and -not $arpNameFinal) {
    foreach ($a in $anchorSet) {
      if ($a) {
        # Skip Windows Error Reporting (WER) crash identifiers such as
        # "AppCrash_*". These strings are not package families and would
        # otherwise satisfy the underscore heuristic.  Do not promote them.
        if ($a -like 'AppCrash_*') { continue }

        # Require the anchor to start with alphanumeric characters, contain a dot,
        # and have at least one underscore following the dot.  This matches
        # package family names like "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2" while
        # excluding domains like "now.gg" or "example.com" which lack
        # underscores.  We also avoid matching names with whitespace or commas.
        if ($a -match '^[A-Za-z0-9][A-Za-z0-9\.]*_[^,\s]+$' -and ($a -match '\.') ) {
          $uwpFamiliesFinal = @($a)
          break
        }
      }
    }
  }

  # Finally fall back to the raw search term if no name has been determined.
  if (-not $NameFinal) {
    $NameFinal = $AppName
  }

$PathAnchorsRaw = @()
foreach ($a in $anchorSet) {
  if ($a) { $PathAnchorsRaw += $a }
}
if ($uwpFamiliesFinal.Count -gt 0) {
  $PathAnchorsRaw = Compress-UwpAnchors $PathAnchorsRaw
}

  # Convert the raw path anchors to an array up front. Wrapping with @() prevents
  # a single item from being collapsed into a scalar string. Then normalize via
  # Simplify-Anchors and wrap again to ensure an array result.
  $PathAnchors = @($PathAnchorsRaw | Sort-Object -Unique)
  $PathAnchors = @(Simplify-Anchors $PathAnchors)

$targetEntry = [pscustomobject]@{
  Name                  = $NameFinal
  UWPFamily             = $uwpFamiliesFinal
  ARPName               = $arpNameFinal
  Publisher             = $pubFinal
  InstallerSignatures   = $InstallerSignatures
  PortableExeSignatures = $PortableExeSignatures
  PathAnchors           = $PathAnchors
}

$outJson  = Get-TargetsJsonPath
$existing = Load-ExistingEntries $outJson

if (-not $existing) {
  $existing = @()
}

$merged   = @()
$didMerge = $false

foreach ($e in $existing) {
  $e.UWPFamily = To-StringArray $e.UWPFamily
  $e.PathAnchors = To-StringArray $e.PathAnchors

  if ($e.PSObject.Properties['Installer']) {
    $e.PSObject.Properties.Remove('Installer')
  }

  if (-not $e.PSObject.Properties['InstallerSignatures']) {
    $e | Add-Member -NotePropertyName 'InstallerSignatures' -NotePropertyValue $null -Force
  } elseif ($e.InstallerSignatures -is [System.Array]) {
    $e.InstallerSignatures = Build-InstallerSignature $e.InstallerSignatures
  }

  if (-not $e.PSObject.Properties['PortableExeSignatures']) {
    $e | Add-Member -NotePropertyName 'PortableExeSignatures' -NotePropertyValue $null -Force
  }

  if (-not $e.PSObject.Properties['UWPFamily']) {
    $e | Add-Member -NotePropertyName 'UWPFamily' -NotePropertyValue $null -Force
  }

  if (-not $e.PSObject.Properties['ARPName']) {
    $e | Add-Member -NotePropertyName 'ARPName' -NotePropertyValue $null -Force
  }

  if (-not $e.PSObject.Properties['Publisher']) {
    $e | Add-Member -NotePropertyName 'Publisher' -NotePropertyValue $null -Force
  }

  # Merge only when the friendly Name matches exactly; this prevents unrelated
  # apps from being merged together.
  if ($e.Name -and $targetEntry.Name -and ($e.Name -eq $targetEntry.Name)) {
    $didMerge = $true

    # Prefer freshly-discovered ARP/UWP/publisher when present
    $e.UWPFamily = Union-StringArrays (To-StringArray $e.UWPFamily) (To-StringArray $targetEntry.UWPFamily)
    $e.UWPFamily = $e.UWPFamily | Sort-Object -Unique
    if ($targetEntry.ARPName)   { $e.ARPName   = $targetEntry.ARPName }
    if ($targetEntry.Publisher) { $e.Publisher = $targetEntry.Publisher }

    # Union of anchors and installer signatures
    $e.PathAnchors         = Simplify-Anchors (Union-StringArrays $e.PathAnchors $targetEntry.PathAnchors)
    $e.InstallerSignatures = Merge-InstallerSignature $e.InstallerSignatures $targetEntry.InstallerSignatures

    # Prefer the most recent portable signatures if present
    if ($targetEntry.PortableExeSignatures) {
      $e.PortableExeSignatures = $targetEntry.PortableExeSignatures
    }

    if (-not (Is-EmptyTarget $e)) {
      $merged += $e
    }
  }
  else {
    # Different Name → keep the existing entry as-is
    $merged += $e
  }
}

if (-not $didMerge -and -not (Is-EmptyTarget $targetEntry)) {
  $merged += $targetEntry
}

foreach ($m in $merged) {
  if (-not $m.PSObject.Properties['Name']) {
    $m | Add-Member -NotePropertyName 'Name' -NotePropertyValue '' -Force
  } elseif ($m.Name -ne $null -and ($m.Name -isnot [string])) {
    $m.Name = $m.Name.ToString()
  }

  if (-not $m.PSObject.Properties['UWPFamily']) {
    $m | Add-Member -NotePropertyName 'UWPFamily' -NotePropertyValue @() -Force
  }
  $m.UWPFamily = To-StringArray $m.UWPFamily
  $m.UWPFamily = $m.UWPFamily | Sort-Object -Unique


  $m.PathAnchors = To-StringArray $m.PathAnchors

  if ($m.InstallerSignatures) {
    # Normalize the installer signature to ensure string fields are compact and descriptions are normalized
    $m.InstallerSignatures = Normalize-InstallerSignature $m.InstallerSignatures
    # Coerce all scalar properties to strings and ensure FileDescriptions remains an array of strings.  Without
    # this, single-element collections or other IEnumerable implementations can collapse into a single string
    # during JSON conversion.
    $isig = $m.InstallerSignatures
    foreach ($propName in 'ProductName','CompanyName','OriginalFilename','CertThumbprint','SignerSimpleName','InstallerFileName','InstallerPath') {
      if ($isig.$propName) { $isig.$propName = $isig.$propName.ToString() }
    }
    $isig.FileDescriptions = To-StringArray $isig.FileDescriptions
  }


  if ($m.PortableExeSignatures) {
    $psig = $m.PortableExeSignatures
    foreach ($propName in 'ProductName','CompanyName','OriginalFilename','CertThumbprint','SignerSimpleName','InstallerFileName','InstallerPath') {
      if ($psig.$propName) { $psig.$propName = $psig.$propName.ToString() }
    }
    $psig.FileDescriptions = To-StringArray $psig.FileDescriptions
  }
}

$merged = $merged | Sort-Object -Property @{
  Expression = { ($_.Name -as [string]).ToLowerInvariant() }
  Ascending  = $true
}

$jsonOut = $merged | ConvertTo-Json -Depth 10
$jsonOut = $jsonOut -replace '\\u0027', "'"
Set-Content -Path $outJson -Value $jsonOut -Encoding UTF8
Write-Host "Results written to: $outJson"
Write-Host "=== Recognizer done ==="
