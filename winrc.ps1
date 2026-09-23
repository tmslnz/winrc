# Set-StrictMode -Version
$progressPreference = 'SilentlyContinue'

# PowerShell 7 and Windows PowerShell 5.1 both honor RemoteSigned, which lets a
# freshly-downloaded winrc.ps1 run after the user approves it once. Attempt that in
# the CurrentUser scope only, and only when the effective policy is not already
# permissive. We deliberately never fail or warn here: when a more-specific scope
# (group policy, or a -Bypass/-Unrestricted launch) overrides our request, the
# running session is already able to execute this script, so there is nothing to fix.
try {
    if ((Get-ExecutionPolicy) -ne 'RemoteSigned' -and (Get-ExecutionPolicy) -ne 'Bypass' -and (Get-ExecutionPolicy) -ne 'Unrestricted') {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -ErrorAction SilentlyContinue
    }
}
catch { }

$CachedAppsList = @()
$WINRC_QUIET = $true

# --- Self-update configuration -------------------------------------------------
# Where this script was loaded from (needed to replace it in place on update).
$script:WinrcSourcePath = $PSCommandPath
if (-not $script:WinrcSourcePath -or -not [IO.File]::Exists($script:WinrcSourcePath)) {
    $script:WinrcSourcePath = Join-Path $PSScriptRoot 'winrc.ps1'
}
# Version stamp. Keep in sync with the version released on GitHub.
$script:WinrcVersion = '0.1.0'
# The public repo. Owner/Repo are parsed out of it so one variable drives everything.
$script:WinrcRepo = 'tmslnz/winrc'
# Default update source: 'release' prefers the latest GitHub release tag; on failure
# (or when $UpdateSource -eq 'raw'), falls back to the raw branch file.
$script:WinrcUpdateSource = 'auto'   # 'auto' | 'release' | 'raw'
$script:WinrcBranch = 'main'

# --- Periodic auto-check -------------------------------------------------------
# When $script:WinrcAutoCheck is $true, winrc checks for updates in the background
# on load, at most once per $script:WinrcAutoCheckIntervalDays. The check is silent
# (runs as a background job so it never delays prompt startup), and when an update
# is found it is staged to disk; the new code takes effect on the next new shell
# (the check never force-reloads the running session mid-command).
$script:WinrcAutoCheck = $true
$script:WinrcAutoCheckIntervalDays = 3
# State file remembering the last time a check was performed.
$script:WinrcStateFile = Join-Path $env:LOCALAPPDATA 'winrc\winrc.state.json'

# =============================================================================
# 1. ORCHESTRATION
# =============================================================================

function Main {
    Show-WinrcUpdateNotice
    $actions = @'
Install-PowerShellProfile
Set-ConfigPowershell
Set-ConfigSSH
Set-ConfigWSL1
Set-ConfigWSL2
Set-ConfigNpm
Set-ConfigZoxide
Set-ConfigGit
Set-ConfigRhinoceros
Set-ConfigCyberduck
Set-ConfigPowerToys
'@
    $actions.Replace("`r`n", "`n").Split("`n") | ForEach-Object -Process {
        if ($WINRC_QUIET) {
            $command = [Scriptblock]::Create("$_ > `$null")
        }
        else {
            $command = [Scriptblock]::Create("$_")
            Write-Host $command
        }
        Invoke-Command -ScriptBlock $command
    }
    # Background periodic update check, only when this is a real interactive shell
    # (e.g. a profile load), not when the file is run standalone or via Update-Winrc.
    if ($script:WinrcAutoCheck -and [Environment]::UserInteractive -and $Host.Name -notmatch 'Server|NonInteractive') {
        Start-WinrcUpdateCheck
    }
}

# =============================================================================
# 5. TERMINAL PROMPT
# =============================================================================

function Get-GitPromptStatus {
    <#
    .SYNOPSIS
        Cheap, lazy git status for prompt use. Returns a small object with Branch
        and Dirty, or $null when the current directory is not inside a git work tree.
        Results are cached per working directory so the prompt only spawns git when
        you actually change folders.
    #>
    param(
        [switch]$NoCache
    )
    $here = (Get-Location).Path
    if (-not $NoCache -and $script:GitPromptCache -and $script:GitPromptCache.Path -eq $here) {
        return $script:GitPromptCache.Result
    }

    # Exit fast when git is not installed.
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $script:GitPromptCache = @{ Path = $here; Result = $null }
        return $null
    }

    try {
        $gitDir = & git rev-parse --git-dir 2>$null
        if (-not $gitDir) {
            $script:GitPromptCache = @{ Path = $here; Result = $null }
            return $null
        }
    }
    catch {
        $script:GitPromptCache = @{ Path = $here; Result = $null }
        return $null
    }

    $branch = (& git symbolic-ref --quiet --short HEAD 2>$null)
    if (-not $branch) {
        # Detached HEAD: fall back to a short commit id.
        $branch = (& git rev-parse --short HEAD 2>$null)
    }

    $dirty = $false
    try {
        $di = & git status --porcelain 2>$null
        if ($di) { $dirty = $true }
    }
    catch { }

    $result = [pscustomobject]@{ Branch = $branch; Dirty = $dirty }
    $script:GitPromptCache = @{ Path = $here; Result = $result }
    $result
}

function Get-ShortPath {
    <#
    .SYNOPSIS
        Shorten a path for display. Replaces the $HOME prefix with '~' and collapses
        the middle segments of long paths to an ellipsis, keeping the leaf component.
    #>
    param(
        [string]$Path
    )
    $homePrefix = $HOME.TrimEnd('\', '/')
    $p = $Path
    if ($p.StartsWith($homePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $p = '~' + $p.Substring($homePrefix.Length)
    }
    # Allow a reasonably long path before we trim.
    if ($p.Length -le 44) { return $p }
    $parts = $p -split '[\\/]'
    if ($parts.Count -lt 3) { return $p }
    $head = $parts[0..1]
    $tail = $parts[($parts.Count - 2)..($parts.Count - 1)]
    ($head -join '/') + '/…/' + ($tail -join '/')
}

function prompt {
    # Success/failure state of the previous command. We read this from $? (via
    # $global:LASTEXITCODE) because $LASTEXITCODE alone is set only by external
    # commands; builtins like `cd` never touch it, so a clean `cd .` would keep
    # showing a stale error. $? is updated for both builtins and externals.
    $ok = $global:?
    $code = $global:LASTEXITCODE
    $prefix = $(
        if (Test-IsDebug) { '[DEBUG] ' }
        elseif (Test-IsAdmin) { '[ADMIN] ' }
        else { '' }
    )
    $user = $(Get-Username)
    $hostname = [System.Net.Dns]::GetHostName()
    $cwd = Get-ShortPath (Get-Location).Path
    # Exit-code indicator: red (code) on failure, nothing on success.
    if (-not $ok) {
        if ($null -ne $code -and $code -ne 0) {
            $status = "$($PSStyle.Foreground.Red)($code)$($PSStyle.Reset) "
        }
        else {
            $status = ""
        }
    }
    else {
        $status = ""
    }

    # Git segment (lazy).
    $git = Get-GitPromptStatus
    $gitSeg = ''
    if ($git -and $git.Branch) {
        $color = if ($git.Dirty) { $PSStyle.Foreground.Yellow } else { $PSStyle.Foreground.Cyan }
        $mark = if ($git.Dirty) { ' *' } else { '' }
        $gitSeg = " $($PSStyle.Dim)($($PSStyle.Reset)$color$($git.Branch)$mark$($PSStyle.Reset)$($PSStyle.Dim))$($PSStyle.Reset)"
    }

    $who = "$($PSStyle.Bold)${user}@$($PSStyle.Dim)${hostname}$($PSStyle.Reset)"
    $where = "$($PSStyle.Bold):$($PSStyle.Reset)${cwd}"
    $suffix = $(if ($NestedPromptLevel -ge 1) { "$($PSStyle.Dim)$ $($PSStyle.Reset)" }) + "$($PSStyle.Dim)$([char]0x25CF)$($PSStyle.Reset) "
    "${prefix}${status}${who}${where}${gitSeg} ${suffix}"
}

# =============================================================================
# 4. APP CONFIGURATION SETTERS
# =============================================================================

function Set-ConfigPowershell {
    <#
    Reverse Search
    https://stackoverflow.com/a/62891313
    #>
    Set-PSReadLineOption -HistorySearchCursorMovesToEnd
    Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadlineKeyHandler -Key Tab -Function Complete
}

function Set-ConfigZoxide {
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command zoxide -ErrorAction SilentlyContinue)) { return }
    Invoke-Expression (& {
            $hook = if ($PSVersionTable.PSVersion.Major -ge 6) {
                'pwd'
            }
            else {
                'prompt'
            } (zoxide init powershell --hook $hook | Out-String)
        })
}

function Set-ConfigNpm {
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command npm -ErrorAction SilentlyContinue)) { return }
    $file = "$home\.npmrc"
    $config = @'
; BEGIN_SHELLRC
; https://docs.npmjs.com/cli/using-npm/config
save-exact=true
prefer-offline=true
update-notifier=false
fund=false
long=true
; END_SHELLRC
'@
    Set-ConfigSection -String $config -Path $file
}

function Set-ConfigGit {
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command git -ErrorAction SilentlyContinue)) { return }
    $file = "$home\.config\git\config"
    $config = @'
# BEGIN_SHELLRC
[init]
    defaultBranch = main

[core]
    autocrlf = true
    eol = native
    sshCommand = C:/Windows/System32/OpenSSH/ssh.exe
    # https://git-scm.com/docs/git-config#Documentation/git-config.txt-corewhitespace
    whitespace = space-before-tab,trailing-space
    # https://git-scm.com/docs/git-config#Documentation/git-config.txt-corequotePath
    quotepath = false
    bigFileThreshold = 64m

[safe]
    directory = *

[filter "lfs"]
    clean = git-lfs clean -- %f
    smudge = git-lfs smudge -- %f
    process = git-lfs filter-process
    required = true

[merge]
    # Include summaries of merged commits in newly created merge commit messages
    log = true

[credential]
    helper = wincred

[push]
    default = simple

[color]
    ui = auto
# END_SHELLRC
'@
    Set-ConfigSection -String $config -Path $file
    $file = "$home\.config\git\ignore"
    $config = @'
# BEGIN_SHELLRC
# Windows thumbnail cache files
Thumbs.db
Thumbs.db:encryptable
ehthumbs.db
ehthumbs_vista.db

# Dump file
*.stackdump

# Folder config file
[Dd]esktop.ini

# Recycle Bin used on file shares
$RECYCLE.BIN/

# Windows Installer files
*.cab
*.msi
*.msix
*.msm
*.msp

# Windows shortcuts
*.lnk
# END_SHELLRC
'@
    Set-ConfigSection -String $config -Path $file
    $file = "$home\.config\git\attributes"
    $config = @'
# BEGIN_SHELLRC

# END_SHELLRC
'@
    Set-ConfigSection -String $config -Path $file
}

function Set-ConfigRhinoceros {
    <#
    # TODO
    $hosts = [Environment]::SystemDirectory + '\drivers\etc\hosts'
    #>
}

function Set-ConfigWSL1 {
    <#
    # TODO
    #>
}

function Set-ConfigWSL2 {
    <#
    # TODO
    #>
}

function Set-ConfigSSH {
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command ssh -ErrorAction SilentlyContinue)) { return }
    $file = "$home\.ssh\config"
    $config = @'
# BEGIN_SHELLRC

Host *
ServerAliveInterval 60
ServerAliveCountMax 240
Compression yes
# CVE-2016-0777, CVE-2016-0778
UseRoaming no
IgnoreUnknown AddKeysToAgent,UseKeychain
# Store passphrases in Keychain
AddKeysToAgent yes
UseKeychain yes

# END_SHELLRC
'@
    Set-ConfigSection -String $config -Path $file
}

function Set-ConfigCyberduck {
    <#
    TODO
    C:\Users\tmslnz\AppData\Roaming\Cyberduck\Cyberduck.user.config

    <setting name="update.check" value="false" />
    <setting name="queue.window.open.default" value="false" />
    <setting name="editor.alwaysusedefault" value="true" />
    <setting name="editor.bundleidentifier" value="c:\program files\sublime text\sublime_text.exe" />
    <setting name="browser.doubleclick.edit" value="true" />
    <setting name="browser.enterkey.rename" value="true" />
    <setting name="browser.move.confirm" value="false" />
    <setting name="bookmark.toggle.options" value="true" />
    #>
    $Path = "$Home\AppData\Roaming\Cyberduck\Cyberduck.user.config"
    if (! [System.IO.File]::Exists("$Path")) { return $false }
    $xml = New-Object XML
    $xml.Load("$Path")
    $nodes = $xml.SelectNodes('//setting[@name="CdSettings"]/value/settings/setting')
    $nodes
}

function Set-ConfigPowerToys {
    <#
    $ TODO
    C:\Users\tmslnz\AppData\Local\Microsoft\PowerToys\Keyboard Manager
    #>
}

function Set-ConfigExplorer {
    # Make AppData folder visible
    $appData = Split-Path $env:APPDATA -Parent
    Set-ItemProperty -Path $appData -Name Attributes -Value Normal
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f
    $value = @'
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]

; Show all file extensions
"HideFileExt"=dword:00000000

; Show hidden files
"Hidden"=dword:00000002

; Displays compressed and encrypted NTFS files in color
"ShowCompColor"=dword:00000001

; Do not change case of path elements
"DontPrettyPath"=dword:00000001

; Allow bottom-right hover to show Desktop
"DisablePreviewDesktop"=dword:00000000

; Group when full
"TaskbarGlomLevel"=dword:00000001

;"AlwaysShowMenus"=dword:00000001
;"AutoCheckSelect"=dword:00000000
;"DontUsePowerShellOnWinX"=dword:00000000
;"ExtendedUIHoverTime"=dword:00000190
;"Filter"=dword:00000000
;"HideIcons"=dword:00000000
;"HideMergeConflicts"=dword:00000000
;"IconsOnly"=dword:00000000
;"LastActiveClick"=dword:00000001
;"LaunchTo"=dword:00000001
;"ListviewAlphaSelect"=dword:00000001
;"ListviewShadow"=dword:00000001
;"MapNetDrvBtn"=dword:00000000
;"NavPaneExpandToCurrentFolder"=dword:00000000
;"NavPaneShowAllFolders"=dword:00000001
;"OnboardUnpinCortana"=dword:00000001
;"ReindexedProfile"=dword:00000001
;"SeparateProcess"=dword:00000000
;"ServerAdminUI"=dword:00000000
;"ShowCortanaButton"=dword:00000000
;"ShowEncryptCompressedColor"=dword:00000001
;"ShowInfoTip"=dword:00000001
;"ShowStatusBar"=dword:00000001
;"ShowSuperHidden"=dword:00000001
;"ShowTaskViewButton"=dword:00000000
;"ShowTypeOverlay"=dword:00000001
;"Start_SearchFiles"=dword:00000002
;"Start_TrackDocs"=dword:00000001
;"Start_TrackProgs"=dword:00000000
;"StartMenuInit"=dword:0000000d
;"StartMigratedBrowserPin"=dword:00000001
;"StoreAppsOnTaskbar"=dword:00000001
;"TaskbarAnimations"=dword:00000001
;"TaskbarAutoHideInTabletMode"=dword:00000000
;"TaskbarBadges"=dword:00000001
;"TaskbarSizeMove"=dword:00000000
;"TaskbarSmallIcons"=dword:00000000
;"WebView"=dword:00000001

; Disable "~/3D Objects"
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}]
'@
    Import-RegSettings $value
}

function Set-ConfigWindows {
    <#
    https://howtomanagedevices.com/windows-10/3654/how-to-disable-privacy-settings-experience-at-first-sign-in-in-windows-10/
    #>
    $value = @'
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock]
"AllowDevelopmentWithoutDevLicense"=dword:00000001
"AllowAllTrustedApps"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy]
"HasAccepted"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo]
"Enabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\International]
"AcceptLanguage"=-
[HKEY_CURRENT_USER\Control Panel\International\User Profile]
"HttpAcceptLanguageOptOut"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_TrackProgs"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SubscribedContent-338393Enabled"=dword:00000000
"SubscribedContent-353694Enabled"=dword:00000000
"SubscribedContent-353696Enabled"=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location]
"Value"="Deny"

'@
    Import-RegSettings $value
}

function Set-ConfigKeyboard {
    # https://superuser.com/questions/1264164/how-to-map-windows-key-to-ctrl-key-on-windows-10
    $value = @'
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Keyboard Layout]
"Scancode Map"=hex:00,00,00,00,00,00,00,00,03,00,00,00,5B,E0,3A,00,1D,00,5B,E0,00,00,00,00
'@
    Import-RegSettings $value
}

# =============================================================================
# 3. SHELLRC CONFIG-BLOCK HELPERS
# =============================================================================

function Set-ConfigSection {
    <#
    .SYNOPSIS
        Writes an idempotent "SHELLRC" fenced block into a config file.
    .DESCRIPTION
        The block is delimited by BEGIN_SHELLRC / END_SHELLRC markers inside a
        comment line whose first character is one of # ; / . This function:
          - creates the file (and its parent dirs) if it does not exist,
          - replaces the existing block in place if the markers are already present,
          - otherwise prepends (default) or appends (-Append) the block once.
        Every call is idempotent: running it twice produces the same file.
    .PARAMETER Path
        The config file to modify.
    .PARAMETER String
        The full block, including the "# BEGIN_SHELLRC" and "# END_SHELLRC" fence lines.
    .PARAMETER Append
        Insert the block at the end of the file instead of the top. Useful for apps
        that read configs top-down and where later values win.
    .PARAMETER Force
        Rewrite the block even when the current content matches (useful after a
        schema change that shouldn't trigger on content hash alone is desired).
    .EXAMPLE
        $b = @'
        # BEGIN_SHELLRC
        save-exact=true
        ; END_SHELLRC
        '@
        Set-ConfigSection -Path "$home\.npmrc" -String $b
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$String,
        [switch]$Append,
        [switch]$Force
    )

    # Normalize line endings in the block to LF for comparison purposes.
    $block = $String.Replace("`r`n", "`n").TrimEnd("`n")

    # Ensure parent directory exists.
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    if (-not [IO.File]::Exists($Path)) {
        # Fresh file: write the block and a trailing newline.
        New-Item -ItemType File -Path $Path -Force | Out-Null
        [IO.File]::WriteAllText($Path, $block + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        return $true
    }

    $content = [IO.File]::ReadAllText($Path)

    # Regex spans the whole fenced block. It tolerates a leading run of comment
    # chars and whitespace before each fence line. Captures what's between them.
    #   ^[ \t]*(?<lead>[#;/])[ \t]*BEGIN_SHELLRC.*?^[ \t]*[#;/][ \t]*END_SHELLRC
    $pattern = '(?ms)^[ \t]*(?<fence>[#;/])[ \t]*BEGIN_SHELLRC.*?^[ \t]*[#;/][ \t]*END_SHELLRC[ \t]*\r?$'
    $m = [regex]::Match($content, $pattern)

    if ($m.Success) {
        # Determine the fence char so we keep the block's own delimiters consistent.
        $lead = $m.Groups['fence'].Value
        # If the caller's block already has markers, use those; else build them.
        if ($block -match '(?m)^[ \t]*[#;/][ \t]*BEGIN_SHELLRC') {
            $newBlock = $block
        }
        else {
            $newBlock = "$lead BEGIN_SHELLRC`n$block`n$lead END_SHELLRC"
        }
        $newBlock = $newBlock.TrimEnd("`n")

        # Normalize both sides (drop trailing CR/LF the regex may have consumed) so
        # idempotent re-runs are detected as "no change".
        $existing = $m.Value.Replace("`r`n", "`n").TrimEnd("`r", "`n")
        $newBlockN = $newBlock.Replace("`r`n", "`n").TrimEnd("`r", "`n")
        if (-not $Force -and ($existing -eq $newBlockN)) {
            return $false   # no change
        }

        # Remove the matched region and insert the new block. Any line terminator
        # that followed END_SHELLRC (and wasn't consumed by the regex's \r?) stays
        # in $content untouched, so content after the block stays separated.
        $replaced = $content.Remove($m.Index, $m.Length).Insert($m.Index, $newBlock)
        [IO.File]::WriteAllText($Path, $replaced, [Text.UTF8Encoding]::new($false))
        return $true
    }

    # Marker not present: insert the block. Ensure the file ends with a newline
    # before appending, so we don't glue onto the last existing line.
    if ($Append) {
        $sep = if ($content -and -not $content.EndsWith("`n") -and -not $content.EndsWith("`r")) { [Environment]::NewLine } else { '' }
        $new = $content + $sep + $block + [Environment]::NewLine
    }
    else {
        $body = if ($content -and -not $content.EndsWith("`n") -and -not $content.EndsWith("`r")) { [Environment]::NewLine + $content } else { $content }
        $new = $block + [Environment]::NewLine + $body
    }
    [IO.File]::WriteAllText($Path, $new, [Text.UTF8Encoding]::new($false))
    return $true
}

# =============================================================================
# 2. SELF-UPDATE & PERIODIC AUTO-CHECK
# =============================================================================

function Update-Winrc {
    <#
    .SYNOPSIS
        Self-update winrc.ps1 from a public GitHub repo.
        Prefers the latest tagged release, falling back to the raw branch file.
    .DESCRIPTION
        Downloads the remote winrc.ps1 into a temp file, compares it to the running
        copy (by content hash). If identical, reports "already up to date". If
        different, atomically replaces the file on disk and reloads it into this
        session so the new version takes effect immediately (no shell restart).
    .PARAMETER Force
        Force a re-download and reload even if the on-disk hash matches the remote.
    .PARAMETER CheckOnly
        Report whether an update is available without applying it.
    .PARAMETER Source
        Override the update source for this call: 'auto', 'release', or 'raw'.
    .PARAMETER NoReload
        Update the file on disk but do not reload it into the current session.
        Lets a background check stage the update without disrupting a running
        session; the new code loads on the next new shell.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [switch]$CheckOnly,
        [switch]$NoReload,
        [ValidateSet('auto', 'release', 'raw')]
        [string]$Source = $script:WinrcUpdateSource
    )
    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $remote = $null
    if ($Source -in @('auto', 'release')) {
        try {
            $remote = Get-WinrcRemoteContent -Release
        }
        catch {
            if ($Source -eq 'release') { throw }
            Write-Verbose "Release lookup failed ($($_.Exception.Message)); falling back to raw."
        }
    }
    if (-not $remote -and $Source -in @('auto', 'raw')) {
        $remote = Get-WinrcRemoteContent -Raw
    }

    if (-not $remote) {
        throw 'Could not obtain remote winrc.ps1 from any configured source.'
    }

    $currentText = [IO.File]::ReadAllText($script:WinrcSourcePath)
    $currentHash = Get-FileHashValue -InputObject $currentText
    $needUpdate = $Force -or ($remote.Hash -ne $currentHash)

    if (-not $needUpdate) {
        Write-Host "winrc is up to date (v$script:WinrcVersion)." -ForegroundColor Green
        return
    }

    if ($CheckOnly) {
        Write-Host "Update available (remote $($remote.Hash.Substring(0,8)) != local $($currentHash.Substring(0,8)))." -ForegroundColor Yellow
        return
    }

    # Atomic replace: write to a sibling temp file first, then move over the target.
    $targetDir = Split-Path -Parent $script:WinrcSourcePath
    $targetName = Split-Path -Leaf $script:WinrcSourcePath
    $tmp = Join-Path $targetDir ".$targetName.tmp.$PID"
    try {
        [IO.File]::WriteAllText($tmp, $remote.Content, [Text.UTF8Encoding]::new($false))
        # Preserve any existing file ACL/attributes by removing the temp then moving.
        if ([IO.File]::Exists($script:WinrcSourcePath)) {
            Copy-Item -Path $script:WinrcSourcePath -Destination "$script:WinrcSourcePath.bak" -Force -ErrorAction SilentlyContinue
        }
        Move-Item -Path $tmp -Destination $script:WinrcSourcePath -Force
    }
    catch {
        if ([IO.File]::Exists($tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        throw "Update failed: $($_.Exception.Message)"
    }

    if ($NoReload) {
        Write-Host "winrc updated ($($currentHash.Substring(0,8)) -> $($remote.Hash.Substring(0,8))). Takes effect in a new shell." -ForegroundColor Cyan
        return
    }

    Write-Host "winrc updated ($($currentHash.Substring(0,8)) -> $($remote.Hash.Substring(0,8))). Reloading..." -ForegroundColor Cyan

    # Reload into this session so the new code is live right away.
    . $script:WinrcSourcePath
}

function Get-WinrcRemoteContent {
    <#
    .SYNOPSIS
        Returns a hashtable with Content (string) and Hash (SHA256) of the remote
        winrc.ps1 from either a GitHub release asset or the raw branch file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Release')]
        [switch]$Release,
        [Parameter(Mandatory = $true, ParameterSetName = 'Raw')]
        [switch]$Raw
    )
    $repo = $script:WinrcRepo

    if ($PSCmdlet.ParameterSetName -eq 'Release') {
        # Resolve latest release, then its winrc.ps1 asset via the API (media type = raw body).
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" `
            -Headers @{ 'User-Agent' = 'winrc' } -ErrorAction Stop
        $asset = $release.assets | Where-Object { $_.name -eq 'winrc.ps1' } | Select-Object -First 1
        if (-not $asset) {
            throw "Latest release '$($release.tag_name)' has no 'winrc.ps1' asset."
        }
        $content = Invoke-WebRequest -Uri $asset.browser_download_url -UseBasicParsing -ErrorAction Stop
        return @{ Content = $content.Content; Hash = Get-FileHashValue -InputObject $content.Content }
    }
    else {
        $branch = $script:WinrcBranch
        $url = "https://raw.githubusercontent.com/$repo/$branch/winrc.ps1"
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        return @{ Content = $content.Content; Hash = Get-FileHashValue -InputObject $content.Content }
    }
}

function Get-FileHashValue {
    <#
    .SYNOPSIS
        Returns the lowercase SHA256 hex of a string.
    #>
    param(
        [string]$InputObject
    )
    $sb = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($InputObject)
        $hash = $sb.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sb.Dispose()
    }
}

function Read-WinrcState {
    <#
    .SYNOPSIS
        Reads the winrc state file (a small JSON) or returns an empty default.
    #>
    try {
        if ([IO.File]::Exists($script:WinrcStateFile)) {
            $j = Get-Content -Raw -Path $script:WinrcStateFile | ConvertFrom-Json
            if ($j) { return $j }
        }
    }
    catch { }
    [pscustomobject]@{ LastCheckUtc = $null }
}

function Write-WinrcState {
    param(
        [AllowNull()]
        [datetime]$LastCheckUtc
    )
    try {
        $dir = Split-Path -Parent $script:WinrcStateFile
        if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $obj = [pscustomobject]@{ LastCheckUtc = $LastCheckUtc }
        $obj | ConvertTo-Json | Set-Content -Path $script:WinrcStateFile -Encoding UTF8
    }
    catch { }
}

function Test-WinrcUpdateDue {
    <#
    .SYNOPSIS
        Returns $true when a periodic auto-check should run, based on the last check
        time stored in the state file. Returns $false when disabled or not yet due.
    #>
    if (-not $script:WinrcAutoCheck) { return $false }
    $state = Read-WinrcState
    if ($null -eq $state.LastCheckUtc -or '' -eq ([string]$state.LastCheckUtc)) { return $true }
    try {
        $last = [datetime]$state.LastCheckUtc
        $due = $last.AddDays($script:WinrcAutoCheckIntervalDays)
        return [datetime]::UtcNow -ge $due
    }
    catch {
        return $true   # unreadable timestamp -> just check
    }
}

function Start-WinrcUpdateCheck {
    <#
    .SYNOPSIS
        Kicks off the periodic self-update check if it is due.
    .DESCRIPTION
        Runs the actual check as a background job so it never delays prompt startup.
        When an update is found it is staged to disk (no in-session reload) and a
        one-shot notice marker is written; the new code takes effect the next time a
        shell starts. The check time is recorded regardless of outcome so we don't
        re-attempt on every launch.
    #>
    if (-not (Test-WinrcUpdateDue)) { return }

    # Record the attempt before launching so a slow/offline check can't cause us to
    # busy-retry on every subsequent prompt.
    Write-WinrcState -LastCheckUtc ([datetime]::UtcNow)

    $noticePath = Join-Path (Split-Path -Parent $script:WinrcStateFile) 'update-staged.txt'
    # The job stages the update and drops a marker file that Main picks up on the
    # next shell to print a one-time notice. (Events tied to a job's session can
    # leak, so a marker file is more robust.)
    try {
        Start-Job -ScriptBlock {
            param($srcPath, $repo, $branch, $noticePath)
            function Get-FileHashValue {
                param([string]$InputObject)
                $sb = [Security.Cryptography.SHA256]::Create()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($InputObject)
                    $hash = $sb.ComputeHash($bytes)
                    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
                }
                finally { $sb.Dispose() }
            }
            # Raw-branch check is used for the periodic pass (release lookup would
            # need two network calls and adds no value for a silent background check).
            $url = "https://raw.githubusercontent.com/$repo/$branch/winrc.ps1"
            try {
                $remote = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10).Content
            }
            catch { return }   # offline / transient -> silently skip

            if (-not (Test-Path $srcPath)) { return }
            $current = [IO.File]::ReadAllText($srcPath)
            if ((Get-FileHashValue -InputObject $current) -eq (Get-FileHashValue -InputObject $remote)) {
                return   # already up to date
            }

            # Stage the update to disk atomically and signal the next shell.
            $tmp = Join-Path (Split-Path -Parent $srcPath) (".$((Split-Path -Leaf $srcPath)).tmp.$PID")
            try {
                [IO.File]::WriteAllText($tmp, $remote, [Text.UTF8Encoding]::new($false))
                Copy-Item -Path $srcPath -Destination "$srcPath.bak" -Force -ErrorAction SilentlyContinue
                Move-Item -Path $tmp -Destination $srcPath -Force
                $dir = Split-Path -Parent $noticePath
                if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                [IO.File]::WriteAllText($noticePath, [DateTime]::UtcNow.ToString('o'), [Text.UTF8Encoding]::new($false))
            }
            catch {
                if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
        } -ArgumentList $script:WinrcSourcePath, $script:WinrcRepo, $script:WinrcBranch, $noticePath | Out-Null
    }
    catch {
        # Background check is best-effort; never let it break the shell.
    }
}

function Show-WinrcUpdateNotice {
    <#
    .SYNOPSIS
        Prints a one-time notice when a background auto-check staged an update that
        hasn't been acknowledged yet, then clears the marker.
    #>
    $notice = Join-Path (Split-Path -Parent $script:WinrcStateFile) 'update-staged.txt'
    if (-not (Test-Path -LiteralPath $notice)) { return }
    $stagedAt = Get-Content -Raw -LiteralPath $notice
    Write-Host "`n[winrc] an update was staged ($stagedAt) and will be active in a new shell. Run 'Update-Winrc' to apply it now." -ForegroundColor Cyan
    Remove-Item -LiteralPath $notice -Force -ErrorAction SilentlyContinue
}

# =============================================================================
# 6. PLATFORM & ENVIRONMENT HELPERS
# =============================================================================

# $PSStyle exists only on PowerShell 7.2+. On Windows PowerShell 5.1 we emulate the
# small subset used here so every code path survives. Note: on 5.1 the terminal
# may not understand the ANSI escapes; ANSICON/Windows Terminal handle them fine.
if (-not (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue)) {
    # `e (ESC) is a valid escape only on PowerShell 6+. On 5.1 that backtick
    # sequence degrades to the literal text `e[..m`, which is exactly the "literal
    # escape characters" prompt bug. Build the ESC byte explicitly so the ANSI
    # codes are interpreted by Windows Terminal / ANSICON on every engine.
    $esc = [char]27
    $PSStyle = @{
        Bold       = "${esc}[1m"
        Dim        = "${esc}[2m"
        Underline  = "${esc}[4m"
        Reset      = "${esc}[0m"
        Foreground = @{ Red = "${esc}[31m"; Green = "${esc}[32m"; Yellow = "${esc}[33m"; Cyan = "${esc}[36m" }
        Background = @{}
    }
}

function Get-Username {
    if ($env:userdomain -AND $env:username) {
        $me = "$($env:username)"
    }
    elseif ($env:LOGNAME) {
        $me = $env:LOGNAME
    }
    else {
        $me = "[?]"
    }
    "$me"
}

function Test-IsWindows {
    if ($IsWindows) { return $true }
    # Fallback for Windows PowerShell 5.1, where $IsWindows is not defined.
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    $false
}

function Test-IsLinux {
    if ($IsLinux) { return $true }
    $false
}

function Test-IsMacOS {
    if ($IsMacOS) { return $true }
    $false
}

function Test-IsAdmin {
    if (Test-IsLinux -or Test-IsMacOS) {
        if ($(id -g) -eq 0 ) { return $true }
        else { return $false }
    }
    if (Test-IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
        return $principal.IsInRole($adminRole)
    }
    $false
}

function Test-IsDebug {
    Test-Path variable:/PSDebugContext
}

function Test-IsInstalled {
    <#
    TODO: split display name on:
    - v[0-9]
    - [0-9]
    - \(
    #>
    param (
        [string] $Name
    )
    # $res = Get-InstalledApplications | Where-Object -DisplayName -Like "${Name}" -ErrorAction SilentlyContinue
    $res = Get-InstalledApplications | Where-Object {
        ($_.PSobject.Properties.Name -contains 'DisplayName') -and ($_.DisplayName -like "${Name}")
    }
    $null -ne $res
}

function New-Symlink {
    try {
        New-Item -ItemType 'SymbolicLink' @args -ErrorAction Stop
    }
    catch {
        gsudo { New-Item -ItemType 'SymbolicLink' @args } -args @($args)
    }
}

function New-TemporaryDirectory {
    <#
    .SYNOPSIS
    https://stackoverflow.com/a/34559554
    #>
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

function Grant-ReadAccess {
    param (
        [Parameter(mandatory = $true)]
        [string]$Account,
        [Parameter(mandatory = $true)]
        [string]$Path
    )
    $ErrorActionPreference = 'Stop'
    $Acl = Get-Acl $Path
    $arguments = $account, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $arguments
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $Path -AclObject $Acl
}

function Import-RegSettings {
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Value")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command gsudo -ErrorAction SilentlyContinue)) {
        Write-Warning -Message 'Please install gsudo first. Aborting.'
        return
    }
    $header = 'Windows Registry Editor Version 5.00'
    $regString = ($header + "`n" + $Value) -replace "\r?\n", "`r`n"
    $tempFile = "$env:TEMP\winrc.reg"
    $regString | Out-File -FilePath "$tempFile" -Encoding unicode
    try {
        reg import "$tempFile"
    }
    catch {
        gsudo reg import "$tempFile"
    }
    Remove-Item -Path "$tempFile"
}

# =============================================================================
# 7. INSTALLERS & PROVISIONING
# =============================================================================

function Install-PowerShellProfile {
    <#
    .SYNOPSIS
        Installs the winrc.ps1 loader into the startup profiles of both PowerShell
        engines, each as a SHELLRC-fenced block written through Set-ConfigSection.
    .DESCRIPTION
        Windows PowerShell 5.1 and PowerShell 7 each read their own profile file,
        so a loader written only to $PROFILE (the current engine's file) is
        invisible to the other. This writes the same fenced loader block into both
        shared per-engine startup files:
          - <Documents>\PowerShell\profile.ps1            (PowerShell 7)
          - <Documents>\WindowsPowerShell\profile.ps1       (Windows PowerShell 5.1)
        Each write goes through Set-ConfigSection, which is idempotent and
        compare-based: it only rewrites a section whose content differs from the
        value stored here, and fences it with BEGIN_SHELLRC / END_SHELLRC. An
        existing profile is backed up (once) before its first SHELLRC insert so
        user content is never lost.
    #>
    # Locate winrc.ps1 that is running right now, so the loader points at it.
    # Prefer the resolved source path set at the top of the script (handles being
    # dot-sourced without a real file context); fall back to $PSScriptRoot, and
    # finally to the current directory, so an empty path never corrupts the fence.
    $loader = $script:WinrcSourcePath
    if (-not $loader -or -not [IO.File]::Exists($loader)) {
        $candidate = Join-Path -Path $PSScriptRoot -ChildPath 'winrc.ps1' -ErrorAction SilentlyContinue
        if (-not [IO.File]::Exists($candidate)) { $candidate = Join-Path -Path (Get-Location) -ChildPath 'winrc.ps1' }
        $loader = $candidate
    }

    # The literal text written into each profile. Kept as an explicit value here so
    # the user can see exactly what the script stores, and so Set-ConfigSection can
    # compare it against whatever is already in the file before deciding to write.
    $Content = @"
# BEGIN_SHELLRC
# Load winrc.ps1 (terminal + config bootstrap). See https://github.com/tmslnz/winrc
. '$loader'
# END_SHELLRC
"@

    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    $profiles = @(
        (Join-Path -Path $myDocs -ChildPath 'PowerShell\profile.ps1'),           # PowerShell 7
        (Join-Path -Path $myDocs -ChildPath 'WindowsPowerShell\profile.ps1')      # Windows PowerShell 5.1
    )

    $changed = $false
    foreach ($profilePath in $profiles) {
        # Back up an existing profile only when we are about to insert a SHELLRC
        # section for the first time (i.e. it exists, has content, and no fence yet).
        if ([IO.File]::Exists($profilePath)) {
            if (-not (Get-Content -Raw -Path $profilePath -ErrorAction SilentlyContinue |
                    Select-String -Pattern 'BEGIN_SHELLRC' -Quiet -ErrorAction SilentlyContinue)) {
                $info = [IO.FileInfo]::new($profilePath)
                $ts = Get-Date -UFormat '+%Y-%m-%dT%H%M%S'
                $dest = Join-Path -Path $info.DirectoryName -ChildPath "${info.BaseName}_backup_${ts}${info.Extension}"
                Copy-Item -Path $profilePath -Destination $dest -ErrorAction SilentlyContinue
                Write-Information -MessageData "winrc: backed up $profilePath -> $dest" -InformationAction Continue
            }
        }
        # Set-ConfigSection is compare-based and returns $true only when it writes.
        if (Set-ConfigSection -String $Content -Path $profilePath) {
            $changed = $true
            Write-Information -MessageData "winrc: wrote loader to $profilePath" -InformationAction Continue
        }
    }

    if ($changed) {
        Write-Host "winrc installed for both PowerShell 7 and Windows PowerShell 5.1." -ForegroundColor Cyan
        Write-Host "Restart your terminal(s) for the new prompt to take effect." -ForegroundColor Yellow
    }
}

function Install-CoreTools {
    Install-Scoop
    Install-SSH
}

function Install-SSH {
    Invoke-gsudo -ArgumentList None -ScriptBlock {
        $name = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*' | Select-Object -Property Name
        if ($null -ne $name) {
            Add-WindowsCapability -Online -Name $name
        }
        $name = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -Property Name
        if ($null -ne $name) {
            Add-WindowsCapability -Online -Name $name
            Start-Service sshd
            Set-Service -Name sshd -StartupType 'Automatic'
            if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
                Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
                New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
            }
            else {
                Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
            }
        }
    }
}

function Install-WingetApp {
    param (
        [string]$name
    )
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact $name
}

function Install-WingetApps {
    if (-Not (Test-IsWindows)) { return }
    Install-WingetApp 'Microsoft.PowerShell'
    Install-WingetApp 'HEIF Image Extensions'
    Install-WingetApp 'Webp Image Extensions'
    Install-WingetApp 'VP9 Video Extensions'
    Install-WingetApp 'Web Media Extensions'
    Install-WingetApp 'AgileBits.1Password'
    Install-WingetApp 'Bitwarden.Bitwarden'
    Install-WingetApp 'OpenWhisperSystems.Signal'
    Install-WingetApp 'Microsoft.VisualStudioCode'
    Install-WingetApp 'SublimeHQ.SublimeMerge'
    Install-WingetApp 'SublimeHQ.SublimeText.4'
    Install-WingetApp 'Microsoft.PowerToys'
    Install-WingetApp 'Mozilla.Firefox'
    Install-WingetApp 'Brave.Brave'
    Install-WingetApp 'Figma.Figma'
    Install-WingetApp 'NextDNS.NextDNS.Desktop'
    Install-WingetApp 'SlackTechnologies.Slack'
    Install-WingetApp 'Splashtop.SplashtopBusiness'
}

function Install-Scoop {
    if (-Not (Test-IsWindows)) { return }
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod -Uri 'https://get.scoop.sh' | Invoke-Expression
    # Core
    $list = @'
git
aria2
7zip
scoop-search
gsudo
'@ -Split "`r?`n"
    scoop install @list
}

function Install-Pyenv {
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"
    & "./install-pyenv-win.ps1"
    Remove-Item "./install-pyenv-win.ps1"
}

function Install-ScoopApps {
    if (-Not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        Install-Scoop
    }

    # Buckets
    scoop bucket add extras
    scoop bucket add versions
    scoop bucket add nirsoft
    scoop bucket add java
    scoop bucket add nonportable

    # CLI apps
    $list = @'
1password-cli
bitwarden-cli
docker
docker-buildx
everything-cli
fd
ffmpeg
fzf
gallery-dl
handbrake-cli
iperf3
mariadb
msys2
nmap
nodejs-lts
ntop
pandoc
qpdf
rclone
shellcheck
sqlite
which
yt-dlp
zoxide
'@ -Split "`r?`n"
    scoop install @list

    # GUI
    $list = @'
extras/advanced-ip-scanner
extras/bleachbit
extras/bulk-crap-uninstaller
extras/cpu-z
extras/cyberduck
extras/dupeguru
extras/everything
extras/gpu-z
extras/handbrake
extras/windows
extras/heidisql
extras/kdiff3
extras/msedgeredirect
extras/opentabletdriver
versions/dotnet6-sdk
extras/rapidee
extras/renamer
extras/sharex
extras/sharpkeys
extras/sqlitestudio
extras/sumatrapdf
extras/synctrayzor
extras/treesize-free
extras/vlc
extras/winaero-tweaker
nirsoft/registrychangesview
nirsoft/searchmyfiles
nonportable/zadig-np
'@ -Split "`r?`n"
    scoop install @list
}

function Install-SyncthingService {
    # TODO
    $account = 'syncthing'
    $servicename = 'syncthing'
    if (Get-Service "$servicename" -ErrorAction SilentlyContinue) {
        Write-Information -MessageData "Service $servicename exists" -InformationAction Continue
        return
    }
    # Get password
    Write-Information -MessageData "Creating local user: $account" -InformationAction Continue
    Write-Information -MessageData "Create password for user: $account" -InformationAction Continue
    $Secure1 = Read-Host -AsSecureString
    Write-Information -MessageData 'Re-enter password to verify' -InformationAction Continue
    $Secure2 = Read-Host -AsSecureString
    if (-Not $Secure1 -or -Not $Secure2) {
        return
    }
    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure1))
    $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure2))
    if ($pwd1_text -ne $pwd2_text) {
        Write-Warning -Message 'Passwords did not match. Try again.' -WarningAction Continue
        return
    }
    Invoke-gsudo -ArgumentList $account, $servicename, $Secure1, $pwd2_text -ScriptBlock {
        $account = $args[0]
        $servicename = $args[1]
        $Secure1 = $args[2]
        $pwd2_text = $args[3]
        Write-Host $account
        Write-Host $servicename
        Write-Host $Secure1
        Write-Host $pwd2_text
        # Start
        New-LocalUser -Name "$account" -Password $Secure1 -UserMayNotChangePassword -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Users" -Member "$account" -ErrorAction SilentlyContinue
        Get-LocalUser -Name "$account" | Set-LocalUser -Password $Secure1
        $Credential = [PSCredential]::New($account, $Secure1)
        Start-Process "cmd.exe" -Credential $Credential -ArgumentList "/C" -LoadUserProfile
        New-Item -ItemType Directory "C:\Users\$account\AppData\Local\Syncthing\Logs" -Force
        $Acl = Get-Acl -Path "C:\Users\$account\AppData\Local\Syncthing"
        $Owner = New-Object System.Security.Principal.NTAccount("$account")
        $Acl.SetOwner($Owner)
        Set-Acl "C:\Users\$account\AppData\Local\Syncthing" $Acl
        # {
        #     winget install --id 'NSSM.NSSM' --scope machine
        #     winget install --id 'Syncthing.Syncthing' --scope machine
        # }
        # Fix permissions
        # {
        #     $symlink = Get-Item "C:\Program Files\WinGet\Links\syncthing.exe"
        #     $symlinkDir = Split-Path $symlink.Target -parent | Split-Path -parent
        #     $Acl = Get-Acl $symlinkDir
        #     $arguments = $account, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow"
        #     $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $arguments
        #     $acl.SetAccessRule($accessRule)
        #     Set-Acl -Path $symlinkDir -AclObject $Acl
        #     $symlink = Get-Item "C:\Program Files\WinGet\Links\nssm.exe"
        #     $symlinkDir = Split-Path $symlink.Target -parent | Split-Path -parent
        #     $Acl = Get-Acl $symlinkDir
        #     $arguments = $account, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow"
        #     $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $arguments
        #     $acl.SetAccessRule($accessRule)
        #     Set-Acl -Path $symlinkDir -AclObject $Acl
        # }
        scoop install -g nssm syncthing
        $syncthing = scoop shim info syncthing --global | Select-Object -ExpandProperty Path
        # Install Service
        nssm install $servicename $syncthing
        nssm set $servicename Start SERVICE_DELAYED_AUTO_START
        nssm set $servicename AppDirectory C:\Users\$account\AppData\Local\Syncthing
        nssm set $servicename AppParameters -no-browser -no-restart -home='"'C:\Users\$account\AppData\Local\Syncthing'"'
        nssm set $servicename DisplayName $servicename
        nssm set $servicename Description 'Syncthing service for all users'
        # Log On
        nssm set $servicename ObjectName ".\$account" "$pwd2_text"
        # Process
        nssm set $servicename AppPriority NORMAL_PRIORITY_CLASS
        nssm set $servicename AppNoConsole 0
        nssm set $servicename AppAffinity All
        # Shutdown
        nssm set $servicename AppStopMethodSkip 0
        nssm set $servicename AppStopMethodConsole 10000
        nssm set $servicename AppStopMethodWindow 10000
        nssm set $servicename AppStopMethodThreads 10000
        # Exit
        nssm set $servicename AppThrottle 5000
        nssm set $servicename AppExit Default Exit
        nssm set $servicename AppExit 0 Exit
        nssm set $servicename AppExit 3 Restart
        nssm set $servicename AppExit 4 Restart
        nssm set $servicename AppRestartDelay 0
        # I/O
        nssm set $servicename AppStdout C:\Users\$account\AppData\Local\Syncthing\Logs\Syncthing.log
        nssm set $servicename AppStderr C:\Users\$account\AppData\Local\Syncthing\Logs\Syncthing.log
    }
    # Remove user from Login options
    $value = @"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList]
"${account}"=dword:00000000
"@
    Import-RegSettings $value
}

function Install-WindowsSandbox {
    <#
    # TODO
    https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file#networking
    #>
    Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
}

# =============================================================================
# 8. UTILITIES & DIAGNOSTICS
# =============================================================================

function Disable-LogitechWebcamMicrophone {
    if (!(Test-IsWindows)) { return }
    gsudo Get-PnpDevice -Class AudioEndpoint -FriendlyName "*Logitech*" | Disable-PnpDevice -Confirm $false
}

function Uninstall-Crap {
    winget uninstall --name 'Windows Web Experience Pack'
    winget uninstall --name 'Microsoft To Do'
    winget uninstall --name 'Microsoft Sticky Notes'
    winget uninstall --name 'Cortana'
    winget uninstall --name 'Feedback Hub'
    winget uninstall --name 'Microsoft OneDrive'
}

function Get-AudioDevices {
    Get-PnpDevice -Class AudioEndpoint
}

function Get-InstalledApplications() {
    <#
    .SYNOPSIS
    https://xkln.net/blog/please-stop-using-win32product-to-find-installed-software-alternatives-inside/
    #>
    [cmdletbinding(DefaultParameterSetName = 'GlobalAndCurrentUser')]
    Param (
        [Parameter(ParameterSetName = "Global")]
        [switch]$Global,
        [Parameter(ParameterSetName = "GlobalAndCurrentUser")]
        [switch]$GlobalAndCurrentUser,
        [Parameter(ParameterSetName = "GlobalAndAllUsers")]
        [switch]$GlobalAndAllUsers,
        [Parameter(ParameterSetName = "CurrentUser")]
        [switch]$CurrentUser,
        [Parameter(ParameterSetName = "AllUsers")]
        [switch]$AllUsers,
        [switch]$NoCache,
        [switch]$NamesOnly
    )
    # Excplicitly set default param to True if used to allow conditionals to work
    if ($PSCmdlet.ParameterSetName -eq "GlobalAndCurrentUser") {
        $GlobalAndCurrentUser = $true
    }
    # Check if running with Administrative privileges if required
    if ($GlobalAndAllUsers -or $AllUsers) {
        if ((Test-IsAdmin) -eq $false) {
            Write-Error "Finding all user applications requires administrative privileges"
            break
        }
    }
    # Empty array to store applications
    if ($NoCache -eq $true) {
        $Script:CachedAppsList = @()
    }
    if ($Script:CachedAppsList.length -eq 0) {
        $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        # Retreive globally insatlled applications
        if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
            $Script:CachedAppsList += Get-ItemProperty "HKLM:\$32BitPath"
            $Script:CachedAppsList += Get-ItemProperty "HKLM:\$64BitPath"
        }
        if ($CurrentUser -or $GlobalAndCurrentUser) {
            $Script:CachedAppsList += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
            $Script:CachedAppsList += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
        }
        if ($AllUsers -or $GlobalAndAllUsers) {
            Write-Host "Collecting hive data for all users"
            $AllProfiles = Get-CimInstance Win32_UserProfile | Select-Object LocalPath, SID, Loaded, Special | Where-Object { $_.SID -like "S-1-5-21-*" }
            $MountedProfiles = $AllProfiles | Where-Object { $_.Loaded -eq $true }
            $UnmountedProfiles = $AllProfiles | Where-Object { $_.Loaded -eq $false }
            Write-Host "Processing mounted hives"
            $MountedProfiles | ForEach-Object {
                $Script:CachedAppsList += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
                $Script:CachedAppsList += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
            }
            Write-Host "Processing unmounted hives"
            $UnmountedProfiles | ForEach-Object {
                $Hive = "$($_.LocalPath)\NTUSER.DAT"
                Write-Host " -> Mounting hive at $Hive"
                if (Test-Path $Hive) {
                    REG LOAD HKU\temp $Hive
                    $Script:CachedAppsList += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
                    $Script:CachedAppsList += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"
                    # Run manual GC to allow hive to be unmounted
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    REG UNLOAD HKU\temp
                }
                else {
                    Write-Warning "Unable to access registry hive at $Hive"
                }
            }
        }
    }
    if ($NamesOnly -eq $true) {
        $Script:CachedAppsList | Where-Object {
            $_.PSobject.Properties.Name -contains 'DisplayName'
        } | Sort-Object -Property 'DisplayName' | Select-Object -Property 'DisplayName' -Unique
    }
    else {
        Write-Output $Script:CachedAppsList
    }
}

Main
