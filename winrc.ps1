# Set-StrictMode -Version
$progressPreference = 'SilentlyContinue'
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

$CachedAppsList = @()
$WINRC_QUIET = $true

function Main {
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
    $actions.Replace("`r`n", "`n").Split("`n") | ForEach-Object -Process {
        if ($_.StartsWith('#')) { return }
        Get-ChildItem -Path "Function:\$_" | Remove-Item
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

function Test-IsAdmin {
    if (-Not (Test-IsWindows)) {
        if ($(id -g) -eq 0 ) { return $true }
        else { return $false }
    }
    if ((Test-IsWindows) -or $psEdition -eq 'desktop') {
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

function Test-IsWindows {
    if ($Env:OS) { return $true }
    if (-Not $Env:OS) { return $false }
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

function New-ConfigSection {
    [cmdletbinding(DefaultParameterSetName = 'Prepend')]
    param(
        [string]$String,
        [string]$Path,
        [switch]$Append,
        [Parameter(ParameterSetName = "Prepend")]
        [switch]$Prepend
    )
    $ResolvedPath = Resolve-Path -Path $Path -ErrorAction SilentlyContinue
    if ($ResolvedPath) { $Path = $ResolvedPath }
    if ($PSCmdlet.ParameterSetName -eq "Prepend") { $Prepend = $true }
    if (-Not [IO.File]::Exists($Path)) {
        New-Item -Path $Path -ItemType File -Force
    }
    if (Select-String -Path $Path -Pattern "BEGIN_SHELLRC") { return $false }
    if ($Prepend) {
        $result = @($String) + (Get-Content -Raw -Path $Path)
        [IO.File]::WriteAllLines(($Path | Resolve-Path), $result)
    }
    if ($Append) {
        [IO.File]::AppendAllLines(($Path | Resolve-Path), [string[]]$String)
    }
}

function Update-ConfigSection {
    param(
        [string]$String,
        [string]$Path
    )
    if (! [System.IO.File]::Exists("$Path")) { return $false }
    if (! (Select-String -Path $Path -Pattern "BEGIN_SHELLRC")) { return $false }
    $content = [IO.File]::ReadAllText($Path)
    $pattern = '(?smi)[#;/].*?BEGIN_SHELLRC(.*?)[#;/].*?END_SHELLRC'
    $result = $content | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
    $result = $result.Replace("`r`n", "`n")
    $String = $String.Replace("`r`n", "`n")
    if ($result -eq $String) { return $false }
    $replaced = $content -replace $pattern, $String
    [IO.File]::WriteAllLines(($Path | Resolve-Path), $replaced)
}

function prompt {
    $prefix = $(
        if (Test-IsDebug) { '[DEBUG] ' }
        elseif (Test-IsAdmin) { '[ADMIN] ' }
        else { '' }
    )
    $user = $(Get-Username)
    $hostname = [System.Net.Dns]::GetHostName()
    $cwd = $(Get-Location).Path
    if ($cwd -eq $HOME) { $cwd = '~' }
    $body = "$($PSStyle.Bold)${user}@$($PSStyle.Dim)${hostname}:$($PSStyle.Reset)${cwd}"
    $suffix = $(if ($NestedPromptLevel -ge 1) { "$($PSStyle.Dim)$ $($PSStyle.Reset)" }) + "$($PSStyle.Dim)$([char]0x25CF)$($PSStyle.Reset) "
    "${prefix}${body} ${suffix}"
}

function Update-Winrc {
    <#
    # https://stackoverflow.com/a/41618979/218107
    #>
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $res = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/tmslnz/winrc/main/winrc.ps1' -ErrorAction SilentlyContinue --TimeoutSec 5
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    Write-Host $res.Content
    # [IO.File]::AppendAllLines(($Path | Resolve-Path), [string[]]$String)
}

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
    New-ConfigSection -String $config -Path $file
    Update-ConfigSection -String $config -Path $file
}

function Set-ConfigGit {
    if (-Not (Test-IsWindows)) { return }
    if (-Not (Get-Command npm -ErrorAction SilentlyContinue)) { return }
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
    New-ConfigSection -String $config -Path $file
    Update-ConfigSection -String $config -Path $file
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
    New-ConfigSection -String $config -Path $file
    Update-ConfigSection -String $config -Path $file
    $file = "$home\.config\git\attributes"
    $config = @'
# BEGIN_SHELLRC

# END_SHELLRC
'@
    New-ConfigSection -String $config -Path $file
    Update-ConfigSection -String $config -Path $file
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
    New-ConfigSection -String $config -Path $file
    Update-ConfigSection -String $config -Path $file
}

function Set-ConfigShareX {
    # TODO
    <#
    $a = Get-Content 'D:\temp\mytest.json' -raw | ConvertFrom-Json
    $a.update | % {if($_.name -eq 'test1'){$_.version=3.0}}
    $a | ConvertTo-Json -depth 32| set-content 'D:\temp\mytestBis.json'
    #>
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

function Disable-LogitechWebcamMicrophone {
    if (!(Test-IsWindows)) { return }
    gsudo Get-PnpDevice -Class AudioEndpoint -FriendlyName "*Logitech*" | Disable-PnpDevice -Confirm $false
}

function Install-PowerShellProfile {
    if ([IO.File]::Exists($PROFILE)) {
        if (! (Select-String -Path $PROFILE -Pattern "BEGIN_SHELLRC" -ErrorAction SilentlyContinue)) {
            $dirname = ([IO.FileInfo]$PROFILE).DirectoryName
            $basename = ([IO.FileInfo]$PROFILE).BaseName
            $ext = ([IO.FileInfo]$PROFILE).Extension
            $ts = Get-Date -UFormat '+%Y-%m-%dT%H%M%S'
            $dest = Join-Path -Path $dirname -ChildPath "${basename}_backup_${ts}${ext}"
            Copy-Item -Path $PROFILE -Destination $dest
        }
    }
    if (! [IO.File]::Exists($PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force
    }
    $Value = Join-Path -Path "$PSScriptRoot" -ChildPath 'winrc.ps1'
    $Content = @"
# BEGIN_SHELLRC
. '$Value'
# END_SHELLRC
"@
    New-ConfigSection -String $Content -Path $PROFILE
    Update-ConfigSection -String $Content -Path $PROFILE
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
ntop
nodejs-lts
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
cygwin
extras/advanced-ip-scanner
extras/audacity
extras/bleachbit
extras/blender
extras/bulk-crap-uninstaller
extras/cpu-z
extras/cyberduck
extras/dupeguru
extras/everything
extras/f3d
extras/ghostwriter
extras/gpu-z
extras/handbrake
extras/heidisql
extras/inkscape
extras/kdiff3
extras/krita
extras/logseq
extras/losslesscut
extras/msedgeredirect
extras/obs-studio
extras/opentabletdriver
extras/pureref
extras/rapidee
extras/renamer
extras/sharex
extras/sharpkeys
extras/simplenote
extras/sqlitestudio
extras/sumatrapdf
extras/synctrayzor
extras/treesize-free
extras/vlc
extras/winaero-tweaker
extras/xnconvert
extras/xnviewmp
nirsoft/openedfilesview
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

function Install-Winget {
    <#
    .SYNOPSIS
    https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
    #>
    if (!(Test-IsWindows)) { return }
    $progressPreference = 'silentlyContinue'
    $tmp_dir = New-TemporaryDirectory
    Write-Information "Downloading WinGet and its dependencies..."
    Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile "${tmp_dir}\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile "${tmp_dir}\Microsoft.VCLibs.x64.14.00.Desktop.appx"
    Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile "${tmp_dir}\Microsoft.UI.Xaml.2.8.x64.appx"
    Add-AppxPackage "${tmp_dir}\Microsoft.VCLibs.x64.14.00.Desktop.appx"
    Add-AppxPackage "${tmp_dir}\Microsoft.UI.Xaml.2.8.x64.appx"
    Add-AppxPackage "${tmp_dir}\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
}

function Install-WindowsSandbox {
    <#
    # TODO
    https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file#networking
    #>
    Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
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
        } | Select-Object -Property 'DisplayName'
    }
    else {
        Write-Output $Script:CachedAppsList
    }
}

Main
