$cached_Packages
$cached_AppxPackages
$cached_Win32_Products
$QUIET = $true

function Main {
    $actions = @'
Install-PowerShellProfile
Set-ConfigNpm
Set-ConfigZoxide
Set-ConfigGit
'@
    $actions.Replace("`r`n", "`n").Split("`n") | ForEach-Object -Process {
        if ($QUIET) {
            $command = [Scriptblock]::Create("$_ > `$null")
        }
        else {
            $command = [Scriptblock]::Create("$_")
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
        if (($principal.IsInRole($adminRole))) { return $true }
        else { return $false }
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
    <#
    # TODO
    #>
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
    $xml = New-Object XML
    $xml.Load("$Home\AppData\Roaming\Cyberduck\Cyberduck.user.config")
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
;"TaskbarGlomLevel"=dword:00000002
;"TaskbarSizeMove"=dword:00000000
;"TaskbarSmallIcons"=dword:00000000
;"WebView"=dword:00000001
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

function Install-WingetApps {
    function Install-WingetApp {
        param (
            [string]$name,
            [string]$id
        )
        if ($name) {
            winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact --name $name
        }
        elseif ($id) {
            winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --id $id
        }
    }
    if (-Not (Test-IsWindows)) { return }
    Install-WingetApp -id 'Microsoft.PowerShell'
    Install-WingetApp -name 'HEIF Image Extensions'
    Install-WingetApp -name 'Webp Image Extensions'
    Install-WingetApp -name 'VP9 Video Extensions'
    Install-WingetApp -name 'Web Media Extensions'
    Install-WingetApp -id 'AgileBits.1Password'
    Install-WingetApp -id 'Bitwarden.Bitwarden'
    Install-WingetApp -id 'OpenWhisperSystems.Signal'
    Install-WingetApp -id 'Microsoft.VisualStudioCode'
    Install-WingetApp -id 'SublimeHQ.SublimeMerge'
    Install-WingetApp -id 'SublimeHQ.SublimeText.4'
    Install-WingetApp -id 'Microsoft.PowerToys'
    Install-WingetApp -id 'Mozilla.Firefox'
    Install-WingetApp -id 'Brave.Brave'
    Install-WingetApp -id 'Figma.Figma'
    Install-WingetApp -id 'NextDNS.NextDNS.Desktop'
    Install-WingetApp -id 'SlackTechnologies.Slack'
    Install-WingetApp -id 'Splashtop.SplashtopBusiness'
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
extras/dbeaver
extras/dupeguru
extras/everything
extras/f3d
extras/freecommander
extras/ghostwriter
extras/gpu-z
extras/handbrake
extras/heidisql
extras/inkscape
extras/kdiff3
extras/krita
extras/logseq
extras/losslesscut
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
    $account = 'mario'
    $servicename = 'mario'
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
    #>
    # Remove user from Login options
    $value = @"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList]
"${account}"=dword:00000000
"@
    # Import-RegSettings $value
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
}

function Get-AudioDevices {
    Get-PnpDevice -Class AudioEndpoint
}

function Get-InstalledAppxPackage {
    param (
        [string]$Name
    )
    if (! $Script:cached_AppxPackages) {
        Write-Host "Caching Get-AppxPackage"
        $Script:cached_AppxPackages = Get-AppxPackage | Select-Object -Property Name, Version
    }
    $Script:cached_AppxPackages | Where-Object -Property Name -like $Name
}

function Get-InstalledPackage {
    param (
        [string]$Name
    )
    if (! $Script:cached_Packages) {
        Write-Host "Caching Get-Package"
        $Script:cached_Packages = Get-Package
    }
    $Script:cached_Packages | Where-Object -Property Name -like $Name
}

function Get-InstalledProgram {
    # TODO
    param (
        [string]$Name
    )
    if (! $Script:cached_Win32_Products) {
        Get-InstalledApplications -GlobalAndCurrentUser |
        Where-Object -Property DisplayName -like $Name  |
        Select-Object -Property DisplayName
        # Write-Host "Caching Get-WmiObject -Class Win32_Product"
        # $Script:cached_Win32_Products = Get-WmiObject -Class Win32_Product
        # $Script:cached_Win32_Products = Get-CimInstance -ClassName Win32_Program
    }
    # $Script:cached_Win32_Products | Where-Object -Property Name -like $Name
}

function Get-InstalledApplications() {
    <#
    .SYNOPSIS
    https://xkln.net/blog/please-stop-using-win32product-to-find-installed-software-alternatives-inside/
    #>
    [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]
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
        [switch]$AllUsers
    )
    # Excplicitly set default param to True if used to allow conditionals to work
    if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
        $GlobalAndAllUsers = $true
    }
    # Check if running with Administrative privileges if required
    if ($GlobalAndAllUsers -or $AllUsers) {
        $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($RunningAsAdmin -eq $false) {
            Write-Error "Finding all user applications requires administrative privileges"
            break
        }
    }
    # Empty array to store applications
    $Apps = @()
    $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    # Retreive globally insatlled applications
    if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
        Write-Host "Processing global hive"
        $Apps += Get-ItemProperty "HKLM:\$32BitPath"
        $Apps += Get-ItemProperty "HKLM:\$64BitPath"
    }
    if ($CurrentUser -or $GlobalAndCurrentUser) {
        Write-Host "Processing current user hive"
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
        $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
    }
    if ($AllUsers -or $GlobalAndAllUsers) {
        Write-Host "Collecting hive data for all users"
        $AllProfiles = Get-CimInstance Win32_UserProfile | Select-Object LocalPath, SID, Loaded, Special | Where-Object { $_.SID -like "S-1-5-21-*" }
        $MountedProfiles = $AllProfiles | Where-Object { $_.Loaded -eq $true }
        $UnmountedProfiles = $AllProfiles | Where-Object { $_.Loaded -eq $false }
        Write-Host "Processing mounted hives"
        $MountedProfiles | ForEach-Object {
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
        }
        Write-Host "Processing unmounted hives"
        $UnmountedProfiles | ForEach-Object {
            $Hive = "$($_.LocalPath)\NTUSER.DAT"
            Write-Host " -> Mounting hive at $Hive"
            if (Test-Path $Hive) {
                REG LOAD HKU\temp $Hive
                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"
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
    Write-Output $Apps
}

Main
