$cached_Packages
$cached_AppxPackages
$cached_Win32_Products
$QUIET = $true

function Main {
    $actions = @'
Install-Profile
Set-ConfigNpm
Set-ConfigZoxide
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

function Set-AllowSymlinks {
    <#
    .SYNOPSIS
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-configure
    #>
    sudo {
        secedit /export /cfg c:\secpol.cfg
        (Get-Content C:\secpol.cfg).replace('SeCreateSymbolicLinkPrivilege = ', 'SeCreateSymbolicLinkPrivilege = " + Environment.UserName + ",') | Out-File C:\secpol.cfg
        secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
        Remove-Item -Force -Path c:\secpol.cfg -Confirm:$false
    }
}

function Install-Profile {
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

function Set-ExecutionPolicyRemote {
    sudo Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
}

function Set-ConfigRhinoceros {
    $hosts = [Environment]::SystemDirectory + '\drivers\etc\hosts'
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
        New-Item -Path $Path -ItemType File
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
    if ($isLinux -or $IsMacOS) {
        if ($(id -g) -eq 0 ) { return $true }
        else { return $false }
    }
    if ($isWindows -or $psEdition -eq 'desktop') {
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

function Test-IsWindows {
    if ($Env:OS) { return $true }
    if (-Not $Env:OS) { return $false }
}

function Set-ConfigZoxide {
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

function New-Profile {
    if (! [IO.File]::Exists($PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force
    }
}

function New-Symlink () {
    try {
        New-Item -ItemType 'SymbolicLink' @args -ErrorAction Stop
    }
    catch {
        sudo { New-Item -ItemType 'SymbolicLink' @args } -args @($args)
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

function Disable-Logitech-Webcam-Microphone {
    if (!(Test-IsWindows)) { return }
    sudo Get-PnpDevice -Class AudioEndpoint -FriendlyName "*Logitech*" | Disable-PnpDevice -Confirm $false
}

function Get-AudioDevices {
    Get-PnpDevice -Class AudioEndpoint
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

function Install-WingetApps {
    if (!(Test-IsWindows)) { return }
    Install-WingetApp -id 'gerardog.gsudo'
    Install-WingetApp -id 'Microsoft.PowerShell'
    Install-WingetApp -name 'HEIF Image Extensions'
    Install-WingetApp -name 'Webp Image Extensions'
    Install-WingetApp -name 'VP9 Video Extensions'
    Install-WingetApp -name 'Web Media Extensions'
    Install-WingetApp -id 'AgileBits.1Password'
    Install-WingetApp -id 'OpenWhisperSystems.Signal'
}

function Install-Scoop {
    if (!(Test-IsWindows)) { return }
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod -Uri 'https://get.scoop.sh' | Invoke-Expression
}

function Install-Pyenv {
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"
    & "./install-pyenv-win.ps1"
    Remove-Item "./install-pyenv-win.ps1"
}
function Install-ScoopApps {
    if (-Not (Get-Command scoop -ErrorAction SilentlyContinue)) { return }
    scoop update
    scoop install git

    scoop bucket add extras
    scoop bucket add nonportable
    scoop bucket add nirsoft
    scoop bucket add java

    # GUI Apps
    sudo scoop install --global 7zip
    sudo scoop install --global bulk-crap-uninstaller
    sudo scoop install --global cyberduck
    sudo scoop install --global everything
    sudo scoop install --global handbrake
    sudo scoop install --global losslesscut
    sudo scoop install --global nssm
    sudo scoop install --global obs-studio
    sudo scoop install --global rapidee
    sudo scoop install --global treesize-free
    sudo scoop install --global vlc

    # CLI apps
    scoop install python
    scoop install ripgrep
    scoop install fciv

    # CLI global
    sudo scoop install --global nodejs-lts
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