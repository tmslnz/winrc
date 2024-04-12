$cached_Packages
$cached_AppxPackages
$cached_Win32_Products

function Main {
    New-Profile
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

function Test-Is-Admin {
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

function Test-Is-Debug {
    Test-Path variable:/PSDebugContext
}

function prompt {
    $prefix = $(
        if (Test-Is-Debug) { '[DEBUG] ' }
        elseif (Test-Is-Admin) { '[ADMIN] ' }
        else { '' }
    )
    $user = $(Get-Username)
    $hostname = [System.Net.Dns]::GetHostName()
    $cwd = $(Get-Location)
    $body = "${user}@${hostname}: ${cwd}"
    # $pwd = $executionContext.SessionState.Path.CurrentLocation
    $suffix = $(if ($NestedPromptLevel -ge 1) { '>>' }) + '> '
    "${prefix}${body} ${suffix}"
}

function Test-Is-Windows {
    if ($Env:OS) { return $true }
    if (-Not $Env:OS) { return $false }
}

function Set-Zoxide {
    Invoke-Expression (& {
            $hook = if ($PSVersionTable.PSVersion.Major -ge 6) {
                'pwd'
            }
            else {
                'prompt'
            } (zoxide init powershell --hook $hook | Out-String)
        })
}

function New-Profile {
    if (!(Test-Path -Path $PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force
    }
}

function New-Symlink () {
    param(
        $target,
        $link
    )
    New-Item -Path $link -ItemType SymbolicLink -Value $target
}

function New-Hardlink () {
    param(
        $target,
        $link
    )
    New-Item -Path $link -ItemType HardLink -Value $target
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
    if (!(Test-Is-Windows)) { return }
    sudo Get-PnpDevice -Class AudioEndpoint -FriendlyName "*Logitech*" | Disable-PnpDevice -Confirm $false
}

function Get-Audio-Devices {
    Get-PnpDevice -Class AudioEndpoint
}

function Install-Winget {
    <#
    .SYNOPSIS
    https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
    #>
    if (!(Test-Is-Windows)) { return }
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

function Get-Installed-AppxPackage {
    param (
        [string]$Name
    )
    if (! $Script:cached_AppxPackages) {
        Write-Host "Caching Get-AppxPackage"
        $Script:cached_AppxPackages = Get-AppxPackage | Select-Object -Property Name, Version
    }
    $Script:cached_AppxPackages | Where-Object -Property Name -like $Name
}

function Get-Installed-Package {
    param (
        [string]$Name
    )
    if (! $Script:cached_Packages) {
        Write-Host "Caching Get-Package"
        $Script:cached_Packages = Get-Package
    }
    $Script:cached_Packages | Where-Object -Property Name -like $Name
}

function Get-Installed-App {
    param (
        [string]$Name
    )
    if (! $Script:cached_Win32_Products) {
        Write-Host "Caching Get-WmiObject -Class Win32_Product"
        $Script:cached_Win32_Products = Get-WmiObject -Class Win32_Product
    }
    $Script:cached_Win32_Products | Where-Object -Property Name -like $Name
}

function Install-Winget-App {
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

function Install-Winget-Apps {
    if (!(Test-Is-Windows)) { return }
    Install-Winget-App -id 'gerardog.gsudo'
    Install-Winget-App -id 'Microsoft.PowerShell'
    Install-Winget-App -name 'HEIF Image Extensions'
    Install-Winget-App -name 'Webp Image Extensions'
    Install-Winget-App -name 'VP9 Video Extensions'
    Install-Winget-App -name 'Web Media Extensions'
    Install-Winget-App -id 'AgileBits.1Password'
}

function Install-Scoop {
    if (!(Test-Is-Windows)) { return }
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod -Uri 'https://get.scoop.sh' | Invoke-Expression
}

function Install-Pyenv-Win {
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"
    & "./install-pyenv-win.ps1"
    Remove-Item "./install-pyenv-win.ps1"
}
function Install-Scoop-Apps {
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


Main