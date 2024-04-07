function Install-Winget {
    <#
    .SYNOPSIS
    https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget-on-windows-sandbox
    #>
    $progressPreference = 'silentlyContinue'
    Write-Information "Downloading WinGet and its dependencies..."
    Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
    Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
    Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
    Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
}

$cached_Packages
function Is-Installed-Package {
    param (
        [string]$Name
    )
    if (! $Script:cached_Packages) {
        Write-Host "Caching Get-Package"
        $Script:cached_Packages = Get-Package    
    }
    $Script:cached_Packages | Where-Object -Property Name -like $Name
    # Get-Package -Name "$Name" -ErrorAction SilentlyContinue
}

$cached_Win32_Products
function Is-Installed-App {
    param (
        [string]$Name
    )
    if (! $Script:cached_Win32_Products) {
        Write-Host "Caching Get-WmiObject -Class Win32_Product"
        $Script:cached_Win32_Products = Get-WmiObject -Class Win32_Product
    }
    $Script:cached_Win32_Products | Where-Object -Property Name -like $Name
}

function Install-Winget-Apps {
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --id 'gerardog.gsudo'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --id 'Microsoft.PowerShell'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact --name 'HEIF Image Extensions'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact --name 'Webp Image Extensions'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact --name 'VP9 Video Extensions'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --exact --name 'Web Media Extensions'
    winget.exe install --silent --no-upgrade --accept-package-agreements --accept-source-agreements --id 'AgileBits.1Password'
}

function Install-Scoop {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
}

function Install-Scoop-Apps {
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

function funcName {
    
}