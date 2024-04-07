function Install-PS {
    winget install --silent --id 'Microsoft.PowerShell' --source winget
}

function Is-Installed-Package {
    param (
        [string]$name
    )
    Get-Package -Name "$name" -ErrorAction SilentlyContinue
}

$cached_Win32_Products
function Is-Installed-App {
    param (
        [string]$name
    )
    if (! $Script:cached_Win32_Products) {
        Write-Host "Caching Get-WmiObject -Class Win32_Product"
        $Script:cached_Win32_Products = Get-WmiObject -Class Win32_Product
    }
    $cached_Win32_Products | Where-Object -Property Name -like $name
}

Is-Installed-App F

function Install-Winget-Apps {
    winget.exe install -e --id gerardog.gsudo
    winget.exe install -e --name "HEIF Image Extensions"
    winget.exe install -e --name "Webp Image Extensions"
    winget.exe install -e --name "VP9 Video Extensions"
    winget.exe install -e --name "Web Media Extensions"
    winget.exe install -e --id AgileBits.1Password
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