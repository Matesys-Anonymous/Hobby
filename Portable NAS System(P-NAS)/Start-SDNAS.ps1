#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# Portable SD-NAS
# Windows 10 / 11, Windows PowerShell 5.1
# ============================================================

$ScriptPath = $MyInvocation.MyCommand.Path
$AppDir = Split-Path -Parent $ScriptPath
$DataDir = Join-Path $AppDir 'Data'
$ConfigDir = Join-Path $AppDir 'Config'
$LogDir = Join-Path $AppDir 'Logs'
$DeviceIdFile = Join-Path $ConfigDir 'device-id.txt'
$SettingsFile = Join-Path $ConfigDir 'settings.json'
$LogFile = Join-Path $LogDir 'sdnas.log'
$FirewallRuleName = 'PortableSDNAS-SMB-In'
$script:Cleaned = $false
$script:NetworkProfileChanged = $false
$script:OriginalNetworkCategory = $null
$script:ChangedInterfaceIndex = $null

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }

    $line = '[{0}][{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Administrator {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath
    Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs
    exit 0
}

function Initialize-Folders {
    foreach ($dir in @($DataDir, $ConfigDir, $LogDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

function Get-DeviceId {
    if (Test-Path $DeviceIdFile) {
        $id = (Get-Content -Path $DeviceIdFile -Raw).Trim()
        $parsed = [Guid]::Empty

        if ([Guid]::TryParse($id, [ref]$parsed)) {
            return $id
        }

        throw 'Invalid device-id.txt. Delete the file and start again.'
    }

    $id = [Guid]::NewGuid().ToString()
    Set-Content -Path $DeviceIdFile -Value $id -Encoding ASCII
    return $id
}

function Get-Settings {
    param([Parameter(Mandatory = $true)][string]$DefaultShareName)

    if (-not (Test-Path $SettingsFile)) {
        [ordered]@{
            schemaVersion = 1
            shareName = $DefaultShareName
            allowWrite = $true
            privateNetworkOnly = $true
            encryptSmbTraffic = $false
            concurrentUserLimit = 20
        } | ConvertTo-Json | Set-Content -Path $SettingsFile -Encoding UTF8
    }

    $settings = Get-Content -Path $SettingsFile -Raw | ConvertFrom-Json

    if ([string]::IsNullOrWhiteSpace([string]$settings.shareName)) {
        throw 'shareName is empty in settings.json.'
    }

    if ([string]$settings.shareName -notmatch '^[A-Za-z0-9_-]{1,40}$') {
        throw 'shareName contains invalid characters.'
    }

    if ($null -eq $settings.PSObject.Properties['allowWrite']) {
        $settings | Add-Member -NotePropertyName allowWrite -NotePropertyValue $true
    }

    if ($null -eq $settings.PSObject.Properties['privateNetworkOnly']) {
        $settings | Add-Member -NotePropertyName privateNetworkOnly -NotePropertyValue $true
    }

    if ($null -eq $settings.PSObject.Properties['encryptSmbTraffic']) {
        $settings | Add-Member -NotePropertyName encryptSmbTraffic -NotePropertyValue $false
    }

    if ($null -eq $settings.PSObject.Properties['concurrentUserLimit']) {
        $settings | Add-Member -NotePropertyName concurrentUserLimit -NotePropertyValue 20
    }

    $limit = [int]$settings.concurrentUserLimit
    if ($limit -lt 1 -or $limit -gt 100) {
        throw 'concurrentUserLimit must be between 1 and 100.'
    }

    return $settings
}

function Get-PrimaryNetwork {
    $routes = @(
        Get-NetRoute `
            -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction Stop |
        Where-Object {
            $_.State -eq 'Alive' -and
            $_.NextHop -ne '0.0.0.0'
        }
    )

    if ($routes.Count -eq 0) {
        throw 'No active IPv4 default route was found.'
    }

    $candidates = foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $config = Get-NetIPConfiguration -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $profile = Get-NetConnectionProfile -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $address = $config.IPv4Address | Select-Object -First 1

        if (
            $null -ne $adapter -and
            $adapter.Status -eq 'Up' -and
            $null -ne $address -and
            $address.IPAddress -notlike '127.*' -and
            $address.IPAddress -notlike '169.254.*'
        ) {
            [PSCustomObject]@{
                InterfaceIndex = $route.InterfaceIndex
                InterfaceAlias = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                IPAddress = $address.IPAddress
                NetworkCategory = if ($profile) { $profile.NetworkCategory } else { 'Unknown' }
                RouteMetric = [int]$route.RouteMetric
                InterfaceMetric = [int]$route.InterfaceMetric
                TotalMetric = [int]$route.RouteMetric + [int]$route.InterfaceMetric
                IsHardware = [bool]$adapter.HardwareInterface
            }
        }
    }

    $primary = $candidates |
        Sort-Object `
            @{ Expression = 'IsHardware'; Descending = $true },
            @{ Expression = 'TotalMetric'; Ascending = $true } |
        Select-Object -First 1

    if (-not $primary) {
        throw 'No usable primary IPv4 network was found.'
    }

    return $primary
}


function Enable-TemporaryPrivateNetwork {
    param([Parameter(Mandatory = $true)]$Network)

    $profile = Get-NetConnectionProfile `
        -InterfaceIndex $Network.InterfaceIndex `
        -ErrorAction Stop

    $script:OriginalNetworkCategory = [string]$profile.NetworkCategory
    $script:ChangedInterfaceIndex = [uint32]$profile.InterfaceIndex

    if ($profile.NetworkCategory -eq 'DomainAuthenticated') {
        Write-Log 'DomainAuthenticated profile detected. No temporary change is required.'
        return
    }

    if ($profile.NetworkCategory -eq 'Private') {
        Write-Log 'Primary network is already Private. It will not be changed on exit.'
        return
    }

    if ($profile.NetworkCategory -ne 'Public') {
        throw "Unsupported network category: $($profile.NetworkCategory)"
    }

    Set-NetConnectionProfile `
        -InterfaceIndex $profile.InterfaceIndex `
        -NetworkCategory Private `
        -ErrorAction Stop

    $updated = Get-NetConnectionProfile `
        -InterfaceIndex $profile.InterfaceIndex `
        -ErrorAction Stop

    if ($updated.NetworkCategory -ne 'Private') {
        throw 'Failed to change the primary network profile to Private.'
    }

    $script:NetworkProfileChanged = $true
    Write-Log "Network profile temporarily changed: Public -> Private ($($Network.InterfaceAlias))"
}

function Restore-NetworkProfile {
    if (-not $script:NetworkProfileChanged) {
        return
    }

    if ($null -eq $script:ChangedInterfaceIndex) {
        return
    }

    try {
        Set-NetConnectionProfile `
            -InterfaceIndex $script:ChangedInterfaceIndex `
            -NetworkCategory $script:OriginalNetworkCategory `
            -ErrorAction Stop

        Write-Log "Network profile restored to: $($script:OriginalNetworkCategory)"
        $script:NetworkProfileChanged = $false
    }
    catch {
        Write-Warning "Failed to restore network profile: $($_.Exception.Message)"
    }
}

function Test-PrivateNetwork {
    $network = Get-PrimaryNetwork
    return (
        $network.NetworkCategory -eq 'Private' -or
        $network.NetworkCategory -eq 'DomainAuthenticated'
    )
}

function Read-Password {
    while ($true) {
        $password1 = Read-Host 'Enter SMB password (8 or more characters)' -AsSecureString
        $password2 = Read-Host 'Enter the same password again' -AsSecureString
        $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password1)
        $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password2)

        try {
            $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
            $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)

            if ($plain1.Length -lt 8) {
                Write-Warning 'Password must contain at least 8 characters.'
                continue
            }

            if ($plain1 -ne $plain2) {
                Write-Warning 'Passwords do not match.'
                continue
            }

            return $password1
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
            $plain1 = $null
            $plain2 = $null
        }
    }
}

function Initialize-User {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][SecureString]$Password
    )

    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue

    if ($user) {
        Set-LocalUser -Name $UserName -Password $Password
        if (-not $user.Enabled) {
            Enable-LocalUser -Name $UserName
        }
    }
    else {
        New-LocalUser `
            -Name $UserName `
            -Password $Password `
            -AccountNeverExpires `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -Description 'Portable SD-NAS temporary account' |
        Out-Null
    }

    Write-Log "Temporary user ready: $UserName"
}

function Initialize-Share {
    param(
        [Parameter(Mandatory = $true)][string]$ShareName,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][bool]$AllowWrite,
        [Parameter(Mandatory = $true)][bool]$EncryptData,
        [Parameter(Mandatory = $true)][int]$ConcurrentUserLimit
    )

    $existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue

    if ($existing) {
        if ([IO.Path]::GetFullPath($existing.Path) -ne [IO.Path]::GetFullPath($DataDir)) {
            throw "Share name is already used by another path: $ShareName"
        }

        Remove-SmbShare -Name $ShareName -Force -Confirm:$false
    }

    $account = "$env:COMPUTERNAME\$UserName"
    $parameters = @{
        Name = $ShareName
        Path = $DataDir
        Description = 'Portable SD-NAS'
        CachingMode = 'None'
        EncryptData = $EncryptData
        ConcurrentUserLimit = $ConcurrentUserLimit
    }

    if ($AllowWrite) {
        $parameters['ChangeAccess'] = $account
    }
    else {
        $parameters['ReadAccess'] = $account
    }

    New-SmbShare @parameters | Out-Null
    Write-Log "SMB share created: $ShareName"
}

function Initialize-Firewall {
    param([Parameter(Mandatory = $true)]$Network)

    if (
        $Network.NetworkCategory -ne 'Private' -and
        $Network.NetworkCategory -ne 'DomainAuthenticated'
    ) {
        throw (
            "Primary network '{0}' is not Private. Current category: {1}" -f
            $Network.InterfaceAlias,
            $Network.NetworkCategory
        )
    }

    Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    New-NetFirewallRule `
        -Name $FirewallRuleName `
        -DisplayName 'Portable SD-NAS SMB' `
        -Description 'Temporary SMB rule for Portable SD-NAS' `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 445 `
        -Profile Private `
        -InterfaceAlias $Network.InterfaceAlias `
        -RemoteAddress LocalSubnet |
    Out-Null

    Write-Log "Temporary firewall rule created for: $($Network.InterfaceAlias)"
}

function Get-OpenFiles {
    $root = [IO.Path]::GetFullPath($DataDir).TrimEnd([char]'\')

    return @(
        Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Path -and
            ([IO.Path]::GetFullPath($_.Path)).StartsWith(
                $root,
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    )
}

function Cleanup-SDNAS {
    param(
        [Parameter(Mandatory = $true)][string]$ShareName,
        [Parameter(Mandatory = $true)][string]$UserName,
        [switch]$Force
    )

    if ($script:Cleaned) {
        return
    }

    $openFiles = @(Get-OpenFiles)

    if ($openFiles.Count -gt 0 -and -not $Force) {
        $openFiles |
            Select-Object ClientComputerName, ClientUserName, ShareRelativePath |
            Format-Table -AutoSize

        throw 'Files are still open. Close them and try again.'
    }

    if ($openFiles.Count -gt 0 -and $Force) {
        foreach ($file in $openFiles) {
            Close-SmbOpenFile `
                -FileId $file.FileId `
                -Force `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }

    Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue |
        Remove-SmbShare -Force -Confirm:$false -ErrorAction SilentlyContinue

    Get-NetFirewallRule -Name $FirewallRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue |
        Remove-LocalUser -ErrorAction SilentlyContinue

    Restore-NetworkProfile

    $script:Cleaned = $true
    Write-Host 'Share stopped.'
    Write-Host 'Use Windows Safely Remove Hardware before removing the SD card.'
}

$shareName = $null
$userName = $null

try {
    if (-not (Test-Administrator)) {
        Restart-Administrator
    }

    Initialize-Folders

    $network = Get-PrimaryNetwork
    Write-Host "Primary network : $($network.InterfaceAlias)"
    Write-Host "Primary IPv4    : $($network.IPAddress)"
    Write-Host "Network profile : $($network.NetworkCategory)"
    Write-Host ''

    $deviceId = Get-DeviceId
    $shortId = $deviceId.Replace('-', '').Substring(0, 8).ToLowerInvariant()
    $userName = "sdn_$shortId"
    $settings = Get-Settings -DefaultShareName ("SDNAS-" + $shortId.Substring(0, 6))
    $shareName = [string]$settings.shareName

    if ([bool]$settings.privateNetworkOnly) {
        Enable-TemporaryPrivateNetwork -Network $network
        $network = Get-PrimaryNetwork
    }

    $password = Read-Password

    Initialize-User `
        -UserName $userName `
        -Password $password

    Initialize-Share `
        -ShareName $shareName `
        -UserName $userName `
        -AllowWrite ([bool]$settings.allowWrite) `
        -EncryptData ([bool]$settings.encryptSmbTraffic) `
        -ConcurrentUserLimit ([int]$settings.concurrentUserLimit)

    Initialize-Firewall -Network $network

    Clear-Host
    Write-Host 'Portable SD-NAS is running.'
    Write-Host "Network    : $($network.InterfaceAlias)"
    Write-Host "IPv4       : $($network.IPAddress)"
    Write-Host "Share name : $shareName"
    Write-Host "User name  : $env:COMPUTERNAME\$userName"
    Write-Host "Windows    : \\$($network.IPAddress)\$shareName"
    Write-Host "Documents  : smb://$($network.IPAddress)/$shareName"
    Write-Host ''
    Write-Host 'Documents app settings:'
    Write-Host "  Host/URL : smb://$($network.IPAddress)/$shareName"
    Write-Host "  Domain   : $env:COMPUTERNAME"
    Write-Host "  Login    : $userName"
    Write-Host '  Password : the password entered at startup'
    Write-Host ''
    Write-Host 'Press Enter to stop normally.'
    Write-Host 'Press F to force stop.'
    Write-Host 'Press S to show SMB sessions and open files.'

    while ($true) {
        $key = [Console]::ReadKey($true)

        if ($key.Key -eq [ConsoleKey]::Enter) {
            try {
                Cleanup-SDNAS -ShareName $shareName -UserName $userName
                break
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }
        elseif ($key.Key -eq [ConsoleKey]::F) {
            if ((Read-Host 'Type FORCE to continue') -eq 'FORCE') {
                Cleanup-SDNAS -ShareName $shareName -UserName $userName -Force
                break
            }
        }
        elseif ($key.Key -eq [ConsoleKey]::S) {
            Write-Host ''
            Write-Host 'SMB sessions:'
            Get-SmbSession -ErrorAction SilentlyContinue |
                Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect |
                Format-Table -AutoSize

            $openFiles = @(Get-OpenFiles)
            Write-Host "Open file count: $($openFiles.Count)"
            $openFiles |
                Select-Object ClientComputerName, ClientUserName, ShareRelativePath |
                Format-Table -AutoSize
        }
    }
}
catch {
    Write-Error $_.Exception.Message

    if ($shareName -and $userName) {
        try {
            Cleanup-SDNAS -ShareName $shareName -UserName $userName -Force
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }

    Restore-NetworkProfile
    Read-Host 'Press Enter to exit'
    exit 1
}
