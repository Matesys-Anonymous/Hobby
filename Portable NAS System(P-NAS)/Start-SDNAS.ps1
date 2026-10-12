#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptPath = $MyInvocation.MyCommand.Path
$AppDir = Split-Path -Parent $ScriptPath
$DataDir = Join-Path $AppDir 'Data'
$ConfigDir = Join-Path $AppDir 'Config'
$LogDir = Join-Path $AppDir 'Logs'
$DeviceIdFile = Join-Path $ConfigDir 'device-id.txt'
$SettingsFile = Join-Path $ConfigDir 'settings.json'
$LogFile = Join-Path $LogDir 'sdnas.log'
$LanFirewallRule = 'PortableSDNAS-SMB-LAN-In'
$TailscaleFirewallRule = 'PortableSDNAS-SMB-Tailscale-In'

$script:Cleaned = $false
$script:NetworkProfileChanged = $false
$script:OriginalNetworkCategory = $null
$script:ChangedInterfaceIndex = $null

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    if (-not (Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
    $line = '[{0}][{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Administrator {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath
    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
    exit 0
}

function Initialize-Folders {
    foreach ($dir in @($DataDir, $ConfigDir, $LogDir)) {
        if (-not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
    }
}

function Get-DeviceId {
    if (Test-Path $DeviceIdFile) {
        $id = (Get-Content $DeviceIdFile -Raw).Trim()
        $parsed = [Guid]::Empty
        if ([Guid]::TryParse($id, [ref]$parsed)) { return $id }
        throw 'Invalid device-id.txt. Delete it and start again.'
    }
    $id = [Guid]::NewGuid().ToString()
    Set-Content $DeviceIdFile $id -Encoding ASCII
    return $id
}

function Get-Settings {
    param([string]$DefaultShareName)
    if (-not (Test-Path $SettingsFile)) {
        [ordered]@{
            schemaVersion = 2
            shareName = $DefaultShareName
            allowWrite = $true
            enableLan = $true
            temporarilyMakeLanPrivate = $true
            enableTailscale = $true
            encryptSmbTraffic = $false
            concurrentUserLimit = 20
        } | ConvertTo-Json | Set-Content $SettingsFile -Encoding UTF8
    }
    $settings = Get-Content $SettingsFile -Raw | ConvertFrom-Json
    $defaults = [ordered]@{
        allowWrite = $true
        enableLan = $true
        temporarilyMakeLanPrivate = $true
        enableTailscale = $true
        encryptSmbTraffic = $false
        concurrentUserLimit = 20
    }
    foreach ($name in $defaults.Keys) {
        if ($null -eq $settings.PSObject.Properties[$name]) {
            $settings | Add-Member -NotePropertyName $name -NotePropertyValue $defaults[$name]
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$settings.shareName)) { throw 'shareName is empty.' }
    if ([string]$settings.shareName -notmatch '^[A-Za-z0-9_-]{1,40}$') { throw 'shareName contains invalid characters.' }
    $limit = [int]$settings.concurrentUserLimit
    if ($limit -lt 1 -or $limit -gt 100) { throw 'concurrentUserLimit must be between 1 and 100.' }
    return $settings
}

function Get-PrimaryNetwork {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Where-Object { $_.State -eq 'Alive' -and $_.NextHop -ne '0.0.0.0' })
    $candidates = foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $config = Get-NetIPConfiguration -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $profile = Get-NetConnectionProfile -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        $address = $config.IPv4Address | Select-Object -First 1
        if ($adapter -and $adapter.Status -eq 'Up' -and $address -and
            $address.IPAddress -notlike '127.*' -and $address.IPAddress -notlike '169.254.*' -and
            $adapter.Name -notlike '*Tailscale*') {
            [PSCustomObject]@{
                InterfaceIndex = [uint32]$route.InterfaceIndex
                InterfaceAlias = [string]$adapter.Name
                IPAddress = [string]$address.IPAddress
                NetworkCategory = if ($profile) { [string]$profile.NetworkCategory } else { 'Unknown' }
                TotalMetric = [int]$route.RouteMetric + [int]$route.InterfaceMetric
                IsHardware = [bool]$adapter.HardwareInterface
            }
        }
    }
    $network = $candidates | Sort-Object @{Expression='IsHardware';Descending=$true}, @{Expression='TotalMetric';Ascending=$true} | Select-Object -First 1
    if (-not $network) { throw 'No usable LAN network was found.' }
    return $network
}

function Get-TailscaleIPv4 {
    $paths = @()
    $command = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($command) { $paths += $command.Source }
    if ($env:ProgramFiles) { $paths += (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe') }
    foreach ($path in ($paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
        try {
            $ip = @(& $path ip -4 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^100\.' }) | Select-Object -First 1
            if ($ip) { return [string]$ip }
        } catch { Write-Log "Tailscale CLI lookup failed: $($_.Exception.Message)" 'WARN' }
    }
    $ip = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -like '*Tailscale*' -and $_.IPAddress -match '^100\.' } |
        Select-Object -ExpandProperty IPAddress -First 1
    if ($ip) { return [string]$ip }
    return $null
}

function Get-TailscaleAdapter {
    return Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*Tailscale*' -and $_.Status -eq 'Up' } |
        Select-Object -First 1
}

function Enable-TemporaryPrivateNetwork {
    param($Network)
    $profile = Get-NetConnectionProfile -InterfaceIndex $Network.InterfaceIndex -ErrorAction Stop
    $script:OriginalNetworkCategory = [string]$profile.NetworkCategory
    $script:ChangedInterfaceIndex = [uint32]$profile.InterfaceIndex
    if ($profile.NetworkCategory -eq 'DomainAuthenticated' -or $profile.NetworkCategory -eq 'Private') { return }
    if ($profile.NetworkCategory -ne 'Public') { throw "Unsupported network category: $($profile.NetworkCategory)" }
    Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
    $updated = Get-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -ErrorAction Stop
    if ($updated.NetworkCategory -ne 'Private') { throw 'Failed to change LAN network to Private.' }
    $script:NetworkProfileChanged = $true
    Write-Log "Network profile temporarily changed: Public -> Private ($($Network.InterfaceAlias))"
}

function Restore-NetworkProfile {
    if (-not $script:NetworkProfileChanged -or $null -eq $script:ChangedInterfaceIndex) { return }
    try {
        Set-NetConnectionProfile -InterfaceIndex $script:ChangedInterfaceIndex -NetworkCategory $script:OriginalNetworkCategory -ErrorAction Stop
        Write-Log "Network profile restored to: $($script:OriginalNetworkCategory)"
        $script:NetworkProfileChanged = $false
    } catch { Write-Warning "Failed to restore network profile: $($_.Exception.Message)" }
}

function Read-Password {
    while ($true) {
        $p1 = Read-Host 'Enter SMB password (8 or more characters)' -AsSecureString
        $p2 = Read-Host 'Enter the same password again' -AsSecureString
        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
        $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
        try {
            $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
            $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
            if ($s1.Length -lt 8) { Write-Warning 'Password must contain at least 8 characters.'; continue }
            if ($s1 -ne $s2) { Write-Warning 'Passwords do not match.'; continue }
            return $p1
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
            $s1 = $null; $s2 = $null
        }
    }
}

function Initialize-User {
    param([string]$UserName, [SecureString]$Password)
    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if ($user) {
        Set-LocalUser -Name $UserName -Password $Password
        if (-not $user.Enabled) { Enable-LocalUser -Name $UserName }
    } else {
        New-LocalUser -Name $UserName -Password $Password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'Portable SD-NAS temporary account' | Out-Null
    }
    Write-Log "Temporary user ready: $UserName"
}

function Initialize-Share {
    param([string]$ShareName, [string]$UserName, [bool]$AllowWrite, [bool]$EncryptData, [int]$ConcurrentUserLimit)
    $existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    if ($existing) {
        if ([IO.Path]::GetFullPath($existing.Path) -ne [IO.Path]::GetFullPath($DataDir)) { throw "Share name used by another path: $ShareName" }
        Remove-SmbShare -Name $ShareName -Force -Confirm:$false
    }
    $account = "$env:COMPUTERNAME\$UserName"
    $parameters = @{
        Name=$ShareName; Path=$DataDir; Description='Portable SD-NAS'; CachingMode='None'
        EncryptData=$EncryptData; ConcurrentUserLimit=$ConcurrentUserLimit
    }
    if ($AllowWrite) { $parameters.ChangeAccess = $account } else { $parameters.ReadAccess = $account }
    New-SmbShare @parameters | Out-Null
    Write-Log "SMB share created: $ShareName"
}

function Initialize-LanFirewall {
    param($Network)
    if ($Network.NetworkCategory -ne 'Private' -and $Network.NetworkCategory -ne 'DomainAuthenticated') {
        throw "LAN network is not Private: $($Network.NetworkCategory)"
    }
    Get-NetFirewallRule -Name $LanFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $LanFirewallRule -DisplayName 'Portable SD-NAS SMB via LAN' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Profile Private -InterfaceAlias $Network.InterfaceAlias -RemoteAddress LocalSubnet | Out-Null
    Write-Log "Temporary LAN SMB rule created for: $($Network.InterfaceAlias)"
}

function Initialize-TailscaleFirewall {
    param([string]$TailscaleIPAddress)
    Get-NetFirewallRule -Name $TailscaleFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $adapter = Get-TailscaleAdapter
    if (-not $adapter) { Write-Log 'Tailscale adapter is not active. Tailscale SMB access was not enabled.' 'WARN'; return $false }
    New-NetFirewallRule -Name $TailscaleFirewallRule -DisplayName 'Portable SD-NAS SMB via Tailscale' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Profile Any -InterfaceAlias $adapter.Name -LocalAddress $TailscaleIPAddress -RemoteAddress '100.64.0.0/10' | Out-Null
    Write-Log "Temporary Tailscale SMB rule created: $TailscaleIPAddress"
    return $true
}

function Get-OpenFiles {
    $root = [IO.Path]::GetFullPath($DataDir).TrimEnd([char]'\')
    return @(Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and ([IO.Path]::GetFullPath($_.Path)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)
    })
}

function Cleanup-SDNAS {
    param([string]$ShareName, [string]$UserName, [switch]$Force)
    if ($script:Cleaned) { return }
    $open = @(Get-OpenFiles)
    if ($open.Count -gt 0 -and -not $Force) {
        $open | Select-Object ClientComputerName,ClientUserName,ShareRelativePath | Format-Table -AutoSize
        throw 'Files are still open. Close them and try again.'
    }
    if ($open.Count -gt 0) {
        foreach ($file in $open) { Close-SmbOpenFile -FileId $file.FileId -Force -Confirm:$false -ErrorAction SilentlyContinue }
    }
    Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue | Remove-SmbShare -Force -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name $LanFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name $TailscaleFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
    Restore-NetworkProfile
    $script:Cleaned = $true
    Write-Host 'Share stopped. Use Windows Safely Remove Hardware before removing the SD card.'
}

$shareName = $null
$userName = $null
$lanNetwork = $null
$tailscaleIP = $null
$tailscaleEnabled = $false

try {
    if (-not (Test-Administrator)) { Restart-Administrator }
    Initialize-Folders
    $deviceId = Get-DeviceId
    $shortId = $deviceId.Replace('-','').Substring(0,8).ToLowerInvariant()
    $userName = "sdn_$shortId"
    $settings = Get-Settings -DefaultShareName ("SDNAS-" + $shortId.Substring(0,6))
    $shareName = [string]$settings.shareName

    if ([bool]$settings.enableLan) {
        $lanNetwork = Get-PrimaryNetwork
        if ([bool]$settings.temporarilyMakeLanPrivate) {
            Enable-TemporaryPrivateNetwork -Network $lanNetwork
            $lanNetwork = Get-PrimaryNetwork
        } elseif ($lanNetwork.NetworkCategory -ne 'Private' -and $lanNetwork.NetworkCategory -ne 'DomainAuthenticated') {
            throw 'LAN is enabled but its network profile is not Private.'
        }
    }

    if ([bool]$settings.enableTailscale) { $tailscaleIP = Get-TailscaleIPv4 }
    if (-not $lanNetwork -and -not $tailscaleIP) { throw 'Neither LAN nor Tailscale is available.' }

    $password = Read-Password
    Initialize-User -UserName $userName -Password $password
    Initialize-Share -ShareName $shareName -UserName $userName -AllowWrite ([bool]$settings.allowWrite) -EncryptData ([bool]$settings.encryptSmbTraffic) -ConcurrentUserLimit ([int]$settings.concurrentUserLimit)

    if ($lanNetwork) { Initialize-LanFirewall -Network $lanNetwork }
    if ($tailscaleIP) { $tailscaleEnabled = Initialize-TailscaleFirewall -TailscaleIPAddress $tailscaleIP }

    Clear-Host
    Write-Host 'Portable SD-NAS is running.'
    Write-Host "Share name : $shareName"
    Write-Host "User name  : $env:COMPUTERNAME\$userName"
    if ($lanNetwork) {
        Write-Host "LAN        : smb://$($lanNetwork.IPAddress)/$shareName"
    }
    if ($tailscaleEnabled) {
        Write-Host "Tailscale  : smb://$tailscaleIP/$shareName"
    }
    Write-Host ''
    Write-Host "Domain     : $env:COMPUTERNAME"
    Write-Host "Login      : $userName"
    Write-Host 'Password   : the password entered at startup'
    Write-Host ''
    Write-Host 'Press Enter to stop normally. Press F to force stop. Press S for sessions.'

    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq [ConsoleKey]::Enter) {
            try { Cleanup-SDNAS -ShareName $shareName -UserName $userName; break } catch { Write-Warning $_.Exception.Message }
        } elseif ($key.Key -eq [ConsoleKey]::F) {
            if ((Read-Host 'Type FORCE to continue') -eq 'FORCE') { Cleanup-SDNAS -ShareName $shareName -UserName $userName -Force; break }
        } elseif ($key.Key -eq [ConsoleKey]::S) {
            Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName,ClientUserName,NumOpens,Dialect | Format-Table -AutoSize
            $open = @(Get-OpenFiles)
            Write-Host "Open file count: $($open.Count)"
            $open | Select-Object ClientComputerName,ClientUserName,ShareRelativePath | Format-Table -AutoSize
        }
    }
} catch {
    Write-Error $_.Exception.Message
    if ($shareName -and $userName) {
        try { Cleanup-SDNAS -ShareName $shareName -UserName $userName -Force } catch { Write-Warning $_.Exception.Message }
    } else {
        Get-NetFirewallRule -Name $LanFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Get-NetFirewallRule -Name $TailscaleFirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Restore-NetworkProfile
    }
    Read-Host 'Press Enter to exit'
    exit 1
}
