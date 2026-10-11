@echo off
setlocal

cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""Get-SmbShare | Where-Object Description -eq '''Portable SD-NAS''' | Remove-SmbShare -Force -Confirm:$false; Get-NetFirewallRule -Name '''PortableSDNAS-SMB-In''' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Get-LocalUser | Where-Object Description -eq '''Portable SD-NAS temporary account''' | Remove-LocalUser; Write-Host '''Portable SD-NAS cleanup completed.'''; Read-Host '''Press Enter'''''"

endlocal