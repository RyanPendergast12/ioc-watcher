# Registers "IOC Watcher Vault Sync": every 15 min, git pull ioc-watcher + append approved IOCs to the vault.
# Run once:  powershell -ExecutionPolicy Bypass -File sync\install_task.ps1
# Remove:    Unregister-ScheduledTask -TaskName "IOC Watcher Vault Sync" -Confirm:$false
$repo   = Split-Path -Parent $PSScriptRoot
$py     = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python.exe).Source }
$action  = New-ScheduledTaskAction -Execute $py -Argument "`"$repo\sync\vault_sync.py`"" -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "IOC Watcher Vault Sync" -Action $action -Trigger $trigger -Settings $settings `
  -Description "Append Discord-approved IOCs from github.com/RyanPendergast12/ioc-watcher into the Obsidian vault" -Force | Out-Null
Write-Host "Registered. Log: $env:LOCALAPPDATA\ioc-watcher\sync.log"
