# Registers "IOC Watcher Curator": nightly 02:30, proposes writeup refreshes / coverage gaps / new pages / hygiene.
# Runs only while the laptop is on (StartWhenAvailable catches up after sleep).
# Run once:  powershell -ExecutionPolicy Bypass -File curator\install_task.ps1
# Remove:    Unregister-ScheduledTask -TaskName "IOC Watcher Curator" -Confirm:$false
$repo = Split-Path -Parent $PSScriptRoot
$py   = (Get-Command python.exe).Source
$action  = New-ScheduledTaskAction -Execute $py -Argument "-m curator.run" -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -Daily -At 2:30am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 3)
Register-ScheduledTask -TaskName "IOC Watcher Curator" -Action $action -Trigger $trigger -Settings $settings `
  -Description "Nightly vault curator: proposes writeup/coverage/hygiene changes for Discord approval" -Force | Out-Null
Write-Host "Registered. Log: $env:LOCALAPPDATA\ioc-watcher\curator.log"
