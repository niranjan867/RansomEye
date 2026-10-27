# Routine admin script: installs an agent from the internal share.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
$dest = Join-Path $env:TEMP 'agent.msi'
Invoke-WebRequest -Uri https://updates.example.invalid/agent.msi -OutFile $dest
Write-Output "Downloaded to $dest`r`n"
