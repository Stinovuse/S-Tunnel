; S Tunnel: при удалении программы (но не при обновлении) снимаем всё, что она поставила
!macro customUnInstall
  ${ifNot} ${isUpdated}
    nsExec::Exec 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Stop-ScheduledTask -TaskName \"S Tunnel Guard\" -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName \"S Tunnel Guard\" -Confirm:$$false -ErrorAction SilentlyContinue; Remove-NetFirewallRule -Group STunnelOnly -ErrorAction SilentlyContinue; Remove-NetFirewallRule -Group STunnelApps -ErrorAction SilentlyContinue; Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $$env:ProgramData \"STunnel\apps.json\"),(Join-Path $$env:ProgramData \"STunnel\guard.ps1\")"'
    nsExec::Exec 'schtasks.exe /Delete /F /TN "S Tunnel"'
  ${endIf}
!macroend
