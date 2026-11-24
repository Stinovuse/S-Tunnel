; S Tunnel: при удалении программы (но не при обновлении) снимаем её правила
!macro customUnInstall
  ${ifNot} ${isUpdated}
    nsExec::Exec 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Remove-NetFirewallRule -Group STunnelApps -ErrorAction SilentlyContinue"'
    nsExec::Exec 'schtasks.exe /Delete /F /TN "S Tunnel"'
  ${endIf}
!macroend
