# S Tunnel — аварийное восстановление интернета.
# Убирает kill switch и возвращает правила брандмауэра в состояние до подключения.
$ErrorActionPreference = 'Continue'
Get-Process sing-box -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-NetFirewallRule -Group 'STunnel' -ErrorAction SilentlyContinue
$state = Join-Path $env:ProgramData 'STunnel\killswitch.json'
if (Test-Path $state) {
  $s = Get-Content -Raw -Path $state | ConvertFrom-Json
  foreach ($p in @($s.profiles)) {
    if ($p -and $p.Name) { Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction }
  }
  $names = @(@($s.rules) | Where-Object { $_ }); if ($names.Count) { Enable-NetFirewallRule -Name $names -ErrorAction SilentlyContinue }
  Remove-Item -Force -Path $state -ErrorAction SilentlyContinue
  Write-Host 'Правила брандмауэра восстановлены из сохранённого состояния.'
} else {
  Get-NetFirewallProfile -PolicyStore PersistentStore | Where-Object { $_.DefaultOutboundAction -eq 'Block' } |
    ForEach-Object { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction NotConfigured }
  Write-Host 'Сохранённого состояния нет; исходящие соединения разрешены по умолчанию.'
}
Write-Host 'Готово. Интернет должен работать.'
