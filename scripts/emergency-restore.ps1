# S Tunnel — аварийное восстановление интернета.
# Убирает kill switch и возвращает правила брандмауэра в состояние до подключения.
$ErrorActionPreference = 'Continue'
Get-Process sing-box -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-NetFirewallRule -Group 'STunnel' -ErrorAction SilentlyContinue
$state = Join-Path $env:ProgramData 'STunnel\killswitch.json'
if (Test-Path $state) {
  $s = $null
  try { $s = Get-Content -Raw -Path $state | ConvertFrom-Json } catch {}
  # Файлу не доверяем вслепую: восстанавливаем только допустимые значения.
  # Брандмауэр по этому файлу никогда не ВЫКЛЮЧАЕТСЯ (Enabled=False игнорируется).
  foreach ($p in @($s.profiles)) {
    if ($p -and @('Domain','Private','Public') -contains $p.Name -and
        @('Allow','Block','NotConfigured') -contains $p.DefaultOutboundAction) {
      Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction SilentlyContinue
    }
  }
  $names = @(@($s.rules) | Where-Object { $_ -is [string] -and $_ })
  if ($names.Count) {
    $ok = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled False -ErrorAction SilentlyContinue |
      Where-Object { $names -contains $_.Name } | ForEach-Object { $_.Name })
    if ($ok.Count) { Enable-NetFirewallRule -Name $ok -ErrorAction SilentlyContinue }
  }
  Remove-Item -Force -Path $state -ErrorAction SilentlyContinue
  Write-Host 'Правила брандмауэра восстановлены из сохранённого состояния.'
} else {
  Get-NetFirewallProfile -PolicyStore PersistentStore | Where-Object { $_.DefaultOutboundAction -eq 'Block' } |
    ForEach-Object { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction NotConfigured }
  Write-Host 'Сохранённого состояния нет; исходящие соединения разрешены по умолчанию.'
}
Write-Host 'Готово. Интернет должен работать.'
Write-Host 'Приложения из списка «Только через S Tunnel» по-прежнему выходят в интернет только через туннель — так задумано.'
