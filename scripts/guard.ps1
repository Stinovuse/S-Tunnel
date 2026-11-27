# S Tunnel Guard — фоновая защита «Только через S Tunnel».
# Работает как задача Планировщика от имени SYSTEM: запускается вместе с Windows
# и не зависит от того, открыт ли S Tunnel.
#
# 1. Для каждого .exe из выбранных приложений держит ПОСТОЯННО включённое правило
#    брандмауэра Block для любого исходящего трафика, КРОМЕ трафика с адреса туннеля.
#    Туннель включён -> программа работает через прокси; выключен -> сети нет.
#    Правило не переключается, поэтому окон с реальным IP нет вообще.
# 2. Следит за запуском процессов: программа из выбранных приложений без туннеля
#    сразу закрывается; для нового .exe (после обновления) тут же добавляется правило.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Dir      = Join-Path $env:ProgramData 'STunnel'
$AppsFile = Join-Path $Dir 'apps.json'
$LogFile  = Join-Path $Dir 'guard-events.log'
$Group    = 'STunnelOnly'
$OldGroup = 'STunnelApps'
$TunName  = 'STunnel'
$RescanMinutes = 2

# Исходящий трафик блокируется со ВСЕХ локальных адресов, кроме адресов туннеля
# (172.31.249.1, fdfe:5354:4e4c:1::1) и loopback (127.0.0.0/8, ::1).
$LocalExceptTunnel = @(
  '0.0.0.0-126.255.255.255',
  '128.0.0.0-172.31.249.0',
  '172.31.249.2-255.255.255.255',
  '::2-fdfe:5354:4e4c:1::',
  'fdfe:5354:4e4c:1::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
)

$Forbidden = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'explorer.exe', 'svchost.exe',
               'sing-box.exe', 's tunnel.exe', 'icacls.exe', 'schtasks.exe', 'netsh.exe')

function Log([string]$kind, [string]$text) {
  try { Add-Content -LiteralPath $LogFile -Value ((Get-Date).ToString('o') + "`t" + $kind + "`t" + $text) -Encoding UTF8 } catch {}
}

function Test-TunnelUp {
  foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($n.Name -eq $TunName -and $n.OperationalStatus -eq 'Up') { return $true }
  }
  return $false
}

function Read-Apps {
  if (-not (Test-Path -LiteralPath $AppsFile)) { return @() }
  try { return @((Get-Content -Raw -LiteralPath $AppsFile -Encoding UTF8 | ConvertFrom-Json).apps) } catch { return @() }
}

function Add-Exe($t, [string]$path) {
  $leaf = [IO.Path]::GetFileName($path).ToLower()
  if ($Forbidden -contains $leaf) { return }
  if ($path.ToLower().StartsWith($env:SystemRoot.ToLower() + '\')) { return }
  $t.exes[$path.ToLower()] = $path
}

function Add-Folder($t, [string]$folder) {
  $t.dirs += $folder.ToLower().TrimEnd('\')
  Get-ChildItem -LiteralPath $folder -Recurse -Filter *.exe -File -ErrorAction SilentlyContinue |
    Select-Object -First 400 | ForEach-Object { Add-Exe $t $_.FullName }
}

function Get-Targets {
  $t = @{ exes = @{}; dirs = @(); rx = @() }
  $apps = Read-Apps
  $pkgs = $null
  foreach ($a in $apps) {
    if (-not $a -or -not $a.path) { continue }
    switch ([string]$a.type) {
      'exe' { Add-Exe $t ([string]$a.path) }
      'dir' { if (Test-Path -LiteralPath $a.path) { Add-Folder $t ([string]$a.path) } }
      'pkg' {
        $m = [regex]::Match([string]$a.path, '^([A-Za-z0-9.-]+)_([a-z0-9]{13})$')
        if (-not $m.Success) { continue }
        $t.rx += ('\\windowsapps\\' + [regex]::Escape($m.Groups[1].Value.ToLower()) + '_[^\\]*__' + $m.Groups[2].Value + '\\')
        if ($null -eq $pkgs) { $pkgs = @(Get-AppxPackage -AllUsers -PackageTypeFilter Main -ErrorAction SilentlyContinue) }
        foreach ($p in $pkgs) {
          if ($p.PackageFamilyName -eq $a.path -and $p.InstallLocation) { Add-Folder $t ([string]$p.InstallLocation) }
        }
      }
    }
  }
  return $t
}

function New-Rule([string]$path) {
  New-NetFirewallRule -DisplayName ('S Tunnel: только через туннель — ' + [IO.Path]::GetFileName($path)) `
    -Group $Group -Direction Outbound -Action Block -Program $path `
    -LocalAddress $LocalExceptTunnel -Enabled True -ErrorAction SilentlyContinue | Out-Null
}

function Sync-Rules($t) {
  $have = @{}
  foreach ($f in @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
    $k = ([string]$f.Program).ToLower()
    if (-not $k -or -not $t.exes.ContainsKey($k) -or $have.ContainsKey($k)) {
      Remove-NetFirewallRule -Name $f.InstanceID -ErrorAction SilentlyContinue
    } else { $have[$k] = $true }
  }
  foreach ($k in @($t.exes.Keys)) { if (-not $have.ContainsKey($k)) { New-Rule $t.exes[$k] } }
  # правила постоянно включены — на случай, если их кто-то выключил
  Enable-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue
}

function Test-Guarded($t, [string]$path) {
  $l = $path.ToLower()
  if ($t.exes.ContainsKey($l)) { return $true }
  foreach ($d in $t.dirs) { if ($l.StartsWith($d + '\')) { return $true } }
  foreach ($r in $t.rx) { if ($l -match $r) { return $true } }
  return $false
}

function Stop-Guarded($t) {
  foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
    if ($p.ExecutablePath -and (Test-Guarded $t $p.ExecutablePath)) {
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
      Log 'closed' $p.ExecutablePath
    }
  }
}

# ---- старт ----
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
# правила старых версий (переключаемые) больше не нужны
Remove-NetFirewallRule -Group $OldGroup -ErrorAction SilentlyContinue

Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier stunnel_guard | Out-Null
Log 'started' $PID

$t = $null
$stamp = -1
$lastScan = [datetime]::MinValue
$downSince = Get-Date   # при старте туннеля ещё нет — через 5 секунд закроем выбранные приложения
$swept = $false

while ($true) {
  try {
    $s = 0
    if (Test-Path -LiteralPath $AppsFile) { $s = (Get-Item -LiteralPath $AppsFile).LastWriteTimeUtc.Ticks }
    if ($s -ne $stamp -or ((Get-Date) - $lastScan).TotalMinutes -ge $RescanMinutes) {
      $stamp = $s
      $t = Get-Targets
      Sync-Rules $t
      $lastScan = Get-Date
    }

    # Туннель пропал больше чем на 5 секунд -> закрываем выбранные приложения.
    # Короткие перерывы (перезапуск ядра) не трогаем: сеть у них всё равно заблокирована правилом.
    $up = Test-TunnelUp
    if ($up) { $downSince = $null; $swept = $false }
    elseif (-not $swept) {
      if (-not $downSince) { $downSince = Get-Date }
      if (((Get-Date) - $downSince).TotalSeconds -ge 5) { Stop-Guarded $t; $swept = $true }
    }

    $e = Wait-Event -SourceIdentifier stunnel_guard -Timeout 2
    while ($e) {
      $procId = $e.SourceEventArgs.NewEvent.ProcessID
      Remove-Event -EventIdentifier $e.EventIdentifier
      if ($t.exes.Count -or $t.dirs.Count -or $t.rx.Count) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
        if ($p -and $p.ExecutablePath -and (Test-Guarded $t $p.ExecutablePath)) {
          if (-not (Test-TunnelUp)) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Log 'closed' $p.ExecutablePath
          }
          $k = $p.ExecutablePath.ToLower()
          if (-not $t.exes.ContainsKey($k)) {      # новый .exe (обновление) — сразу правило
            Add-Exe $t $p.ExecutablePath
            if ($t.exes.ContainsKey($k)) { New-Rule $p.ExecutablePath; Log 'rule' $p.ExecutablePath }
          }
        }
      }
      $e = Get-Event -SourceIdentifier stunnel_guard -ErrorAction SilentlyContinue | Select-Object -First 1
    }
  } catch {
    Log 'error' $_.Exception.Message
    Start-Sleep -Seconds 2
  }
}
