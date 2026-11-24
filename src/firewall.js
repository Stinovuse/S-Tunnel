'use strict';
// Kill switch на Windows Firewall.
// Пока защита включена: исходящее по умолчанию = Block, все прочие разрешающие
// правила временно выключены, разрешено только:
//   * sing-box.exe -> IP:порт прокси (TCP)
//   * трафик с адреса TUN (т.е. уже внутри туннеля)
//   * DHCP (чтобы не терять аренду адреса)
//   * локальная сеть — только если включено в настройках
// Если ядро упадёт — интернет просто пропадает, реальный IP не уходит наружу.
// Состояние до включения сохраняется в C:\ProgramData\STunnel\killswitch.json,
// откуда его восстанавливает и приложение, и аварийный скрипт.

const { spawn } = require('child_process');
const { TUN_V4, TUN_V6 } = require('./core-config');

const GROUP = 'STunnel';
const LAN = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
  '224.0.0.0/4', 'fe80::/10', 'ff00::/8'];

const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const qList = (arr) => arr.map(q).join(',');

// Все операции с брандмауэром выполняются строго по очереди
let queue = Promise.resolve();
function runPs(script, timeoutMs = 120000) {
  const run = queue.then(() => runPsNow(script, timeoutMs));
  queue = run.catch(() => {});
  return run;
}

function runPsNow(script, timeoutMs) {
  return new Promise((resolve, reject) => {
    // Ошибку отдаём обычной строкой в UTF-8, а не в формате CLIXML
    const full = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
try {
${script}
} catch {
  [Console]::Out.WriteLine('STUNNEL_ERR:' + $_.Exception.Message)
  exit 1
}`;
    const enc = Buffer.from(full, 'utf16le').toString('base64');
    const p = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', enc],
      { windowsHide: true });
    let out = '', err = '';
    p.stdout.setEncoding('utf8');
    p.stderr.setEncoding('utf8');
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    const t = setTimeout(() => { p.kill(); reject(new Error('PowerShell: таймаут')); }, timeoutMs);
    p.on('error', (e) => { clearTimeout(t); reject(e); });
    p.on('close', (code) => {
      clearTimeout(t);
      const m = out.match(/STUNNEL_ERR:(.*)/);
      if (code === 0 && !m) { resolve(out.trim()); return; }
      reject(new Error(m ? m[1].trim() : cleanClixml(err || out) || `PowerShell код ${code}`));
    });
  });
}

/** Запасной вариант: достаём текст ошибок из CLIXML. */
function cleanClixml(text) {
  if (!/CLIXML/.test(text)) return text.trim();
  const parts = [...text.matchAll(/<S S="Error">([\s\S]*?)<\/S>/g)].map((x) => x[1]);
  return parts.join('').replace(/_x000D__x000A_/g, '\n').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&').split('\n')[0].trim();
}

const STATE_PS = `$dir = Join-Path $env:ProgramData 'STunnel'; $state = Join-Path $dir 'killswitch.json'`;

async function isActive() {
  const r = await runPs(`${STATE_PS}; if (Test-Path $state) { 'yes' } else { 'no' }`);
  return r === 'yes';
}

/**
 * @param {object} o
 * @param {string} o.corePath  полный путь к sing-box.exe
 * @param {string} o.proxyIp
 * @param {number} o.proxyPort
 * @param {boolean} o.allowLan
 * @param {boolean} o.udp       SOCKS5: разрешить ядру UDP к серверу прокси
 */
async function enable(o) {
  // UDP-ретранслятор SOCKS5 выдаёт порт динамически, поэтому порт не ограничиваем,
  // но адрес — строго IP прокси и только для sing-box.exe.
  const udpRule = o.udp
    ? `New-NetFirewallRule -DisplayName 'STunnel: ядро -> прокси (UDP)' -Group '${GROUP}' -Direction Outbound -Action Allow -Program ${q(o.corePath)} -Protocol UDP -RemoteAddress ${q(o.proxyIp)} | Out-Null`
    : '';
  const lanRule = o.allowLan
    ? `New-NetFirewallRule -DisplayName 'STunnel: локальная сеть' -Group '${GROUP}' -Direction Outbound -Action Allow -RemoteAddress ${qList(LAN)} | Out-Null`
    : '';
  const script = `
${STATE_PS}
$svc = Get-Service MpsSvc
if ($svc.Status -ne 'Running') { throw 'Служба «Брандмауэр Защитника Windows» не запущена (возможно, её отключил сторонний антивирус). Без неё защита от утечек невозможна.' }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# Писать в папку состояния могут только Администраторы и SYSTEM
& icacls.exe $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 2>&1 | Out-Null
if (-not (Test-Path $state)) {
  $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
    @{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultOutboundAction = [string]$_.DefaultOutboundAction } })
  $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Outbound -Action Allow -Enabled True |
    Where-Object { $_.Group -ne '${GROUP}' } | ForEach-Object { [string]$_.Name })
  # Сначала сохраняем состояние, потом меняем — чтобы его всегда можно было восстановить
  (@{ profiles = $profiles; rules = $rules } | ConvertTo-Json -Depth 4) | Set-Content -Encoding UTF8 -Path $state
  if ($rules.Count) { Disable-NetFirewallRule -Name $rules -ErrorAction SilentlyContinue }
}
Remove-NetFirewallRule -Group '${GROUP}' -ErrorAction SilentlyContinue
Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block
New-NetFirewallRule -DisplayName 'STunnel: ядро -> прокси' -Group '${GROUP}' -Direction Outbound -Action Allow -Program ${q(o.corePath)} -Protocol TCP -RemoteAddress ${q(o.proxyIp)} -RemotePort ${Number(o.proxyPort)} | Out-Null
New-NetFirewallRule -DisplayName 'STunnel: трафик внутри туннеля' -Group '${GROUP}' -Direction Outbound -Action Allow -LocalAddress ${q(TUN_V4)},${q(TUN_V6)} | Out-Null
New-NetFirewallRule -DisplayName 'STunnel: DHCP' -Group '${GROUP}' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
New-NetFirewallRule -DisplayName 'STunnel: DHCPv6' -Group '${GROUP}' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 546 -RemotePort 547 | Out-Null
${udpRule}
${lanRule}
'ok'`;
  return runPs(script);
}

async function disable() {
  const script = `
${STATE_PS}
Remove-NetFirewallRule -Group '${GROUP}' -ErrorAction SilentlyContinue
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
} else {
  Get-NetFirewallProfile -PolicyStore PersistentStore | Where-Object { $_.DefaultOutboundAction -eq 'Block' } |
    ForEach-Object { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction NotConfigured }
}
'ok'`;
  return runPs(script);
}

/**
 * Удаляет «зависшие» адреса туннеля, оставшиеся после принудительного завершения ядра
 * (иначе: "set ipv4 address: The object already exists"). Подсеть уникальна для
 * S Tunnel, поэтому чужие адаптеры это не затрагивает.
 */
async function cleanupTunAddresses() {
  const script = `
foreach ($ip in @(${q(TUN_V4)}, ${q(TUN_V6)})) {
  foreach ($store in @('ActiveStore', 'PersistentStore')) {
    Get-NetIPAddress -IPAddress $ip -PolicyStore $store -ErrorAction SilentlyContinue |
      Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  }
}
# Старая версия использовала 172.19.0.1 — чистим, только если адрес висит на нашем адаптере STunnel
Get-NetIPAddress -InterfaceAlias 'STunnel' -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
'ok'`;
  try { await runPs(script, 30000); } catch { /* не критично: ядро само сообщит об ошибке */ }
}

// ---- Соединения, открытые ДО подключения туннеля ----
// Новый маршрут не действует на уже установленные TCP-соединения: они привязаны к
// адресу физического адаптера и продолжают идти мимо туннеля с реальным IP.
const PRIVATE_RE = String.raw`^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|f[cd][0-9a-f]{2}:)`;

function directConnFilter(o) {
  const phys = o.phys.length ? qList(o.phys) : "''";
  return `
$phys = @(${phys})
$proxy = ${q(o.proxyIp)}
$conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
  ($phys -contains $_.LocalAddress) -and ($_.RemoteAddress -ne $proxy) -and
  ($_.RemoteAddress -notmatch '^(127\\.|::1$)') ${o.allowLan ? `-and ($_.RemoteAddress -notmatch '${PRIVATE_RE}')` : ''}
})`;
}

/**
 * Принудительно закрывает (DELETE_TCB) IPv4-соединения, идущие мимо туннеля.
 * Программы переподключатся — уже через туннель. Для IPv6 Windows такого API не даёт,
 * но новые IPv6-соединения мимо туннеля и так заблокированы брандмауэром.
 * @returns {Promise<number>} сколько соединений сброшено
 */
async function resetDirectConnections(o) {
  const script = `${directConnFilter(o)}
Add-Type -Namespace STunnel -Name Tcp -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPROW { public uint dwState; public uint dwLocalAddr; public uint dwLocalPort; public uint dwRemoteAddr; public uint dwRemotePort; }
[DllImport("iphlpapi.dll")]
public static extern uint SetTcpEntry(ref MIB_TCPROW row);
'@
function AddrU([string]$ip) { [BitConverter]::ToUInt32(([Net.IPAddress]::Parse($ip)).GetAddressBytes(), 0) }
function PortU([int]$p) { [uint32]((($p -shr 8) -band 0xFF) -bor (($p -band 0xFF) -shl 8)) }
$n = 0
foreach ($c in $conns) {
  if ($c.LocalAddress -notmatch '^\\d+\\.\\d+\\.\\d+\\.\\d+$') { continue }
  $row = New-Object STunnel.Tcp+MIB_TCPROW
  $row.dwState = 12
  $row.dwLocalAddr = AddrU $c.LocalAddress; $row.dwLocalPort = PortU $c.LocalPort
  $row.dwRemoteAddr = AddrU $c.RemoteAddress; $row.dwRemotePort = PortU $c.RemotePort
  if ([STunnel.Tcp]::SetTcpEntry([ref]$row) -eq 0) { $n++ }
}
"$n"`;
  return parseInt(await runPs(script, 60000), 10) || 0;
}

/** Список соединений, всё ещё идущих мимо туннеля: [{proc, remote}] */
async function listDirectConnections(o) {
  const script = `${directConnFilter(o)}
$out = foreach ($c in $conns) {
  $name = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  [pscustomobject]@{ proc = [string]$name; remote = "$($c.RemoteAddress):$($c.RemotePort)" }
}
ConvertTo-Json -Compress -InputObject @($out)`;
  const r = await runPs(script, 60000);
  try { const j = JSON.parse(r || '[]'); return Array.isArray(j) ? j : [j]; } catch { return []; }
}

// ---- «Только через S Tunnel» ----
const APPS_GROUP = 'STunnelApps';

/**
 * Приводит Block-правила группы STunnelApps к списку exes (добавляет недостающие,
 * удаляет лишние) и включает/выключает всю группу одной командой.
 * @param {string[]} exes
 * @param {boolean} enabled  true = блокировать (туннель не включён)
 */
async function syncAppRules(exes, enabled) {
  const want = exes.length ? exes.map((p) => q(p)).join(',') : '';
  return runPs(`$want = @(${want})
$wantL = @{}; foreach ($w in $want) { $wantL[$w.ToLower()] = $w }
$have = @{}
foreach ($f in @(Get-NetFirewallRule -Group '${APPS_GROUP}' -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
  $prog = [string]$f.Program
  if (-not $prog -or -not $wantL.ContainsKey($prog.ToLower()) -or $have.ContainsKey($prog.ToLower())) {
    Remove-NetFirewallRule -Name $f.InstanceID -ErrorAction SilentlyContinue
  } else { $have[$prog.ToLower()] = $true }
}
$en = ${enabled ? "'True'" : "'False'"}
foreach ($k in $wantL.Keys) {
  if (-not $have.ContainsKey($k)) {
    $p = $wantL[$k]
    New-NetFirewallRule -DisplayName ('S Tunnel: без туннеля запрещено — ' + (Split-Path $p -Leaf)) -Group '${APPS_GROUP}' -Direction Outbound -Action Block -Program $p -Enabled $en | Out-Null
  }
}
if ($want.Count) {
  if ($en -eq 'True') { Enable-NetFirewallRule -Group '${APPS_GROUP}' -ErrorAction SilentlyContinue }
  else { Disable-NetFirewallRule -Group '${APPS_GROUP}' -ErrorAction SilentlyContinue }
}
'ok'`, 300000);
}

/** Закрывает процессы из списка exes и из папок dirs; возвращает пути закрытых. */
async function stopAppProcesses(exes, dirs) {
  if (!exes.length && !dirs.length) return [];
  const list = (a) => (a.length ? a.map((x) => q(x.toLowerCase())).join(',') : '');
  const r = await runPs(`$exes = @(${list(exes)}); $dirs = @(${list(dirs)})
$hit = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
  $p = $_.ExecutablePath; if (-not $p) { return $false }; $l = $p.ToLower()
  if ($exes -contains $l) { return $true }
  foreach ($d in $dirs) { if ($l.StartsWith($d + '\\')) { return $true } }
  $false })
foreach ($p in $hit) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
ConvertTo-Json -Compress -InputObject @($hit | ForEach-Object { [string]$_.ExecutablePath } | Select-Object -Unique)`, 60000);
  try { const j = JSON.parse(r || '[]'); return Array.isArray(j) ? j : [j]; } catch { return []; }
}

/** Установленные приложения: ярлыки меню «Пуск» -> [{name, exe}] */
async function listStartMenuApps() {
  const r = await runPs(`$dirs = @([Environment]::GetFolderPath('CommonStartMenu'), [Environment]::GetFolderPath('StartMenu'))
$sh = New-Object -ComObject WScript.Shell
$out = foreach ($l in @(Get-ChildItem -Path $dirs -Recurse -Filter *.lnk -ErrorAction SilentlyContinue)) {
  $t = ''
  try { $t = $sh.CreateShortcut($l.FullName).TargetPath } catch {}
  if ($t -and $t.ToLower().EndsWith('.exe') -and (Test-Path -LiteralPath $t)) {
    [pscustomobject]@{ name = $l.BaseName; exe = $t }
  }
}
ConvertTo-Json -Compress -InputObject @($out)`, 120000);
  try { const j = JSON.parse(r || '[]'); return Array.isArray(j) ? j : [j]; } catch { return []; }
}

async function isAdmin() {
  try {
    const r = await runPs(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`, 20000);
    return r.toLowerCase() === 'true';
  } catch { return false; }
}

module.exports = { syncAppRules, stopAppProcesses, listStartMenuApps, APPS_GROUP, enable, disable, resetDirectConnections, listDirectConnections, isActive, isAdmin, cleanupTunAddresses, cleanClixml, runPs, GROUP };
