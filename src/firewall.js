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

function runPs(script, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const full = `$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';\n${script}`;
    const enc = Buffer.from(full, 'utf16le').toString('base64');
    const p = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', enc],
      { windowsHide: true });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    const t = setTimeout(() => { p.kill(); reject(new Error('PowerShell: таймаут')); }, timeoutMs);
    p.on('error', (e) => { clearTimeout(t); reject(e); });
    p.on('close', (code) => {
      clearTimeout(t);
      if (code === 0) resolve(out.trim());
      else reject(new Error((err || out || `PowerShell код ${code}`).trim()));
    });
  });
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
 */
async function enable(o) {
  const lanRule = o.allowLan
    ? `New-NetFirewallRule -DisplayName 'STunnel: локальная сеть' -Group '${GROUP}' -Direction Outbound -Action Allow -RemoteAddress ${qList(LAN)} | Out-Null`
    : '';
  const script = `
${STATE_PS}
$svc = Get-Service MpsSvc
if ($svc.Status -ne 'Running') { throw 'Служба «Брандмауэр Защитника Windows» не запущена (возможно, её отключил сторонний антивирус). Без неё защита от утечек невозможна.' }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
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
${lanRule}
'ok'`;
  return runPs(script);
}

async function disable() {
  const script = `
${STATE_PS}
Remove-NetFirewallRule -Group '${GROUP}' -ErrorAction SilentlyContinue
if (Test-Path $state) {
  $s = Get-Content -Raw -Path $state | ConvertFrom-Json
  foreach ($p in @($s.profiles)) {
    if ($p -and $p.Name) {
      Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction SilentlyContinue
    }
  }
  $names = @(@($s.rules) | Where-Object { $_ }); if ($names.Count) { Enable-NetFirewallRule -Name $names -ErrorAction SilentlyContinue }
  Remove-Item -Force -Path $state
} else {
  Get-NetFirewallProfile -PolicyStore PersistentStore | Where-Object { $_.DefaultOutboundAction -eq 'Block' } |
    ForEach-Object { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction NotConfigured }
}
'ok'`;
  return runPs(script);
}

async function isAdmin() {
  try {
    const r = await runPs(`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`, 20000);
    return r.toLowerCase() === 'true';
  } catch { return false; }
}

module.exports = { enable, disable, isActive, isAdmin, runPs, GROUP };
