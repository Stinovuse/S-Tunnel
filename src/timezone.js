'use strict';
// Часовой пояс Windows = часовой пояс страны/города прокси.
// Само время не меняется (оно синхронизировано и точное) — меняется только пояс,
// как если бы компьютер находился там же, где прокси. При отключении пояс возвращается.
// Исходный пояс хранится в C:\ProgramData\STunnel\timezone.json (только для администраторов),
// поэтому его восстановит и S Tunnel после сбоя, и аварийный скрипт.
const { runPs } = require('./firewall');

const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const IANA_RE = /^[A-Za-z_]+(\/[A-Za-z0-9_+\-]+){0,2}$|^UTC$/;

// Запасная таблица IANA -> Windows (основной способ — ICU, встроенный в Windows 10 1903+)
const FALLBACK = {
  'Europe/Moscow': 'Russian Standard Time', 'Europe/London': 'GMT Standard Time', 'Europe/Dublin': 'GMT Standard Time',
  'Europe/Berlin': 'W. Europe Standard Time', 'Europe/Amsterdam': 'W. Europe Standard Time', 'Europe/Vienna': 'W. Europe Standard Time',
  'Europe/Zurich': 'W. Europe Standard Time', 'Europe/Stockholm': 'W. Europe Standard Time', 'Europe/Rome': 'W. Europe Standard Time',
  'Europe/Paris': 'Romance Standard Time', 'Europe/Brussels': 'Romance Standard Time', 'Europe/Madrid': 'Romance Standard Time',
  'Europe/Warsaw': 'Central European Standard Time', 'Europe/Prague': 'Central Europe Standard Time', 'Europe/Budapest': 'Central Europe Standard Time',
  'Europe/Kyiv': 'FLE Standard Time', 'Europe/Kiev': 'FLE Standard Time', 'Europe/Helsinki': 'FLE Standard Time', 'Europe/Riga': 'FLE Standard Time',
  'Europe/Vilnius': 'FLE Standard Time', 'Europe/Tallinn': 'FLE Standard Time', 'Europe/Istanbul': 'Turkey Standard Time',
  'Europe/Minsk': 'Belarus Standard Time', 'Asia/Almaty': 'Central Asia Standard Time', 'Asia/Tbilisi': 'Georgian Standard Time',
  'Asia/Yerevan': 'Caucasus Standard Time', 'Asia/Dubai': 'Arabian Standard Time', 'Asia/Kolkata': 'India Standard Time',
  'Asia/Singapore': 'Singapore Standard Time', 'Asia/Kuala_Lumpur': 'Singapore Standard Time', 'Asia/Shanghai': 'China Standard Time',
  'Asia/Hong_Kong': 'China Standard Time', 'Asia/Taipei': 'Taipei Standard Time', 'Asia/Tokyo': 'Tokyo Standard Time',
  'Asia/Seoul': 'Korea Standard Time', 'Asia/Bangkok': 'SE Asia Standard Time', 'Asia/Jakarta': 'SE Asia Standard Time',
  'Australia/Sydney': 'AUS Eastern Standard Time', 'America/New_York': 'Eastern Standard Time', 'America/Toronto': 'Eastern Standard Time',
  'America/Chicago': 'Central Standard Time', 'America/Denver': 'Mountain Standard Time', 'America/Phoenix': 'US Mountain Standard Time',
  'America/Los_Angeles': 'Pacific Standard Time', 'America/Sao_Paulo': 'E. South America Standard Time', 'UTC': 'UTC',
};

async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(7000), headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/** Часовой пояс по внешнему IP. Запрос идёт ЧЕРЕЗ туннель, т.е. определяется по IP прокси. */
async function detectProxyTimezone() {
  const sources = [
    async () => { const j = await getJson('https://ipwho.is/'); if (j.success === false) throw new Error(j.message); return { iana: j.timezone?.id, ip: j.ip, place: [j.city, j.country].filter(Boolean).join(', ') }; },
    async () => { const j = await getJson('https://ipapi.co/json/'); return { iana: j.timezone, ip: j.ip, place: [j.city, j.country_name].filter(Boolean).join(', ') }; },
    async () => { const j = await getJson('https://ipinfo.io/json'); return { iana: j.timezone, ip: j.ip, place: [j.city, j.country].filter(Boolean).join(', ') }; },
  ];
  let last;
  for (const s of sources) {
    try {
      const r = await s();
      if (r.iana && IANA_RE.test(r.iana)) return r;
      last = new Error('сервис не вернул часовой пояс');
    } catch (e) { last = e; }
  }
  throw new Error(`не удалось определить часовой пояс прокси (${last?.message})`);
}

/** IANA (Asia/Singapore) -> Windows ID (Singapore Standard Time) через ICU Windows, иначе таблица. */
async function ianaToWindows(iana) {
  if (!IANA_RE.test(iana)) throw new Error('некорректный часовой пояс');
  const r = await runPs(`
$win = ''
try {
  Add-Type -Namespace STunnel -Name Icu -MemberDefinition @'
[DllImport("icu.dll", CharSet = CharSet.Unicode)]
public static extern int ucal_getWindowsTimeZoneID(string id, int len, System.Text.StringBuilder winid, int cap, ref int status);
'@
  $sb = New-Object System.Text.StringBuilder 128
  $st = 0
  $n = [STunnel.Icu]::ucal_getWindowsTimeZoneID(${q(iana)}, ${iana.length}, $sb, 128, [ref]$st)
  if ($st -le 0 -and $n -gt 0) { $win = $sb.ToString().Substring(0, $n) }
} catch {}
if (-not $win) { $win = ${q(FALLBACK[iana] || '')} }
if ($win -and -not (Get-TimeZone -ListAvailable | Where-Object { $_.Id -eq $win })) { $win = '' }
$win`, 60000);
  if (!r) throw new Error(`нет соответствия в Windows для ${iana}`);
  return r;
}

const STATE = `$dir = Join-Path $env:ProgramData 'STunnel'; $state = Join-Path $dir 'timezone.json'
$tzKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\tzautoupdate'`;

/** Поставить пояс. Исходный пояс и автоопределение пояса сохраняются один раз. */
async function apply(winId) {
  return runPs(`${STATE}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
if (-not (Test-Path $state)) {
  $auto = $null
  try { $auto = (Get-ItemProperty -Path $tzKey -Name Start -ErrorAction Stop).Start } catch {}
  (@{ original = (Get-TimeZone).Id; tzauto = $auto } | ConvertTo-Json) | Set-Content -Encoding UTF8 -Path $state
}
# Автоопределение пояса Windows вернуло бы его обратно — выключаем на время туннеля
try { Set-ItemProperty -Path $tzKey -Name Start -Value 4 -ErrorAction Stop; Stop-Service tzautoupdate -Force -ErrorAction SilentlyContinue } catch {}
Set-TimeZone -Id ${q(winId)}
'ok'`, 60000);
}

/** Вернуть исходный пояс (если менялся). */
async function restore() {
  return runPs(`${STATE}
if (Test-Path $state) {
  $s = $null
  try { $s = Get-Content -Raw -Path $state | ConvertFrom-Json } catch {}
  if ($s -and $s.original -and (Get-TimeZone -ListAvailable | Where-Object { $_.Id -eq $s.original })) { Set-TimeZone -Id $s.original }
  if ($s -and $null -ne $s.tzauto -and @(2,3,4) -contains [int]$s.tzauto) {
    try { Set-ItemProperty -Path $tzKey -Name Start -Value ([int]$s.tzauto) -ErrorAction Stop } catch {}
  }
  Remove-Item -Force -Path $state -ErrorAction SilentlyContinue
}
'ok'`, 60000);
}

async function currentWindowsZone() {
  return runPs('(Get-TimeZone).Id', 20000);
}

module.exports = { detectProxyTimezone, ianaToWindows, apply, restore, currentWindowsZone, FALLBACK };
