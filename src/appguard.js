'use strict';
// «Только через S Tunnel»: выбранные приложения не работают без туннеля.
// Элемент списка — либо целое приложение (папка установки: блокируются ВСЕ .exe внутри,
// включая вспомогательные процессы, программы обновления и новые версии), либо один .exe.
// Два уровня защиты:
//  1. Брандмауэр: пока туннель НЕ включён, исходящий трафик этих .exe заблокирован
//     (группа STunnelApps). Правила постоянные — действуют, даже если S Tunnel закрыт.
//  2. Сторож процессов: запуск без туннеля -> процесс сразу закрывается + уведомление.
const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const path = require('path');
const firewall = require('./firewall');
const { scanDir, lc, isInside, pkgPathRegex } = require('./appscan');

const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const RESCAN_MS = 10 * 60 * 1000;

class AppGuard extends EventEmitter {
  /**
   * @param {object} o
   * @param {import('./tunnel').Tunnel} o.tunnel
   * @param {() => Array<{type:'dir'|'exe'|'pkg', path:string, name:string}>} o.getApps
   *   type 'pkg': path = имя семейства пакета MSIX (например Claude_pzs8sxrjxfjjc)
   * @param {(app:{name:string}) => void} o.onBlocked
   */
  constructor({ tunnel, getApps, onBlocked }) {
    super();
    this.tunnel = tunnel;
    this.getApps = getApps;
    this.onBlocked = onBlocked;
    this.watcher = null;
    this.watchKey = '';
    this.cache = null; // { key, at, exes, dirs, counts }
    this.syncing = Promise.resolve();
    tunnel.on('state', (st) => { this.sync(st.state).catch((e) => tunnel.log(`Защита приложений: ${e.message}`)); });
    setInterval(() => { this.cache = null; this.sync().catch(() => {}); }, RESCAN_MS);
  }

  /** Развернуть список в конкретные .exe (с кэшем). */
  async targets(force = false) {
    const apps = this.getApps();
    const key = JSON.stringify(apps.map((a) => [a.type, a.path]));
    if (!force && this.cache && this.cache.key === key && Date.now() - this.cache.at < RESCAN_MS) return this.cache;
    const exes = new Map();
    const dirs = [];
    const pkgRes = [];
    const counts = {};
    const pfns = apps.filter((a) => a.type === 'pkg').map((a) => a.path);
    const located = pfns.length ? await firewall.resolvePackages(pfns).catch(() => ({})) : {};
    for (const a of apps) {
      if (a.type === 'dir') {
        dirs.push(a.path);
        const { exes: found, truncated } = scanDir(a.path);
        counts[a.path] = { n: found.length, truncated };
        for (const e of found) exes.set(lc(e), e);
      } else if (a.type === 'pkg') {
        const rx = pkgPathRegex(a.path);
        if (rx) pkgRes.push(rx);
        let n = 0;
        const locs = [].concat(located[a.path] || []);
        for (const d of locs) {
          dirs.push(d);
          let found = scanDir(d, { allowPackaged: true }).exes;
          if (!found.length) found = await firewall.listExesInDir(d).catch(() => []);
          for (const e of found) exes.set(lc(e), e);
          n += found.length;
        }
        counts[a.path] = { n: locs.length ? n : null, truncated: false, missing: !locs.length };
      } else {
        exes.set(lc(a.path), a.path);
        counts[a.path] = { n: 1, truncated: false };
      }
    }
    this.cache = { key, at: Date.now(), exes: [...exes.values()], dirs, pkgRes, counts };
    return this.cache;
  }

  counts() { return this.cache ? this.cache.counts : {}; }

  findApp(exePath) {
    const l = lc(exePath);
    return this.getApps().find((a) => {
      if (a.type === 'dir') return isInside(l, lc(a.path));
      if (a.type === 'pkg') { const rx = pkgPathRegex(a.path); return !!rx && new RegExp(rx, 'i').test(l); }
      return l === lc(a.path);
    });
  }

  /** Привести правила и процессы в соответствие с состоянием туннеля (по очереди). */
  sync(state, { rescan = false } = {}) {
    const run = this.syncing.then(() => this._sync(state ?? this.tunnel.state, rescan));
    this.syncing = run.catch(() => {});
    return run;
  }

  async _sync(state, rescan) {
    const t = await this.targets(rescan);
    this.restartWatcher(t);
    const block = state !== 'on';
    await firewall.syncAppRules(t.exes, block);
    if (block) await this.closeRunning(t);
  }

  /** ПЕРЕД снятием kill switch: сначала блок приложений, потом обычный интернет. */
  async beforeRestore() {
    const t = await this.targets();
    await firewall.syncAppRules(t.exes, true);
    await this.closeRunning(t);
  }

  async closeRunning(t) {
    const closed = await firewall.stopAppProcesses(t.exes, t.dirs);
    const seen = new Set();
    for (const p of closed) {
      const app = this.findApp(p);
      if (app && !seen.has(app.path)) { seen.add(app.path); this.onBlocked(app); }
    }
  }

  /** Постоянный PowerShell-процесс: сообщает о запуске .exe из списка или из папок приложений. */
  restartWatcher(t) {
    const names = [...new Set(t.exes.map((e) => path.win32.basename(e).toLowerCase()))];
    const dirs = t.dirs.map(lc);
    const pkgRes = t.pkgRes || [];
    const key = JSON.stringify([names, dirs, pkgRes]);
    if (key === this.watchKey && this.watcher) return;
    this.stopWatcher();
    this.watchKey = key;
    if ((!names.length && !dirs.length && !pkgRes.length) || process.platform !== 'win32') return;

    // Если есть папки — смотрим все запуски (новая версия приложения может иметь новое имя .exe)
    const query = dirs.length
      ? 'SELECT * FROM Win32_ProcessStartTrace'
      : `SELECT * FROM Win32_ProcessStartTrace WHERE ${names.map((n) => `ProcessName='${n.replace(/'/g, "''")}'`).join(' OR ')}`;
    const script = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$names = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($n in @(${names.map(q).join(',')})) { [void]$names.Add($n) }
$dirs = @(${dirs.map(q).join(',')})
$pkgRes = @(${pkgRes.map(q).join(',')})
Register-CimIndicationEvent -Query ${q(query)} -SourceIdentifier stunnel_start | Out-Null
while ($true) {
  $e = Wait-Event -SourceIdentifier stunnel_start
  $ev = $e.SourceEventArgs.NewEvent
  Remove-Event -EventIdentifier $e.EventIdentifier
  $procId = $ev.ProcessID
  $isName = $names.Contains(([string]$ev.ProcessName).ToLower())
  if (-not $isName -and $dirs.Count -eq 0 -and $pkgRes.Count -eq 0) { continue }
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
  if (-not $p -or -not $p.ExecutablePath) { continue }
  $l = $p.ExecutablePath.ToLower()
  $hit = $isName
  if (-not $hit) { foreach ($d in $dirs) { if ($l.StartsWith($d + '\\')) { $hit = $true; break } } }
  if (-not $hit) { foreach ($rx in $pkgRes) { if ($l -match $rx) { $hit = $true; break } } }
  if ($hit) { [Console]::Out.WriteLine("$procId|$($p.ExecutablePath)"); [Console]::Out.Flush() }
}`;
    const enc = Buffer.from(script, 'utf16le').toString('base64');
    const w = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', enc], { windowsHide: true });
    this.watcher = w;
    let buf = '';
    w.stdout.setEncoding('utf8');
    w.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        const sep = line.indexOf('|');
        if (sep > 0) this.onProcessStart(parseInt(line.slice(0, sep), 10), line.slice(sep + 1));
      }
    });
    w.stderr.on('data', () => {});
    w.on('exit', () => {
      if (this.watcher !== w) return;
      this.watcher = null;
      this.watchKey = '';
      setTimeout(() => { if (!this.watcher && this.cache) this.restartWatcher(this.cache); }, 3000);
    });
  }

  stopWatcher() {
    const w = this.watcher;
    this.watcher = null;
    if (w) { try { w.kill(); } catch {} }
  }

  onProcessStart(pid, exePath) {
    const app = this.findApp(exePath);
    if (!app) return;
    // Новый .exe в папке приложения (обновилось) — добавим правило брандмауэра
    const known = this.cache && this.cache.exes.some((e) => lc(e) === lc(exePath));
    if (!known) this.sync(undefined, { rescan: true }).catch(() => {});
    if (this.tunnel.state === 'on') return;
    try { process.kill(pid); } catch {}
    this.onBlocked(app);
  }
}

module.exports = { AppGuard };
