'use strict';
// «Только через S Tunnel» — клиентская часть.
// Сама защита живёт в фоновой задаче Windows «S Tunnel Guard» (scripts/guard.ps1, SYSTEM):
// она работает и при закрытом S Tunnel. Здесь мы только:
//  * передаём ей список приложений (C:\ProgramData\STunnel\apps.json — писать могут только админы),
//  * устанавливаем/обновляем и запускаем задачу,
//  * показываем уведомления о закрытых приложениях (по журналу сторожа),
//  * считаем, сколько .exe в каждом приложении (для интерфейса).
const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const firewall = require('./firewall');
const { scanDir, lc, isInside, pkgPathRegex } = require('./appscan');

const RESCAN_MS = 10 * 60 * 1000;
const STATE_DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'STunnel');
const APPS_FILE = path.join(STATE_DIR, 'apps.json');
const LOG_FILE = path.join(STATE_DIR, 'guard-events.log');
const GUARD_COPY = path.join(STATE_DIR, 'guard.ps1');
const TASK = 'S Tunnel Guard';
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;

class AppGuard extends EventEmitter {
  /**
   * @param {object} o
   * @param {() => Array<{type:'dir'|'exe'|'pkg', path:string, name:string}>} o.getApps
   *   type 'pkg': path = имя семейства пакета MSIX (например Claude_pzs8sxrjxfjjc)
   * @param {(app:{name:string,path:string}) => void} o.onBlocked
   * @param {string} o.guardScript  путь к scripts/guard.ps1 в установленном приложении
   * @param {(line:string) => void} o.log
   */
  constructor({ getApps, onBlocked, guardScript, log }) {
    super();
    this.getApps = getApps;
    this.onBlocked = onBlocked;
    this.guardScript = guardScript;
    this.log = log;
    this.cache = null;
    this.logPos = null;
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

  /** Установить/обновить фоновую задачу и передать ей текущий список. */
  async start() {
    if (process.platform !== 'win32') return;
    await this.publish();
    await this.installTask();
    this.watchLog();
  }

  /** Записать список приложений для сторожа (он перечитает файл сам в течение 2 секунд). */
  async publish() {
    if (process.platform !== 'win32') return;
    fs.mkdirSync(STATE_DIR, { recursive: true });
    const apps = this.getApps().map(({ type, path: p, name }) => ({ type, path: p, name }));
    fs.writeFileSync(APPS_FILE, JSON.stringify({ apps }, null, 2));
    this.cache = null;
    await this.targets(true).catch(() => {});
  }

  async installTask() {
    const src = fs.readFileSync(this.guardScript);
    const same = fs.existsSync(GUARD_COPY) &&
      crypto.createHash('sha256').update(fs.readFileSync(GUARD_COPY)).digest('hex') === crypto.createHash('sha256').update(src).digest('hex');
    if (!same) fs.writeFileSync(GUARD_COPY, src);
    await firewall.runPs(`
& icacls.exe ${q(STATE_DIR)} /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 2>&1 | Out-Null
$task = Get-ScheduledTask -TaskName ${q(TASK)} -ErrorAction SilentlyContinue
if (-not $task -or ${same ? '$false' : '$true'}) {
  if ($task) { Stop-ScheduledTask -TaskName ${q(TASK)} -ErrorAction SilentlyContinue }
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + ${q(GUARD_COPY)} + '"')
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName ${q(TASK)} -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}
if ((Get-ScheduledTask -TaskName ${q(TASK)}).State -ne 'Running') { Start-ScheduledTask -TaskName ${q(TASK)} }
'ok'`, 120000);
    this.log(same ? 'Фоновая защита приложений работает' : 'Фоновая защита приложений установлена/обновлена');
  }

  /** Уведомления: читаем новые строки журнала сторожа. */
  watchLog() {
    try { this.logPos = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE).size : 0; } catch { this.logPos = 0; }
    const seen = new Map();
    fs.watchFile(LOG_FILE, { interval: 1000 }, (cur) => {
      if (cur.size < this.logPos) this.logPos = 0; // файл пересоздан
      if (cur.size === this.logPos) return;
      let chunk = '';
      try {
        const fd = fs.openSync(LOG_FILE, 'r');
        const buf = Buffer.alloc(cur.size - this.logPos);
        fs.readSync(fd, buf, 0, buf.length, this.logPos);
        fs.closeSync(fd);
        chunk = buf.toString('utf8');
      } catch { return; }
      this.logPos = cur.size;
      for (const line of chunk.split(/\r?\n/)) {
        const [, kind, text] = line.replace(/^\uFEFF/, '').split('\t');
        if (kind !== 'closed' || !text) continue;
        const app = this.findApp(text) || { name: path.win32.basename(text, '.exe'), path: text };
        const now = Date.now();
        if (now - (seen.get(app.path) || 0) < 5000) continue;
        seen.set(app.path, now);
        this.onBlocked(app);
      }
    });
  }

  /** Перед возвратом обычного интернета: закрыть выбранные приложения (сторож тоже это делает). */
  async beforeRestore() {
    const t = await this.targets();
    await firewall.stopAppProcesses(t.exes, t.dirs);
  }
}

module.exports = { AppGuard, STATE_DIR, TASK };
