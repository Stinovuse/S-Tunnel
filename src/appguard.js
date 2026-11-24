'use strict';
// «Только через S Tunnel»: выбранные программы не работают без туннеля.
// Два уровня защиты:
//  1. Брандмауэр: пока туннель НЕ включён, исходящий трафик этих программ заблокирован
//     правилом Block (группа STunnelApps). Правило постоянное — действует, даже если
//     S Tunnel закрыт или не запущен.
//  2. Сторож процессов: при запуске такой программы без туннеля S Tunnel сразу её закрывает
//     и показывает уведомление. При отключении туннеля уже запущенные — тоже закрываются.
const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const path = require('path');
const firewall = require('./firewall');

const q = (s) => `'${String(s).replace(/'/g, "''")}'`;

// Нельзя добавлять: системные программы и всё, на чём работает сам S Tunnel
const FORBIDDEN_NAMES = new Set(['powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'explorer.exe',
  'svchost.exe', 'sing-box.exe', 's tunnel.exe', 'icacls.exe', 'schtasks.exe', 'netsh.exe']);

function validateAppPath(p) {
  const norm = path.win32.normalize(p);
  const lower = norm.toLowerCase();
  if (!lower.endsWith('.exe')) return 'Выберите .exe-файл программы';
  if (FORBIDDEN_NAMES.has(path.win32.basename(lower))) return 'Эту программу добавить нельзя: на ней работает Windows или сам S Tunnel';
  const winDir = (process.env.SystemRoot || 'C:\\Windows').toLowerCase();
  if (lower.startsWith(winDir + '\\')) return 'Системные программы Windows добавить нельзя';
  if (lower.includes('\\windowsapps\\')) return 'Приложения из Microsoft Store пока не поддерживаются';
  return '';
}

class AppGuard extends EventEmitter {
  /**
   * @param {object} o
   * @param {import('./tunnel').Tunnel} o.tunnel
   * @param {() => Array<{path:string,name:string}>} o.getApps
   * @param {(app:{path:string,name:string}) => void} o.onBlocked
   */
  constructor({ tunnel, getApps, onBlocked }) {
    super();
    this.tunnel = tunnel;
    this.getApps = getApps;
    this.onBlocked = onBlocked;
    this.watcher = null;
    this.watchKey = '';
    tunnel.on('state', (st) => { this.sync(st.state).catch((e) => tunnel.log(`Защита программ: ${e.message}`)); });
  }

  paths() { return this.getApps().map((a) => a.path); }
  findApp(p) {
    const l = String(p || '').toLowerCase();
    return this.getApps().find((a) => a.path.toLowerCase() === l);
  }

  /** Привести правила и процессы в соответствие с состоянием туннеля. */
  async sync(state = this.tunnel.state) {
    this.restartWatcher();
    if (state === 'on') {
      await firewall.setAppBlocks([]);
    } else {
      await firewall.setAppBlocks(this.paths());
      await this.closeRunning();
    }
  }

  /** Вызывается ПЕРЕД снятием kill switch: сначала блок программ, потом обычный интернет. */
  async beforeRestore() {
    await firewall.setAppBlocks(this.paths());
    await this.closeRunning();
  }

  async closeRunning() {
    const closed = await firewall.stopProcessesByPath(this.paths());
    for (const p of closed) {
      const app = this.findApp(p);
      if (app) this.onBlocked(app);
    }
  }

  /** Постоянный PowerShell-процесс, сообщающий о запуске нужных .exe (событие WMI). */
  restartWatcher() {
    const apps = this.getApps();
    const names = [...new Set(apps.map((a) => path.win32.basename(a.path).toLowerCase()))];
    const key = names.join('|');
    if (key === this.watchKey && this.watcher) return;
    this.stopWatcher();
    this.watchKey = key;
    if (!names.length || process.platform !== 'win32') return;

    const where = names.map((n) => `ProcessName='${n.replace(/'/g, "''")}'`).join(' OR ');
    const script = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Register-CimIndicationEvent -Query ${q(`SELECT * FROM Win32_ProcessStartTrace WHERE ${where}`)} -SourceIdentifier stunnel_start | Out-Null
while ($true) {
  $e = Wait-Event -SourceIdentifier stunnel_start
  $procId = $e.SourceEventArgs.NewEvent.ProcessID
  Remove-Event -EventIdentifier $e.EventIdentifier
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
  if ($p -and $p.ExecutablePath) { [Console]::Out.WriteLine("$procId|$($p.ExecutablePath)"); [Console]::Out.Flush() }
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
      setTimeout(() => this.restartWatcher(), 3000); // сторож упал — поднимаем снова
    });
  }

  stopWatcher() {
    const w = this.watcher;
    this.watcher = null;
    if (w) { try { w.kill(); } catch {} }
  }

  onProcessStart(pid, exePath) {
    if (this.tunnel.state === 'on') return;
    const app = this.findApp(exePath);
    if (!app) return;
    try { process.kill(pid); } catch {}
    this.onBlocked(app);
  }
}

module.exports = { AppGuard, validateAppPath };
