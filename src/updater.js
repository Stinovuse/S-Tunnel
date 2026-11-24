'use strict';
// Обновления из GitHub Releases (electron-updater).
// Приватность: проверяем и скачиваем ТОЛЬКО когда туннель включён — GitHub видит IP прокси,
// а не ваш реальный. При установке kill switch остаётся включённым, а новая версия
// после запуска сама подключается снова — окна с реальным IP не возникает.
const { app } = require('electron');
const path = require('path');
const fs = require('fs');

let autoUpdater = null;
try { ({ autoUpdater } = require('electron-updater')); } catch { /* dev без зависимостей */ }

const CHECK_EVERY_MS = 6 * 60 * 60 * 1000;

class Updater {
  constructor({ tunnel, send, log }) {
    this.tunnel = tunnel;
    this.send = send;
    this.log = log;
    this.status = { state: 'idle', version: app.getVersion(), available: '', percent: 0, error: '' };
    this.flagPath = path.join(app.getPath('userData'), 'reconnect-after-update');
    if (!autoUpdater) return;

    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.on('checking-for-update', () => this.set({ state: 'checking', error: '' }));
    autoUpdater.on('update-available', (i) => { this.set({ state: 'available', available: i.version }); this.log(`Доступна новая версия ${i.version}`); });
    autoUpdater.on('update-not-available', () => this.set({ state: 'latest' }));
    autoUpdater.on('download-progress', (p) => this.set({ state: 'downloading', percent: Math.round(p.percent) }));
    autoUpdater.on('update-downloaded', (i) => { this.set({ state: 'ready', available: i.version }); this.log(`Версия ${i.version} скачана — можно установить`); });
    autoUpdater.on('error', (e) => this.set({ state: 'error', error: shortErr(e) }));
  }

  set(patch) { Object.assign(this.status, patch); this.send('update', this.status); }

  canUseNetwork() {
    if (!autoUpdater || !app.isPackaged) { this.set({ state: 'error', error: 'Обновления работают только в установленной версии' }); return false; }
    if (this.tunnel.state !== 'on') { this.set({ state: 'error', error: 'Подключитесь: обновления скачиваются только через прокси' }); return false; }
    return true;
  }

  async check({ silent = false } = {}) {
    if (silent && (this.tunnel.state !== 'on' || !autoUpdater || !app.isPackaged)) return;
    if (!silent && !this.canUseNetwork()) return;
    if (['checking', 'downloading', 'ready'].includes(this.status.state)) return;
    try { await autoUpdater.checkForUpdates(); } catch (e) { this.set({ state: 'error', error: shortErr(e) }); }
  }

  async download() {
    if (!this.canUseNetwork()) return;
    try { await autoUpdater.downloadUpdate(); } catch (e) { this.set({ state: 'error', error: shortErr(e) }); }
  }

  /** Установка: ядро стоп, kill switch НЕ снимаем, после перезапуска — автоподключение. */
  install(onBeforeQuit) {
    if (this.status.state !== 'ready') return;
    try { fs.writeFileSync(this.flagPath, '1'); } catch {}
    onBeforeQuit();
    setImmediate(() => autoUpdater.quitAndInstall(true, true));
  }

  /** Вызывается при запуске: true, если надо переподключиться после обновления. */
  consumeReconnectFlag() {
    if (!fs.existsSync(this.flagPath)) return false;
    try { fs.unlinkSync(this.flagPath); } catch {}
    return true;
  }

  start() {
    setTimeout(() => this.check({ silent: true }), 30 * 1000);
    setInterval(() => this.check({ silent: true }), CHECK_EVERY_MS);
    // сразу после подключения тоже проверим (тихо)
    this.tunnel.on('state', (st) => { if (st.state === 'on' && this.status.state === 'idle') this.check({ silent: true }); });
  }
}

function shortErr(e) {
  const m = String(e?.message || e);
  if (/404|Not Found/i.test(m)) return 'Релизы не найдены (репозиторий приватный или релизов ещё нет)';
  if (/net::|ENOTFOUND|ETIMEDOUT|ECONNRE/i.test(m)) return 'Нет связи с GitHub';
  return m.split('\n')[0].slice(0, 200);
}

module.exports = { Updater };
