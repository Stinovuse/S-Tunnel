'use strict';
const { app, BrowserWindow, Tray, Menu, ipcMain, safeStorage, nativeImage, dialog, shell, Notification } = require('electron');
const path = require('path');
const fs = require('fs');
const { Tunnel } = require('./src/tunnel');
const { PROTOCOLS } = require('./src/core-config');
const firewall = require('./src/firewall');
const tz = require('./src/timezone');
const { Updater } = require('./src/updater');
const { AppGuard } = require('./src/appguard');
const { validateAppPath, validateAppDir, validatePfn, lc } = require('./src/appscan');

if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }

const userDir = app.getPath('userData');
const settingsPath = path.join(userDir, 'settings.json');
const corePath = app.isPackaged
  ? path.join(process.resourcesPath, 'bin', 'sing-box.exe')
  : path.join(__dirname, 'bin', 'sing-box.exe');
const emergencyScript = app.isPackaged
  ? path.join(process.resourcesPath, 'scripts', 'emergency-restore.cmd')
  : path.join(__dirname, 'scripts', 'emergency-restore.cmd');

const DEFAULTS = {
  host: '', port: 8080, protocol: 'http', username: '', passwordEnc: '',
  allowLan: false, dnsServer: '1.1.1.1', autoConnect: false, cachedIp: '', guardedApps: [], syncTimezone: true,
};

function loadSettings() {
  let s;
  try { s = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(settingsPath, 'utf8')) }; }
  catch { return { ...DEFAULTS }; }
  // миграция со старой версии, где был флажок tls
  if ('tls' in s) { if (!PROTOCOLS.includes(s.protocol) || s.protocol === 'http') s.protocol = s.tls ? 'https' : 'http'; delete s.tls; }
  if (!PROTOCOLS.includes(s.protocol)) s.protocol = 'http';
  // элементы: {type:'dir'|'exe', path, name}; старые записи (без type) — это .exe
  s.guardedApps = (Array.isArray(s.guardedApps) ? s.guardedApps : [])
    .filter((a) => a && typeof a.path === 'string')
    .map((a) => ({ type: ['dir', 'pkg'].includes(a.type) ? a.type : 'exe', path: a.path, name: String(a.name || path.basename(a.path)) }))
    .filter((a) => !validateEntry(a));
  return s;
}
function validateEntry(e) {
  if (e.type === 'dir') return validateAppDir(e.path);
  if (e.type === 'pkg') return validatePfn(e.path);
  return validateAppPath(e.path);
}
function saveSettings(s) {
  fs.mkdirSync(userDir, { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(s, null, 2));
}
function decryptPassword(s) {
  if (!s.passwordEnc) return '';
  try { return safeStorage.decryptString(Buffer.from(s.passwordEnc, 'base64')); } catch { return ''; }
}
function publicSettings(s) {
  const { passwordEnc, ...rest } = s;
  return { ...rest, hasPassword: !!passwordEnc };
}

let win = null;
let tray = null;
let quitting = false;
const logBuf = [];
const tunnel = new Tunnel({ corePath, workDir: path.join(userDir, 'core') });

const send = (ch, data) => { if (win && !win.isDestroyed()) win.webContents.send(ch, data); };
let updating = false;
const updater = new Updater({
  tunnel,
  send: (ch, d) => { send(ch, d); if (d.state === 'ready') updateTray(); },
  log: (l) => tunnel.log(l),
});

// ---- «Только через S Tunnel» ----
const lastNotified = new Map();
const guard = new AppGuard({
  guardScript: app.isPackaged
    ? path.join(process.resourcesPath, 'scripts', 'guard.ps1')
    : path.join(__dirname, 'scripts', 'guard.ps1'),
  log: (l) => tunnel.log(l),
  getApps: () => loadSettings().guardedApps,
  onBlocked: (a) => {
    tunnel.log(`Закрыто приложение ${a.name}: туннель не подключён`);
    const now = Date.now();
    if (now - (lastNotified.get(a.path) || 0) < 5000) return;
    lastNotified.set(a.path, now);
    if (Notification.isSupported()) {
      const n = new Notification({
        title: `${a.name} закрыт`,
        body: 'Это приложение работает только через S Tunnel. Нажмите, чтобы подключиться.',
        icon: path.join(__dirname, 'assets', 'icon.png'),
      });
      n.on('click', () => { showWindow(); doConnect(); });
      n.show();
    }
  },
});
tunnel.beforeRestore = () => guard.beforeRestore();

// ---- Часовой пояс прокси ----
let tzInfo = null; // { iana, win, place, ip }
async function applyProxyTimezone() {
  if (!loadSettings().syncTimezone) return;
  tunnel.log('Определяю часовой пояс прокси…');
  const info = await tz.detectProxyTimezone();
  const win = await tz.ianaToWindows(info.iana);
  await tz.apply(win);
  tzInfo = { ...info, win };
  tunnel.log(`Часовой пояс Windows: ${info.iana} (${win})${info.place ? `, как у прокси — ${info.place}` : ''}`);
}
tunnel.afterConnect = () => applyProxyTimezone().catch((e) => { tzInfo = { error: e.message }; throw e; });
tunnel.afterRestore = async () => { await tz.restore(); if (tzInfo && !tzInfo.error) tunnel.log('Часовой пояс Windows возвращён'); tzInfo = null; };
tunnel.extraChecks = async () => {
  if (!loadSettings().syncTimezone) return [];
  if (!tzInfo || tzInfo.error) {
    return [{ name: 'Часовой пояс', ok: false, detail: `не совпадает с прокси: ${tzInfo?.error || 'не определён'}` }];
  }
  const cur = await tz.currentWindowsZone().catch(() => '');
  const ok = cur === tzInfo.win;
  return [{ name: 'Часовой пояс', ok, detail: ok ? `${tzInfo.iana}${tzInfo.place ? ` — ${tzInfo.place}` : ''}, как у прокси` : `в Windows ${cur}, а у прокси ${tzInfo.win}` }];
};

tunnel.on('log', (line) => {
  const l = `[${new Date().toLocaleTimeString()}] ${line}`;
  logBuf.push(l); if (logBuf.length > 500) logBuf.shift();
  send('log', l);
});
tunnel.on('state', (st) => { send('state', st); updateTray(st.state); });
tunnel.on('resolved', (ip) => { const s = loadSettings(); s.cachedIp = ip; saveSettings(s); });

const STATE_TEXT = {
  off: 'Отключено', connecting: 'Подключение…', on: 'Защищено',
  broken: 'Обрыв — интернет заблокирован', error: 'Ошибка — интернет заблокирован',
};

function trayIcon(state) {
  const name = state === 'on' ? 'tray-on.png' : (state === 'off' ? 'tray-off.png' : 'tray-warn.png');
  return nativeImage.createFromPath(path.join(__dirname, 'assets', name));
}

function updateTray(state = tunnel.state) {
  if (!tray) return;
  tray.setImage(trayIcon(state));
  tray.setToolTip(`S Tunnel — ${STATE_TEXT[state] || state}`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: `Статус: ${STATE_TEXT[state] || state}`, enabled: false },
    { type: 'separator' },
    { label: 'Открыть', click: showWindow },
    { label: 'Подключить', enabled: state !== 'on' && state !== 'connecting', click: () => doConnect() },
    { label: 'Отключить (вернуть обычный интернет)', enabled: state !== 'off', click: () => doDisconnect() },
    { type: 'separator' },
    ...(updater.status.state === 'ready'
      ? [{ label: `Установить обновление ${updater.status.available}`, click: showWindow }] : []),
    { label: 'Выход', click: () => { quitting = true; app.quit(); } },
  ]));
}

function showWindow() {
  if (!win) createWindow();
  win.show(); win.focus();
}

function createWindow() {
  win = new BrowserWindow({
    width: 520, height: 760, minWidth: 460, minHeight: 600,
    title: 'S Tunnel', autoHideMenuBar: true, backgroundColor: '#0f1115',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.on('close', (e) => { if (!quitting) { e.preventDefault(); win.hide(); } });
}

async function doConnect() {
  const s = loadSettings();
  if (!s.host || !s.port) { showWindow(); send('toast', 'Укажите адрес и порт прокси'); return; }
  await tunnel.connect({ ...s, password: decryptPassword(s) });
}

async function doDisconnect() {
  try { await tunnel.disconnect(); }
  catch (e) {
    dialog.showErrorBox('S Tunnel', `Не удалось восстановить брандмауэр: ${e.message}\n\nЗапустите аварийный скрипт: ${emergencyScript}`);
  }
}

// Автозапуск при входе в Windows. Ключ Run не запускает программы, требующие
// прав администратора, поэтому используем Планировщик с наивысшими правами.
function setAutostart(on) {
  if (!app.isPackaged) return;
  const { execFile } = require('child_process');
  const args = on
    ? ['/Create', '/F', '/TN', 'S Tunnel', '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/TR', `"${process.execPath}" --hidden`]
    : ['/Delete', '/F', '/TN', 'S Tunnel'];
  execFile('schtasks.exe', args, { windowsHide: true }, () => {});
}

ipcMain.handle('get-init', async () => ({
  settings: publicSettings(loadSettings()),
  status: tunnel.snapshot(),
  log: logBuf,
  update: updater.status,
  killSwitchLeft: tunnel.state === 'off' ? await firewall.isActive().catch(() => false) : false,
}));

ipcMain.handle('save-settings', (_e, inc) => {
  const s = loadSettings();
  const port = parseInt(inc.port, 10);
  if (!inc.host || /\s/.test(inc.host)) throw new Error('Некорректный адрес прокси');
  if (!(port > 0 && port < 65536)) throw new Error('Некорректный порт');
  if (s.host !== inc.host.trim()) s.cachedIp = '';
  Object.assign(s, {
    host: inc.host.trim(), port, protocol: PROTOCOLS.includes(inc.protocol) ? inc.protocol : 'http', username: (inc.username || '').trim(),
    allowLan: !!inc.allowLan, autoConnect: !!inc.autoConnect, syncTimezone: inc.syncTimezone !== false,
    dnsServer: /^[0-9.]+$/.test(inc.dnsServer || '') ? inc.dnsServer : '1.1.1.1',
  });
  if (typeof inc.password === 'string' && inc.password !== '') {
    s.passwordEnc = safeStorage.isEncryptionAvailable()
      ? safeStorage.encryptString(inc.password).toString('base64') : '';
  }
  if (inc.clearPassword) s.passwordEnc = '';
  saveSettings(s);
  setAutostart(s.autoConnect);
  // переключили «часовой пояс прокси» при включённом туннеле — применяем сразу
  if (tunnel.state === 'on') {
    if (s.syncTimezone && !tzInfo?.win) applyProxyTimezone().catch((e) => tunnel.log(`Часовой пояс: ${e.message}`));
    if (!s.syncTimezone && tzInfo) tz.restore().then(() => { tzInfo = null; tunnel.log('Часовой пояс Windows возвращён'); }).catch(() => {});
  }
  return publicSettings(s);
});

function appsView() {
  const s = loadSettings();
  let counts = {};
  try { counts = guard.counts(); } catch {}
  return s.guardedApps.map((a) => ({
    ...a, count: counts[a.path]?.n ?? null, truncated: !!counts[a.path]?.truncated, missing: !!counts[a.path]?.missing,
  }));
}

async function addApps(entries) {
  const s = loadSettings();
  const errors = [];
  for (const e of entries) {
    const err = validateEntry(e);
    if (err) { errors.push(`${e.name}: ${err}`); continue; }
    if (s.guardedApps.some((a) => lc(a.path) === lc(e.path))) continue;
    s.guardedApps.push({ type: e.type, path: e.path, name: e.name });
  }
  saveSettings(s);
  await guard.publish();
  return { apps: appsView(), errors };
}

ipcMain.handle('apps-list', () => appsView());
ipcMain.handle('guard-status', () => firewall.guardStatus());

// Установленные приложения из меню «Пуск»: приложение = папка, где лежит его программа
ipcMain.handle('apps-installed', async () => {
  const raw = await firewall.listStartMenuApps().catch(() => []);
  const byDir = new Map();
  for (const r of raw) {
    if (!r || !r.exe || /uninstall|удал|readme|help|справк|documentation|website|сайт/i.test(r.name)) continue;
    if (validateAppPath(r.exe)) continue;
    const dir = path.dirname(r.exe);
    const entry = validateAppDir(dir)
      ? { type: 'exe', path: r.exe, name: r.name }
      : { type: 'dir', path: dir, name: r.name };
    const k = lc(entry.path);
    if (!byDir.has(k) || r.name.length < byDir.get(k).name.length) byDir.set(k, entry);
  }
  // Приложения-пакеты MSIX / Microsoft Store (например Claude Desktop): своих ярлыков .lnk у них нет
  const pkgs = await firewall.listPackagedApps().catch(() => []);
  for (const p of pkgs) {
    if (!p || !p.pfn || validatePfn(p.pfn)) continue;
    byDir.set(`pkg:${p.pfn.toLowerCase()}`, { type: 'pkg', path: p.pfn, name: p.name || p.pfn, where: p.dir });
  }
  return [...byDir.values()].sort((a, b) => a.name.localeCompare(b.name, 'ru'));
});

ipcMain.handle('apps-add-entries', (_e, entries) => addApps(
  (Array.isArray(entries) ? entries : []).filter((x) => x && typeof x.path === 'string')
    .map((x) => ({ type: ['dir', 'pkg'].includes(x.type) ? x.type : 'exe', path: x.path, name: String(x.name || path.basename(x.path)) }))));

ipcMain.handle('apps-add-folder', async () => {
  const r = await dialog.showOpenDialog(win, { title: 'Папка, в которой установлено приложение', properties: ['openDirectory'] });
  if (r.canceled || !r.filePaths[0]) return { apps: appsView() };
  const d = r.filePaths[0];
  return addApps([{ type: 'dir', path: d, name: path.basename(d) }]);
});

ipcMain.handle('apps-add-exe', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: 'Отдельная программа (.exe)', filters: [{ name: 'Программы', extensions: ['exe'] }], properties: ['openFile', 'multiSelections'],
  });
  if (r.canceled) return { apps: appsView() };
  return addApps(r.filePaths.map((p) => ({ type: 'exe', path: p, name: path.basename(p, path.extname(p)) })));
});

ipcMain.handle('apps-remove', async (_e, p) => {
  const s = loadSettings();
  s.guardedApps = s.guardedApps.filter((a) => lc(a.path) !== lc(p));
  saveSettings(s);
  await guard.publish();
  return { apps: appsView() };
});

ipcMain.handle('connect', () => doConnect());
ipcMain.handle('disconnect', () => doDisconnect());
ipcMain.handle('leak-test', () => tunnel.state === 'on' ? tunnel.runLeakTest() : []);
ipcMain.handle('update-check', () => updater.check());
ipcMain.handle('update-download', () => updater.download());
ipcMain.handle('update-install', () => updater.install(() => {
  updating = true;
  tunnel.log('Устанавливаю обновление. Интернет заблокирован до переподключения — утечки нет.');
  tunnel.suspend();
}));
ipcMain.handle('open-emergency', () => shell.showItemInFolder(emergencyScript));

app.on('second-instance', showWindow);

app.whenReady().then(async () => {
  tray = new Tray(trayIcon('off'));
  tray.on('click', showWindow);
  updateTray('off');
  createWindow();
  if (process.argv.includes('--hidden')) win.hide();

  if (!(await firewall.isAdmin())) {
    dialog.showErrorBox('S Tunnel', 'Нужны права администратора (TUN-адаптер и брандмауэр). Запустите приложение от имени администратора.');
  }
  const s = loadSettings();
  guard.start().catch((e) => tunnel.log(`Фоновая защита приложений: ${e.message}`));
  const afterUpdate = updater.consumeReconnectFlag();
  if (afterUpdate) tunnel.log(`Обновлено до версии ${app.getVersion()}. Переподключаюсь…`);
  if ((s.autoConnect || afterUpdate) && s.host) doConnect();
  else tz.restore().catch(() => {}); // остался пояс прокси после сбоя — возвращаем ваш
  updater.start();
});

// При выходе ВСЕГДА пытаемся вернуть систему в исходное состояние
app.on('before-quit', async (e) => {
  quitting = true;
  // при обновлении НЕ снимаем kill switch: новая версия сама переподключится
  if (updating || tunnel.state === 'off' || app.__cleaned) return;
  e.preventDefault();
  try { await tunnel.disconnect(); } catch { /* kill switch останется — это безопасно */ }
  app.__cleaned = true;
  app.quit();
});

app.on('window-all-closed', (e) => e.preventDefault());
