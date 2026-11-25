'use strict';
const $ = (id) => document.getElementById(id);
const api = window.stunnel;

const STATE = {
  off: ['Отключено', 'off', 'Подключить'],
  connecting: ['Подключение…', 'warn', 'Отключить'],
  on: ['Защищено — весь трафик через прокси', 'on', 'Отключить'],
  broken: ['Обрыв — интернет заблокирован, утечки нет', 'warn', 'Отключить'],
  error: ['Ошибка — интернет заблокирован, утечки нет', 'bad', 'Отключить'],
};
let current = 'off';
let hasPassword = false;

function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), 3500);
}

function fillSettings(s) {
  $('host').value = s.host || '';
  $('port').value = s.port || '';
  $('username').value = s.username || '';
  $('password').value = '';
  hasPassword = s.hasPassword;
  $('password').placeholder = s.hasPassword ? '•••••• (сохранён)' : '';
  $('protocol').value = s.protocol || 'http';
  protoHint();
  $('allowLan').checked = !!s.allowLan;
  $('autoConnect').checked = !!s.autoConnect;
  $('syncTimezone').checked = s.syncTimezone !== false;
  $('dnsServer').value = s.dnsServer || '1.1.1.1';
}

function renderState(st) {
  current = st.state;
  const [text, cls, btn] = STATE[st.state] || [st.state, 'warn', 'Отключить'];
  $('stateText').textContent = text;
  $('dot').className = `dot ${cls}`;
  $('toggle').textContent = btn;
  $('toggle').disabled = st.state === 'connecting';
  const b = $('banner');
  if (st.lastError) { b.textContent = st.lastError; b.classList.remove('hidden'); } else b.classList.add('hidden');
  $('realIp').textContent = st.realIPv4 ? `Ваш реальный IP (до подключения): ${st.realIPv4}` : '';
  const ul = $('results'); ul.innerHTML = '';
  for (const r of st.leakResults || []) {
    const li = document.createElement('li');
    li.className = r.ok ? 'ok' : 'fail';
    const n = document.createElement('b'); n.textContent = `${r.ok ? '✔' : '✖'} ${r.name}`;
    const d = document.createElement('span'); d.textContent = r.detail;
    li.append(n, d); ul.append(li);
  }
}

function addLog(line) {
  const el = $('log');
  el.textContent += line + '\n';
  if (el.textContent.length > 60000) el.textContent = el.textContent.slice(-50000);
  el.scrollTop = el.scrollHeight;
}

async function save() {
  try {
    const s = await api.save({
      host: $('host').value, port: $('port').value, username: $('username').value,
      password: $('password').value, protocol: $('protocol').value, allowLan: $('allowLan').checked,
      autoConnect: $('autoConnect').checked, syncTimezone: $('syncTimezone').checked, dnsServer: $('dnsServer').value.trim(),
    });
    fillSettings(s);
    toast(current === 'on' ? 'Сохранено. Переподключитесь, чтобы применить.' : 'Сохранено');
    return true;
  } catch (e) { toast(String(e.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '')); return false; }
}

const HINTS = {
  socks5: 'UDP пойдёт через прокси, если сервер это поддерживает (проверка покажет). Канал до прокси не шифруется: провайдер видит, что вы подключены к прокси, и имена сайтов.',
  https: 'Канал до прокси зашифрован. UDP заблокирован: звонки в части мессенджеров и некоторые игры не будут работать.',
  http: 'Канал до прокси не шифруется. UDP заблокирован.',
};
function protoHint() { $('protoHint').textContent = HINTS[$('protocol').value] || ''; }
$('protocol').onchange = protoHint;

$('save').onclick = save;
$('toggle').onclick = async () => {
  const btn = $('toggle');
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    if (current === 'off') { if (await save()) await api.connect(); }
    else { btn.textContent = 'Отключаю…'; await api.disconnect(); }
  } finally { btn.disabled = current === 'connecting'; }
};
$('test').onclick = async () => {
  if (current !== 'on') { toast('Сначала подключитесь'); return; }
  $('test').disabled = true; $('test').textContent = 'Проверяю…';
  await api.leakTest();
  $('test').disabled = false; $('test').textContent = 'Проверить';
};
function plural(n, a, b, c) { const m = n % 10, h = n % 100; return m === 1 && h !== 11 ? a : (m >= 2 && m <= 4 && (h < 12 || h > 14) ? b : c); }

const GUARD_TEXT = {
  Running: '● Фоновая защита работает', Ready: '○ Фоновая защита установлена, но не запущена (запустится вместе с Windows)',
  Disabled: '✖ Фоновая защита отключена в Планировщике заданий', missing: '✖ Фоновая защита не установлена', unknown: '',
};
async function refreshGuard(apps) {
  if (!apps.length) { $('guardState').textContent = ''; return; }
  const st = await api.guardStatus().catch(() => ({ task: 'unknown', firewall: true }));
  let text = GUARD_TEXT[st.task] ?? `Фоновая защита: ${st.task}`;
  if (!st.firewall) text += ' · ⚠ Брандмауэр Windows выключен: без туннеля приложения закрываются, но их сетевая блокировка не действует. Включите брандмауэр.';
  $('guardState').textContent = text;
}

function renderApps(apps) {
  refreshGuard(apps);
  const ul = $('apps'); ul.innerHTML = '';
  if (!apps.length) {
    const li = document.createElement('li'); li.className = 'empty';
    li.textContent = 'Список пуст — все приложения работают как обычно';
    ul.append(li); return;
  }
  for (const a of apps) {
    const li = document.createElement('li'); li.className = 'app';
    const info = document.createElement('div');
    const n = document.createElement('b'); n.textContent = a.name;
    const p = document.createElement('span');
    const c = a.count == null ? '' : ` · ${a.count}${a.truncated ? '+' : ''} ${plural(a.count, 'программа', 'программы', 'программ')}`;
    if (a.type === 'dir') p.textContent = `Приложение целиком${c} — ${a.path}`;
    else if (a.type === 'pkg') p.textContent = a.missing ? `Пакет ${a.path} — сейчас не установлен` : `Приложение целиком (пакет MSIX/Store)${c}`;
    else p.textContent = `Только этот .exe — ${a.path}`;
    p.title = a.path;
    info.append(n, p);
    const rm = document.createElement('button'); rm.className = 'small link'; rm.textContent = 'Убрать';
    rm.onclick = async () => renderApps((await api.appsRemove(a.path)).apps);
    li.append(info, rm); ul.append(li);
  }
}

function afterAdd(r) {
  renderApps(r.apps);
  if (r.errors && r.errors.length) toast(r.errors.join('; '));
}

// ---- окно выбора приложений ----
let installed = [];
const picked = new Set();
function renderPicker() {
  const f = $('pkSearch').value.trim().toLowerCase();
  const ul = $('pkList'); ul.innerHTML = '';
  const list = installed.filter((a) => !f || a.name.toLowerCase().includes(f) || a.path.toLowerCase().includes(f));
  if (!list.length) {
    const li = document.createElement('li'); li.className = 'empty';
    li.textContent = installed.length ? 'Ничего не найдено' : 'Приложения не найдены — выберите папку вручную';
    ul.append(li);
  }
  for (const a of list) {
    const li = document.createElement('li'); li.className = 'pick';
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = picked.has(a.path);
    cb.onchange = () => { cb.checked ? picked.add(a.path) : picked.delete(a.path); $('pkAdd').disabled = !picked.size; };
    const info = document.createElement('div');
    const n = document.createElement('b'); n.textContent = a.name;
    const p = document.createElement('span');
    p.textContent = a.type === 'pkg' ? `Пакет MSIX/Store · ${a.path}` : a.path;
    p.title = a.where || a.path;
    info.append(n, p);
    const label = document.createElement('label'); label.className = 'pickrow';
    label.append(cb, info); li.append(label); ul.append(li);
  }
  $('pkAdd').textContent = picked.size ? `Добавить (${picked.size})` : 'Добавить';
  $('pkAdd').disabled = !picked.size;
}
async function openPicker() {
  picked.clear(); $('pkSearch').value = '';
  $('picker').classList.remove('hidden');
  $('pkList').innerHTML = '<li class="empty">Загружаю список приложений…</li>';
  try { installed = await api.appsInstalled(); } catch { installed = []; }
  renderPicker();
  $('pkSearch').focus();
}
const closePicker = () => $('picker').classList.add('hidden');
$('appsAdd').onclick = openPicker;
$('pkClose').onclick = closePicker;
$('pkSearch').oninput = renderPicker;
$('pkAdd').onclick = async () => {
  const entries = installed.filter((a) => picked.has(a.path));
  $('pkAdd').disabled = true; $('pkAdd').textContent = 'Добавляю…';
  afterAdd(await api.appsAddEntries(entries));
  closePicker();
};
$('pkFolder').onclick = async () => { const r = await api.appsAddFolder(); afterAdd(r); if (!r.errors?.length) closePicker(); };
$('pkExe').onclick = async () => { const r = await api.appsAddExe(); afterAdd(r); if (!r.errors?.length) closePicker(); };

let upd = { state: 'idle' };
function renderUpdate(u) {
  upd = u;
  $('appVersion').textContent = `версия ${u.version}`;
  const btn = $('updBtn'); btn.disabled = false;
  const map = {
    idle: ['Проверяется автоматически, когда туннель включён', 'Проверить'],
    checking: ['Проверяю…', null],
    latest: ['Установлена последняя версия', 'Проверить'],
    available: [`Доступна версия ${u.available}`, 'Скачать'],
    downloading: [`Скачиваю… ${u.percent || 0}%`, null],
    ready: [`Версия ${u.available} скачана`, 'Установить и перезапустить'],
    error: [u.error || 'Ошибка', 'Проверить'],
  };
  const [text, label] = map[u.state] || map.idle;
  $('updText').textContent = text;
  if (label) { btn.textContent = label; btn.classList.remove('hidden'); } else btn.classList.add('hidden');
}
$('updBtn').onclick = () => {
  if (upd.state === 'available') api.updateDownload();
  else if (upd.state === 'ready') api.updateInstall();
  else api.updateCheck();
};
api.onUpdate(renderUpdate);

$('emergency').onclick = () => api.openEmergency();

api.onState(renderState);
api.onLog(addLog);
api.onToast(toast);

api.init().then((d) => {
  fillSettings(d.settings);
  renderState(d.status);
  d.log.forEach(addLog);
  renderUpdate(d.update);
  api.appsList().then(renderApps);
  if (d.killSwitchLeft) {
    const b = $('banner');
    b.textContent = 'Kill switch остался включён после прошлого сбоя — интернет заблокирован. Подключитесь или нажмите «Отключить».';
    b.classList.remove('hidden');
    current = 'error';
    $('toggle').textContent = 'Отключить';
  }
});
