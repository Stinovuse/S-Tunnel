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
  $('tls').checked = !!s.tls;
  $('allowLan').checked = !!s.allowLan;
  $('autoConnect').checked = !!s.autoConnect;
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
      password: $('password').value, tls: $('tls').checked, allowLan: $('allowLan').checked,
      autoConnect: $('autoConnect').checked, dnsServer: $('dnsServer').value.trim(),
    });
    fillSettings(s);
    toast(current === 'on' ? 'Сохранено. Переподключитесь, чтобы применить.' : 'Сохранено');
    return true;
  } catch (e) { toast(String(e.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '')); return false; }
}

$('save').onclick = save;
$('toggle').onclick = async () => {
  if (current === 'off') { if (await save()) api.connect(); }
  else api.disconnect();
};
$('test').onclick = async () => {
  if (current !== 'on') { toast('Сначала подключитесь'); return; }
  $('test').disabled = true; $('test').textContent = 'Проверяю…';
  await api.leakTest();
  $('test').disabled = false; $('test').textContent = 'Проверить';
};
$('emergency').onclick = () => api.openEmergency();

api.onState(renderState);
api.onLog(addLog);
api.onToast(toast);

api.init().then((d) => {
  fillSettings(d.settings);
  renderState(d.status);
  d.log.forEach(addLog);
  if (d.killSwitchLeft) {
    const b = $('banner');
    b.textContent = 'Kill switch остался включён после прошлого сбоя — интернет заблокирован. Подключитесь или нажмите «Отключить».';
    b.classList.remove('hidden');
    current = 'error';
    $('toggle').textContent = 'Отключить';
  }
});
