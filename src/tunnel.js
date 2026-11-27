'use strict';
// Управление туннелем: kill switch -> ядро sing-box -> проверка утечек -> сторож.
const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const dns = require('dns');
const net = require('net');

const { buildConfig, supportsUdp } = require('./core-config');
const firewall = require('./firewall');
const leak = require('./leakcheck');

const MAX_RESTARTS = 5;

class Tunnel extends EventEmitter {
  constructor({ corePath, workDir }) {
    super();
    this.beforeRestore = null; // async-хук перед снятием kill switch (защита программ)
    this.afterConnect = null;  // async-хук после подключения (часовой пояс прокси)
    this.afterRestore = null;  // async-хук после отключения (вернуть часовой пояс)
    this.extraChecks = null;   // async () => [{name, ok, detail}] — доп. пункты проверки утечек
    this.corePath = corePath;
    this.workDir = workDir;
    this.proc = null;
    this.state = 'off'; // off | connecting | on | broken | error
    this.stopping = false;
    this.restarts = 0;
    this.real = {};
    this.settings = null;
    this.gen = 0; // поколение подключения: старые автоперезапуски не мешают новым
    this.lastError = '';
    this.leakResults = [];
    fs.mkdirSync(workDir, { recursive: true });
    this.cfgPath = path.join(workDir, 'config.json');
    this.wipeConfig(); // остаток после аварийного завершения
  }

  /** Конфиг с паролем лежит на диске только на время запуска ядра. */
  wipeConfig() {
    try { if (fs.existsSync(this.cfgPath)) { fs.writeFileSync(this.cfgPath, ''); fs.unlinkSync(this.cfgPath); } } catch {}
  }

  setState(state, extra = {}) {
    this.state = state;
    Object.assign(this, extra);
    this.emit('state', this.snapshot());
  }

  snapshot() {
    return {
      state: this.state,
      lastError: this.lastError,
      realIPv4: this.real.realIPv4 || '',
      leakResults: this.leakResults,
    };
  }

  log(line) { this.emit('log', line); }

  async resolveProxy(s) {
    if (net.isIP(s.host)) return s.host;
    try {
      const r = await Promise.race([
        dns.promises.lookup(s.host, { family: 4 }),
        new Promise((_, rej) => setTimeout(() => rej(new Error('таймаут DNS')), 6000)),
      ]);
      return r.address;
    } catch (e) {
      // Если kill switch уже активен (например, после сбоя), DNS заблокирован — берём кэш
      if (s.cachedIp && net.isIP(s.cachedIp)) { this.log(`Не удалось разрешить ${s.host} (${e.message}), использую сохранённый IP ${s.cachedIp}`); return s.cachedIp; }
      throw new Error(`Не удалось получить IP прокси ${s.host}: ${e.message}`);
    }
  }

  /** @param {{force?:boolean}} [opts]  force: переподключиться при уже включённом туннеле (kill switch не снимается) */
  async connect(settings, opts = {}) {
    if (this.state === 'connecting') return;
    if (this.state === 'on' && !opts.force) return;
    this.gen += 1;
    this.killCore();
    this.settings = settings;
    this.stopping = false;
    this.restarts = 0;
    this.leakResults = [];
    this.lastError = '';
    this.setState('connecting');
    try {
      if (!fs.existsSync(this.corePath)) throw new Error(`Не найдено ядро: ${this.corePath}`);
      const proxyIp = await this.resolveProxy(settings);
      this.emit('resolved', proxyIp);

      // Запоминаем реальный IP до подключения (только чтобы сравнить в тестах; никуда не отправляется)
      if (!(await firewall.isActive())) {
        this.real = {};
        try { this.real.realIPv4 = await leak.publicIPv4(); } catch {}
        try { this.real.realIPv6 = await leak.publicIPv6(); } catch {}
      }

      this.log('Включаю kill switch (Windows Firewall)…');
      await firewall.enable({ corePath: this.corePath, proxyIp, proxyPort: settings.port, allowLan: settings.allowLan, udp: supportsUdp(settings.protocol), direct: (settings.excludedApps || []).length > 0 });

      const cfg = buildConfig({
        proxyIp, port: settings.port, protocol: settings.protocol, sni: net.isIP(settings.host) ? '' : settings.host,
        username: settings.username, password: settings.password,
        allowLan: settings.allowLan, dnsServer: settings.dnsServer, excluded: settings.excludedApps || [],
      });
      this.cfgJson = JSON.stringify(cfg, null, 2); // только в памяти

      await this.startCore();
      this.proxyIp = proxyIp;
      await this.resetOldConnections();
      this.setState('on');
      if (this.afterConnect) {
        try { await this.afterConnect(); } catch (e) { this.log(`После подключения: ${e.message}`); }
      }
      await this.runLeakTest();
    } catch (e) {
      this.log(`Ошибка: ${e.message}`);
      this.killCore();
      // kill switch оставляем включённым: лучше без интернета, чем с утечкой
      this.setState('error', { lastError: e.message });
    }
  }

  async startCore() {
    await firewall.cleanupTunAddresses();
    return this.spawnCore();
  }

  spawnCore() {
    return new Promise((resolve, reject) => {
      this.log('Запускаю ядро sing-box…');
      fs.writeFileSync(this.cfgPath, this.cfgJson, { mode: 0o600 });
      const p = spawn(this.corePath, ['run', '-c', this.cfgPath, '-D', this.workDir],
        { windowsHide: true, cwd: path.dirname(this.corePath) });
      this.proc = p;
      const myGen = this.gen;
      let started = false;
      let fatal = '';
      const timer = setTimeout(() => {
        if (!started) { reject(new Error('Ядро не запустилось за 20 секунд')); this.killCore(); }
      }, 20000);
      const onData = (d) => {
        for (const line of String(d).split(/\r?\n/)) {
          if (!line.trim()) continue;
          // не показываем пароль, если он вдруг попадёт в лог
          const clean = line.replace(/\x1b\[[0-9;]*m/g, '');
          const safe = this.settings?.password ? clean.split(this.settings.password).join('***') : clean;
          this.log(safe);
          if (/FATAL/.test(safe)) fatal = safe.replace(/^.*FATAL\S*\s*(\[\d+\]\s*)?/, '');
          if (!started && /sing-box started/i.test(line)) { started = true; clearTimeout(timer); this.wipeConfig(); resolve(); }
        }
      };
      // Потоки читаем постоянно, иначе переполненный буфер подвесит ядро
      p.stdout.on('data', onData);
      p.stderr.on('data', onData);
      p.on('error', (e) => { clearTimeout(timer); this.wipeConfig(); if (!started) reject(e); });
      p.on('exit', (code) => {
        clearTimeout(timer);
        this.wipeConfig();
        if (this.proc === p) this.proc = null;
        if (!started) { reject(new Error(explainFatal(fatal) || `Ядро завершилось с кодом ${code} — смотрите журнал`)); return; }
        if (!this.stopping && myGen === this.gen) this.onCrash(code);
      });
    });
  }

  async onCrash(code) {
    const gen = this.gen;
    this.log(`Ядро неожиданно остановилось (код ${code}). Интернет заблокирован kill switch'ем — утечки нет.`);
    this.setState('broken', { lastError: `Ядро остановилось (код ${code})` });
    if (this.restarts >= MAX_RESTARTS) {
      this.log('Автоперезапуск исчерпан. Нажмите «Подключить» или «Отключить защиту».');
      return;
    }
    this.restarts += 1;
    await new Promise((r) => setTimeout(r, 3000 * this.restarts));
    if (this.stopping || gen !== this.gen) return;
    try {
      await this.startCore();
      this.setState('on', { lastError: '' });
      this.log('Туннель восстановлен.');
    } catch (e) {
      this.log(`Перезапуск не удался: ${e.message}`);
      this.onCrash(-1);
    }
  }

  killCore() {
    if (this.proc) { try { this.proc.kill(); } catch {} this.proc = null; }
  }

  /** Закрыть соединения, открытые до туннеля (они шли бы мимо него с реальным IP). */
  async resetOldConnections() {
    try {
      const phys = leak.physicalAddresses().map((a) => a.address);
      const n = await firewall.resetDirectConnections({ phys, proxyIp: this.proxyIp, allowLan: this.settings.allowLan });
      if (n) this.log(`Сброшено соединений, открытых до подключения: ${n}. Программы переподключатся уже через туннель.`);
    } catch (e) { this.log(`Не удалось сбросить старые соединения: ${e.message}`); }
  }

  async runLeakTest() {
    this.log('Проверяю утечки…');
    this.leakResults = await leak.runAll(this.real, {
      udpExpected: supportsUdp(this.settings?.protocol),
      proxyIp: this.proxyIp,
      allowLan: this.settings?.allowLan,
    });
    if (this.extraChecks) {
      try { this.leakResults.push(...(await this.extraChecks())); } catch {}
    }
    for (const r of this.leakResults) this.log(`${r.ok ? '✔' : '✖'} ${r.name}: ${r.detail}`);
    this.emit('state', this.snapshot());
    return this.leakResults;
  }

  /** Остановить ядро, но оставить kill switch (используется при установке обновления). */
  suspend() {
    this.stopping = true;
    this.gen += 1;
    this.killCore();
  }

  /** Полное отключение: ядро стоп + восстановление правил брандмауэра. */
  disconnect() {
    // Повторный вызов (двойной клик, трей + кнопка) ждёт уже идущее отключение
    if (!this._disconnecting) {
      this._disconnecting = this._disconnect().finally(() => { this._disconnecting = null; });
    }
    return this._disconnecting;
  }

  async _disconnect() {
    this.cfgJson = '';
    this.stopping = true;
    this.gen += 1;
    this.killCore();
    if (this.beforeRestore) {
      try { await this.beforeRestore(); } catch (e) { this.log(`Защита программ: ${e.message}`); }
    }
    this.log('Восстанавливаю исходные правила брандмауэра…');
    try { await firewall.disable(); } catch (e) { this.log(`Ошибка восстановления: ${e.message}`); throw e; }
    this.leakResults = [];
    if (this.afterRestore) {
      try { await this.afterRestore(); } catch (e) { this.log(`После отключения: ${e.message}`); }
    }
    this.setState('off', { lastError: '' });
  }
}

function explainFatal(f) {
  if (!f) return '';
  if (/already exists/i.test(f)) return `Адрес виртуального адаптера занят другой программой (VPN/прокси-клиент). Закройте её и подключитесь снова. (${f})`;
  if (/access is denied|permission/i.test(f)) return `Нет прав администратора для создания адаптера. (${f})`;
  return `Ядро не запустилось: ${f}`;
}

module.exports = { Tunnel };
