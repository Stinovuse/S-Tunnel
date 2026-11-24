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
      if (s.cachedIp) { this.log(`Не удалось разрешить ${s.host} (${e.message}), использую сохранённый IP ${s.cachedIp}`); return s.cachedIp; }
      throw new Error(`Не удалось получить IP прокси ${s.host}: ${e.message}`);
    }
  }

  async connect(settings) {
    if (this.state === 'connecting' || this.state === 'on') return;
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
      await firewall.enable({ corePath: this.corePath, proxyIp, proxyPort: settings.port, allowLan: settings.allowLan, udp: supportsUdp(settings.protocol) });

      const cfg = buildConfig({
        proxyIp, port: settings.port, protocol: settings.protocol, sni: net.isIP(settings.host) ? '' : settings.host,
        username: settings.username, password: settings.password,
        allowLan: settings.allowLan, dnsServer: settings.dnsServer,
      });
      this.cfgPath = path.join(this.workDir, 'config.json');
      fs.writeFileSync(this.cfgPath, JSON.stringify(cfg, null, 2), { mode: 0o600 });

      await this.startCore();
      this.setState('on');
      await this.runLeakTest();
    } catch (e) {
      this.log(`Ошибка: ${e.message}`);
      this.killCore();
      // kill switch оставляем включённым: лучше без интернета, чем с утечкой
      this.setState('error', { lastError: e.message });
    }
  }

  startCore() {
    return new Promise((resolve, reject) => {
      this.log('Запускаю ядро sing-box…');
      const p = spawn(this.corePath, ['run', '-c', this.cfgPath, '-D', this.workDir],
        { windowsHide: true, cwd: path.dirname(this.corePath) });
      this.proc = p;
      const myGen = this.gen;
      let started = false;
      const timer = setTimeout(() => {
        if (!started) { reject(new Error('Ядро не запустилось за 20 секунд')); this.killCore(); }
      }, 20000);
      const onData = (d) => {
        for (const line of String(d).split(/\r?\n/)) {
          if (!line.trim()) continue;
          // не показываем пароль, если он вдруг попадёт в лог
          const safe = this.settings?.password ? line.split(this.settings.password).join('***') : line;
          this.log(safe);
          if (!started && /sing-box started/i.test(line)) { started = true; clearTimeout(timer); resolve(); }
        }
      };
      // Потоки читаем постоянно, иначе переполненный буфер подвесит ядро
      p.stdout.on('data', onData);
      p.stderr.on('data', onData);
      p.on('error', (e) => { clearTimeout(timer); if (!started) reject(e); });
      p.on('exit', (code) => {
        clearTimeout(timer);
        if (this.proc === p) this.proc = null;
        if (!started) { reject(new Error(`Ядро завершилось с кодом ${code} — смотрите журнал`)); return; }
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

  async runLeakTest() {
    this.log('Проверяю утечки…');
    this.leakResults = await leak.runAll(this.real, { udpExpected: supportsUdp(this.settings?.protocol) });
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
  async disconnect() {
    this.stopping = true;
    this.gen += 1;
    this.killCore();
    this.log('Восстанавливаю исходные правила брандмауэра…');
    try { await firewall.disable(); } catch (e) { this.log(`Ошибка восстановления: ${e.message}`); throw e; }
    this.leakResults = [];
    this.setState('off', { lastError: '' });
  }
}

module.exports = { Tunnel };
