'use strict';
// Проверки утечек. Запускаются после подключения и по кнопке.
const os = require('os');
const net = require('net');
const dgram = require('dgram');
const dns = require('dns');
const { TUN_V4, TUN_V6 } = require('./core-config');

async function getText(url, ms = 8000) {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms), cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.text()).trim();
}

async function publicIPv4() { return getText('https://api.ipify.org'); }
async function publicIPv6() { return getText('https://api6.ipify.org'); }

/** Адреса физических адаптеров (всё, кроме loopback, link-local и самого TUN). */
function physicalAddresses() {
  const res = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.internal) continue;
      if (a.address === TUN_V4 || a.address === TUN_V6) continue;
      if (a.family === 'IPv6' && a.address.toLowerCase().startsWith('fe80')) continue;
      if (a.address.startsWith('169.254.')) continue;
      res.push({ iface: name, address: a.address, family: a.family });
    }
  }
  return res;
}

/** Пытаемся выйти в интернет напрямую с адреса физического адаптера. Должно НЕ получиться. */
function tryDirectTcp(localAddress, family) {
  const host = family === 'IPv6' ? '2606:4700:4700::1111' : '1.1.1.1';
  return new Promise((resolve) => {
    const s = net.connect({ host, port: 443, localAddress, family: family === 'IPv6' ? 6 : 4 });
    const done = (leaked) => { s.destroy(); resolve(leaked); };
    s.setTimeout(4000, () => done(false));
    s.on('connect', () => done(true));
    s.on('error', () => done(false));
  });
}

function tryDirectUdpDns(localAddress) {
  // Простой DNS-запрос A example.com на 1.1.1.1:53 с физического адреса
  const query = Buffer.from('abcd01000001000000000000076578616d706c6503636f6d0000010001', 'hex');
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let finished = false;
    const done = (leaked) => { if (finished) return; finished = true; try { sock.close(); } catch {} resolve(leaked); };
    sock.on('error', () => done(false));
    sock.on('message', () => done(true));
    sock.bind(0, localAddress, () => {
      sock.send(query, 53, '1.1.1.1', (e) => { if (e) done(false); });
    });
    setTimeout(() => done(false), 3000);
  });
}

/**
 * STUN Binding Request (RFC 5389): сервер отвечает, с какого IP:порта пришёл UDP-пакет.
 * Через SOCKS5 это должен быть IP прокси; через HTTP(S) запрос не должен пройти вовсе.
 */
function stunMappedIp(host, port, ms = 4000) {
  return new Promise((resolve, reject) => {
    const tid = require('crypto').randomBytes(12);
    const req = Buffer.concat([Buffer.from([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]), tid]);
    const sock = dgram.createSocket('udp4');
    let finished = false;
    const done = (err, ip) => {
      if (finished) return; finished = true; clearTimeout(t);
      try { sock.close(); } catch {}
      err ? reject(err) : resolve(ip);
    };
    const t = setTimeout(() => done(new Error('нет ответа')), ms);
    sock.on('error', (e) => done(e));
    sock.on('message', (msg) => {
      if (msg.length < 20 || msg.readUInt16BE(0) !== 0x0101 || !msg.subarray(8, 20).equals(tid)) return;
      let off = 20;
      while (off + 4 <= msg.length) {
        const type = msg.readUInt16BE(off), len = msg.readUInt16BE(off + 2), v = off + 4;
        if ((type === 0x0020 || type === 0x0001) && msg[v + 1] === 0x01 && len >= 8) {
          const b = msg.subarray(v + 4, v + 8);
          const ip = type === 0x0020
            ? [b[0] ^ 0x21, b[1] ^ 0x12, b[2] ^ 0xa4, b[3] ^ 0x42].join('.')
            : [...b].join('.');
          return done(null, ip);
        }
        off = v + len + ((4 - (len % 4)) % 4);
      }
      done(new Error('ответ STUN без адреса'));
    });
    sock.send(req, port, host, (e) => { if (e) done(e); });
  });
}

async function udpPublicIp() {
  const servers = [['stun.cloudflare.com', 3478], ['stun.l.google.com', 19302]];
  let lastErr;
  for (const [h, p] of servers) {
    try { return await stunMappedIp(h, p); } catch (e) { lastErr = e; }
  }
  throw lastErr;
}

/**
 * @param {{realIPv4?:string, realIPv6?:string}} real  адреса, измеренные ДО подключения
 * @param {{udpExpected?:boolean}} [opts]  true для SOCKS5 (UDP должен идти через прокси)
 * @returns {Promise<Array<{name:string, ok:boolean, detail:string}>>}
 */
async function runAll(real = {}, opts = {}) {
  const results = [];

  // 1. Внешний IPv4
  try {
    const ip = await publicIPv4();
    const ok = !real.realIPv4 || ip !== real.realIPv4;
    results.push({ name: 'Внешний IPv4', ok, detail: ok ? `сайты видят ${ip}` : `УТЕЧКА: виден реальный IP ${ip}` });
  } catch (e) {
    results.push({ name: 'Внешний IPv4', ok: false, detail: `нет соединения через прокси (${e.message})` });
  }

  // 2. IPv6 — должен либо отсутствовать, либо не совпадать с реальным
  try {
    const ip6 = await publicIPv6();
    const ok = !real.realIPv6 || ip6 !== real.realIPv6;
    results.push({ name: 'IPv6', ok, detail: ok ? `через прокси: ${ip6}` : `УТЕЧКА: виден реальный IPv6 ${ip6}` });
  } catch {
    results.push({ name: 'IPv6', ok: true, detail: 'заблокирован (утечки нет)' });
  }

  // 3. DNS: кто резолвит наши запросы (Akamai возвращает IP резолвера)
  try {
    const r = await dns.promises.lookup(`whoami.akamai.net`, { family: 4 });
    const ok = !real.realIPv4 || r.address !== real.realIPv4;
    results.push({ name: 'DNS', ok, detail: `запросы видит резолвер ${r.address} (DoH через прокси)` });
  } catch (e) {
    results.push({ name: 'DNS', ok: false, detail: `DNS не работает (${e.code || e.message})` });
  }

  // 4. UDP (STUN): видимый снаружи IP для UDP-трафика
  try {
    const uip = await udpPublicIp();
    const ok = !real.realIPv4 || uip !== real.realIPv4;
    results.push({ name: 'UDP (звонки, игры, QUIC)', ok,
      detail: ok ? `работает через прокси, виден ${uip}` : `УТЕЧКА: UDP показывает реальный IP ${uip}` });
  } catch {
    results.push({ name: 'UDP (звонки, игры, QUIC)', ok: true,
      detail: opts.udpExpected
        ? 'не работает: сервер SOCKS5 не пропускает UDP (утечки нет, но звонки/игры работать не будут)'
        : 'заблокирован — HTTP(S)-прокси не передаёт UDP (утечки нет)' });
  }

  // 5. Kill switch: прямой выход мимо туннеля с каждого физического адреса
  const phys = physicalAddresses();
  for (const a of phys) {
    const tcpLeak = await tryDirectTcp(a.address, a.family);
    results.push({
      name: `Обход туннеля TCP (${a.iface}, ${a.address})`,
      ok: !tcpLeak,
      detail: tcpLeak ? 'УТЕЧКА: прямое соединение прошло' : 'заблокировано',
    });
    if (a.family === 'IPv4') {
      const udpLeak = await tryDirectUdpDns(a.address);
      results.push({
        name: `Обход туннеля UDP/DNS (${a.iface})`,
        ok: !udpLeak,
        detail: udpLeak ? 'УТЕЧКА: прямой DNS-запрос прошёл' : 'заблокировано',
      });
    }
  }
  if (!phys.length) results.push({ name: 'Обход туннеля', ok: true, detail: 'физические адаптеры не найдены' });

  return results;
}

module.exports = { runAll, udpPublicIp, stunMappedIp, publicIPv4, publicIPv6, physicalAddresses };
