'use strict';
// Проверка генератора конфига. С флагом --write <file> сохраняет пример,
// который в CI проверяется настоящим `sing-box check`.
const assert = require('assert');
const fs = require('fs');
const { buildConfig } = require('../src/core-config');

const base = { proxyIp: '203.0.113.10', port: 3128, protocol: 'https', sni: 'proxy.example.com',
  username: 'u', password: 'p', allowLan: false, dnsServer: '1.1.1.1' };
const c = buildConfig(base);

assert.strictEqual(c.outbounds.length, 1, 'единственный выход — прокси (нет direct)');
assert.strictEqual(c.outbounds[0].type, 'http');
assert.strictEqual(c.outbounds[0].tls.server_name, 'proxy.example.com');
assert.strictEqual(c.route.final, 'proxy');
assert.ok(c.inbounds[0].strict_route && c.inbounds[0].auto_route);
assert.ok(c.inbounds[0].address.some((a) => a.includes(':')), 'IPv6 захватывается туннелем');
assert.ok(c.route.rules.some((r) => r.network === 'udp' && r.action === 'reject'), 'UDP отклоняется');
assert.strictEqual(c.dns.servers[0].detour, 'proxy', 'DNS идёт через прокси');
assert.ok(!c.inbounds[0].route_exclude_address, 'без LAN ничего не исключается');

const lan = buildConfig({ ...base, allowLan: true, protocol: 'http' });
assert.ok(lan.inbounds[0].route_exclude_address.includes('192.168.0.0/16'));
assert.ok(!lan.outbounds[0].tls);

// SOCKS5: UDP НЕ отклоняется, выход типа socks v5, DNS всё так же через прокси
const sk = buildConfig({ ...base, protocol: 'socks5', port: 1080 });
assert.strictEqual(sk.outbounds[0].type, 'socks');
assert.strictEqual(sk.outbounds[0].version, '5');
assert.ok(!sk.outbounds[0].tls);
assert.ok(!sk.route.rules.some((r) => r.network === 'udp'), 'UDP через SOCKS5 разрешён');
assert.strictEqual(sk.route.final, 'proxy');
assert.strictEqual(sk.outbounds.length, 1, 'мимо прокси выхода нет');
assert.strictEqual(sk.dns.servers[0].detour, 'proxy');

// неизвестный протокол -> безопасный http без UDP
const bad = buildConfig({ ...base, protocol: 'weird' });
assert.ok(bad.route.rules.some((r) => r.network === 'udp' && r.action === 'reject'));

// Исключения: правило process_path_regex -> direct раньше блокировки UDP, find_process включён
const ex = buildConfig({ ...base, excluded: [
  { type: 'dir', path: 'C:\\Program Files (x86)\\Steam' },
  { type: 'exe', path: 'C:\\Games\\a+b.exe' },
  { type: 'pkg', path: 'Claude_pzs8sxrjxfjjc' },
] });
assert.deepStrictEqual(ex.outbounds.map((o) => o.tag), ['proxy', 'direct']);
assert.strictEqual(ex.route.find_process, true);
const exIdx = ex.route.rules.findIndex((r) => r.outbound === 'direct');
const udpIdx = ex.route.rules.findIndex((r) => r.network === 'udp');
assert.ok(exIdx > 0 && exIdx < udpIdx, 'исключения раньше блокировки UDP');
assert.strictEqual(ex.route.rules[exIdx].process_path_regex.length, 3);
assert.ok(new RegExp(ex.route.rules[exIdx].process_path_regex[0].replace('(?i)', ''), 'i').test('c:\\program files (x86)\\steam\\steam.exe'));
assert.strictEqual(ex.route.final, 'proxy', 'всё остальное — через прокси');
assert.strictEqual(c.outbounds.length, 1, 'без исключений прямого выхода нет');

const i = process.argv.indexOf('--write');
if (i > 0) {
  fs.writeFileSync(process.argv[i + 1], JSON.stringify(c, null, 2));
  fs.writeFileSync(process.argv[i + 1].replace(/\.json$/, '-socks.json'), JSON.stringify(sk, null, 2));
  fs.writeFileSync(process.argv[i + 1].replace(/\.json$/, '-excl.json'), JSON.stringify(ex, null, 2));
}
console.log('config tests: OK');
