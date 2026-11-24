'use strict';
// Проверка генератора конфига. С флагом --write <file> сохраняет пример,
// который в CI проверяется настоящим `sing-box check`.
const assert = require('assert');
const fs = require('fs');
const { buildConfig } = require('../src/core-config');

const base = { proxyIp: '203.0.113.10', port: 3128, tls: true, sni: 'proxy.example.com',
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

const lan = buildConfig({ ...base, allowLan: true, tls: false });
assert.ok(lan.inbounds[0].route_exclude_address.includes('192.168.0.0/16'));
assert.ok(!lan.outbounds[0].tls);

const i = process.argv.indexOf('--write');
if (i > 0) fs.writeFileSync(process.argv[i + 1], JSON.stringify(c, null, 2));
console.log('config tests: OK');
