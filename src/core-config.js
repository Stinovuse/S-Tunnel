'use strict';
// Генерация конфига sing-box (проверено по схеме 1.13.x).
// Принцип: ВЕСЬ трафик -> TUN -> HTTP(S)-прокси. UDP через HTTP-прокси невозможен
// (CONNECT = только TCP), поэтому UDP отклоняется, а DNS перехватывается и уходит
// как DNS-over-HTTPS (TCP 443) ЧЕРЕЗ прокси.

const TUN_NAME = 'STunnel';
const TUN_V4 = '172.19.0.1';
const TUN_V6 = 'fdfe:dcba:9876::1';

const PRIVATE_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  'fc00::/7',
  'fe80::/10',
];

/**
 * @param {object} o
 * @param {string} o.proxyIp      IP прокси (уже разрешённый, чтобы ядру не нужен был DNS)
 * @param {number} o.port
 * @param {string} [o.sni]        имя хоста для TLS (HTTPS-прокси)
 * @param {boolean} o.tls
 * @param {string} [o.username]
 * @param {string} [o.password]
 * @param {boolean} o.allowLan    пускать локальную сеть (принтеры, NAS) мимо туннеля
 * @param {string} o.dnsServer    IP DoH-сервера, например 1.1.1.1
 * @param {string} [o.logLevel]
 */
function buildConfig(o) {
  const proxy = {
    type: 'http',
    tag: 'proxy',
    server: o.proxyIp,
    server_port: Number(o.port),
  };
  if (o.username) {
    proxy.username = o.username;
    proxy.password = o.password || '';
  }
  if (o.tls) {
    proxy.tls = { enabled: true, server_name: o.sni || o.proxyIp };
  }

  const tun = {
    type: 'tun',
    tag: 'tun-in',
    interface_name: TUN_NAME,
    address: [`${TUN_V4}/30`, `${TUN_V6}/126`], // IPv6 тоже захватываем, чтобы он не шёл мимо
    mtu: 1500,
    auto_route: true,
    strict_route: true, // на Windows: блок DNS (53) мимо TUN через WFP
    stack: 'gvisor',
  };
  if (o.allowLan) tun.route_exclude_address = PRIVATE_RANGES;

  return {
    log: { level: o.logLevel || 'info', timestamp: true },
    dns: {
      servers: [
        { type: 'https', tag: 'doh', server: o.dnsServer || '1.1.1.1', detour: 'proxy' },
      ],
      final: 'doh',
      strategy: 'ipv4_only',
    },
    inbounds: [tun],
    outbounds: [proxy],
    route: {
      auto_detect_interface: true, // сокеты самого ядра привязаны к физ. адаптеру — без петли
      rules: [
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        { port: 53, action: 'hijack-dns' },
        { network: 'udp', action: 'reject' }, // QUIC, WebRTC/STUN, игры — не утекут
        { ip_is_private: true, action: 'reject' },
      ],
      final: 'proxy',
    },
  };
}

module.exports = { buildConfig, TUN_NAME, TUN_V4, TUN_V6, PRIVATE_RANGES };
