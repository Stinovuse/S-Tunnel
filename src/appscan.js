'use strict';
// Приложение = папка, в которой оно установлено. Блокируются ВСЕ .exe внутри:
// основная программа, вспомогательные процессы, программа обновления, новые версии.
const fs = require('fs');
const path = require('path');

const MAX_EXES_PER_APP = 400;
const MAX_DEPTH = 8;

// Нельзя добавлять: системные программы и то, на чём работает сам S Tunnel
const FORBIDDEN_NAMES = new Set(['powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'explorer.exe',
  'svchost.exe', 'sing-box.exe', 's tunnel.exe', 'icacls.exe', 'schtasks.exe', 'netsh.exe']);

const lc = (p) => path.win32.normalize(String(p)).replace(/\\+$/, '').toLowerCase();
const isInside = (child, parent) => child === parent || child.startsWith(parent + '\\');

function env(name) { return process.env[name] ? lc(process.env[name]) : ''; }

/** Слишком общие папки: их блокировка задела бы всё подряд. */
function broadDirs() {
  const home = env('USERPROFILE');
  return [
    env('SystemRoot') || 'c:\\windows', env('ProgramFiles'), env('ProgramFiles(x86)'), env('ProgramW6432'),
    env('ProgramData'), env('CommonProgramFiles'), env('CommonProgramFiles(x86)'),
    home, env('APPDATA'), env('LOCALAPPDATA'),
    home && `${home}\\desktop`, home && `${home}\\downloads`, home && `${home}\\documents`,
    home && `${home}\\onedrive`, env('LOCALAPPDATA') && `${env('LOCALAPPDATA')}\\programs`,
    env('LOCALAPPDATA') && `${env('LOCALAPPDATA')}\\temp`, env('TEMP'),
  ].filter(Boolean);
}

function ownDir() {
  return lc(path.dirname(process.execPath));
}

function validateAppPath(p, { allowPackaged = false } = {}) {
  const l = lc(p);
  if (!l.endsWith('.exe')) return 'Выберите .exe-файл программы';
  if (FORBIDDEN_NAMES.has(path.win32.basename(l))) return 'Эту программу добавить нельзя: на ней работает Windows или сам S Tunnel';
  if (isInside(l, env('SystemRoot') || 'c:\\windows')) return 'Системные программы Windows добавить нельзя';
  if (!allowPackaged && l.includes('\\windowsapps\\')) return 'Это приложение из пакета MSIX/Microsoft Store — добавьте его через список приложений';
  if (isInside(l, ownDir())) return 'Нельзя добавить сам S Tunnel';
  return '';
}

function validateAppDir(d) {
  const l = lc(d);
  if (/^[a-z]:$/.test(l)) return 'Нельзя выбрать весь диск';
  for (const b of broadDirs()) {
    if (l === b || isInside(b, l)) return `Слишком общая папка (${d}) — выберите папку конкретного приложения`;
  }
  if (isInside(l, env('SystemRoot') || 'c:\\windows')) return 'Системные папки Windows добавить нельзя';
  if (l.includes('\\windowsapps')) return 'Это приложение из пакета MSIX/Microsoft Store — добавьте его через список приложений';
  const own = ownDir();
  if (isInside(l, own) || isInside(own, l)) return 'Нельзя добавить папку самого S Tunnel';
  return '';
}

// ---- Приложения-пакеты (MSIX / Microsoft Store), например Claude Desktop ----
// Семейство пакета: "<Имя>_<PublisherId>", папка версии: "<Имя>_<версия>_<арх>__<PublisherId>".
const PFN_RE = /^([A-Za-z0-9.-]+)_([a-z0-9]{13})$/;

function validatePfn(pfn) {
  if (!PFN_RE.test(String(pfn))) return 'Некорректное имя пакета';
  if (/^(microsoft\.windows|windows\.|microsoft\.aad|microsoft\.ui|microsoft\.vclibs|microsoft\.net)/i.test(pfn)) return 'Системные пакеты Windows добавить нельзя';
  return '';
}

/** Регулярка, совпадающая с папкой ЛЮБОЙ версии пакета внутри WindowsApps. */
function pkgPathRegex(pfn) {
  const m = PFN_RE.exec(String(pfn));
  if (!m) return null;
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');
  return `\\\\windowsapps\\\\${esc(m[1].toLowerCase())}_[^\\\\]*__${m[2]}\\\\`;
}

/** Все .exe внутри папки (без перехода по ссылкам). */
function scanDir(dir, { allowPackaged = false } = {}) {
  const out = [];
  let truncated = false;
  const walk = (d, depth) => {
    if (depth > MAX_DEPTH || truncated) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile() && e.name.toLowerCase().endsWith('.exe') && !validateAppPath(full, { allowPackaged })) {
        if (out.length >= MAX_EXES_PER_APP) { truncated = true; return; }
        out.push(full);
      }
    }
  };
  walk(dir, 0);
  return { exes: out, truncated };
}

module.exports = { validateAppPath, validateAppDir, validatePfn, pkgPathRegex, scanDir, isInside, lc, MAX_EXES_PER_APP };
