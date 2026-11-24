'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('stunnel', {
  init: () => ipcRenderer.invoke('get-init'),
  save: (s) => ipcRenderer.invoke('save-settings', s),
  connect: () => ipcRenderer.invoke('connect'),
  disconnect: () => ipcRenderer.invoke('disconnect'),
  leakTest: () => ipcRenderer.invoke('leak-test'),
  updateCheck: () => ipcRenderer.invoke('update-check'),
  updateDownload: () => ipcRenderer.invoke('update-download'),
  updateInstall: () => ipcRenderer.invoke('update-install'),
  onUpdate: (cb) => ipcRenderer.on('update', (_e, d) => cb(d)),
  appsList: () => ipcRenderer.invoke('apps-list'),
  appsInstalled: () => ipcRenderer.invoke('apps-installed'),
  appsAddEntries: (e) => ipcRenderer.invoke('apps-add-entries', e),
  appsAddFolder: () => ipcRenderer.invoke('apps-add-folder'),
  appsAddExe: () => ipcRenderer.invoke('apps-add-exe'),
  appsRemove: (p) => ipcRenderer.invoke('apps-remove', p),
  openEmergency: () => ipcRenderer.invoke('open-emergency'),
  onState: (cb) => ipcRenderer.on('state', (_e, d) => cb(d)),
  onLog: (cb) => ipcRenderer.on('log', (_e, d) => cb(d)),
  onToast: (cb) => ipcRenderer.on('toast', (_e, d) => cb(d)),
});
