'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('stunnel', {
  init: () => ipcRenderer.invoke('get-init'),
  save: (s) => ipcRenderer.invoke('save-settings', s),
  connect: () => ipcRenderer.invoke('connect'),
  disconnect: () => ipcRenderer.invoke('disconnect'),
  leakTest: () => ipcRenderer.invoke('leak-test'),
  openEmergency: () => ipcRenderer.invoke('open-emergency'),
  onState: (cb) => ipcRenderer.on('state', (_e, d) => cb(d)),
  onLog: (cb) => ipcRenderer.on('log', (_e, d) => cb(d)),
  onToast: (cb) => ipcRenderer.on('toast', (_e, d) => cb(d)),
});
