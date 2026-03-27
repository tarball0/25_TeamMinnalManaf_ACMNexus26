const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopAPI', {
  pickFile: () => ipcRenderer.invoke('dialog:pickFile'),
  runAnalysis: (filePath) => ipcRenderer.invoke('analysis:run', filePath),
  getLastAutoScanResult: () => ipcRenderer.invoke('autoscan:getLastResult'),
  getLastAutoScanError: () => ipcRenderer.invoke('autoscan:getLastError'),
  getDownloadsPath: () => ipcRenderer.invoke('system:getDownloadsPath'),
  getCnnStatus: () => ipcRenderer.invoke('system:getCnnStatus'),
  getHistory: () => ipcRenderer.invoke('history:getAll'),

  onAutoScanResult: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('autoscan:complete', handler);
    return () => ipcRenderer.removeListener('autoscan:complete', handler);
  },

  onAutoScanError: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('autoscan:error', handler);
    return () => ipcRenderer.removeListener('autoscan:error', handler);
  },

  onHistoryUpdated: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('history:updated', handler);
    return () => ipcRenderer.removeListener('history:updated', handler);
  }
});
