const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopAPI', {
  pickFile: () => ipcRenderer.invoke('dialog:pickFile'),
  runAnalysis: (filePath) => ipcRenderer.invoke('analysis:run', filePath)
});
