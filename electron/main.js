const {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  Notification,
  Tray,
  Menu,
  nativeImage
} = require('electron');

const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const { spawn } = require('node:child_process');
const chokidar = require('chokidar');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const RENDERER_DIR = path.join(PROJECT_ROOT, 'renderer');
const APP_DIR = path.join(PROJECT_ROOT, 'app');
const WATCHED_EXTENSIONS = new Set(['.exe', '.dll']);

let mainWindow = null;
let tray = null;
let watcher = null;
let isQuitting = false;

let lastAutoScanSuccess = null;
let lastAutoScanError = null;

const activeScans = new Set();
const scannedFingerprints = new Map();

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

app.on('second-instance', () => {
  showMainWindow();
});

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 760,
    show: false,
    backgroundColor: '#0b1020',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.loadFile(path.join(RENDERER_DIR, 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow();
    return;
  }

  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }

  mainWindow.show();
  mainWindow.focus();
}

function sendToRenderer(channel, payload) {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  if (mainWindow.webContents.isLoading()) {
    mainWindow.webContents.once('did-finish-load', () => {
      if (!mainWindow || mainWindow.isDestroyed()) return;
      mainWindow.webContents.send(channel, payload);
    });
    return;
  }

  mainWindow.webContents.send(channel, payload);
}

function maybeCreateTray() {
  const trayCandidates = [
    path.join(PROJECT_ROOT, 'assets', 'tray.png'),
    path.join(PROJECT_ROOT, 'assets', 'icon.png'),
    path.join(PROJECT_ROOT, 'electron', 'tray.png')
  ];

  const iconPath = trayCandidates.find((candidate) => fs.existsSync(candidate));
  if (!iconPath) return;

  const trayIcon = nativeImage.createFromPath(iconPath);
  if (trayIcon.isEmpty()) return;

  tray = new Tray(trayIcon);
  tray.setToolTip('ExeVision');

  const menu = Menu.buildFromTemplate([
    { label: 'Open ExeVision', click: showMainWindow },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(menu);
  tray.on('click', () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      createWindow();
      return;
    }

    if (mainWindow.isVisible()) {
      mainWindow.hide();
    } else {
      showMainWindow();
    }
  });
}

function getPythonLaunchConfig() {
  const bridgeScript = path.join(APP_DIR, 'electron_bridge.py');

  if (!fs.existsSync(bridgeScript)) {
    throw new Error(`Python bridge not found: ${bridgeScript}`);
  }

  if (process.env.PYTHON_PATH) {
    return {
      command: process.env.PYTHON_PATH,
      args: [bridgeScript]
    };
  }

  if (process.platform === 'win32') {
    return {
      command: 'py',
      args: ['-3', bridgeScript]
    };
  }

  return {
    command: 'python3',
    args: [bridgeScript]
  };
}

function runAnalysis(filePath) {
  return new Promise((resolve, reject) => {
    let launch;

    try {
      launch = getPythonLaunchConfig();
    } catch (error) {
      reject(String(error.message || error));
      return;
    }

    const child = spawn(launch.command, [...launch.args, filePath], {
      cwd: PROJECT_ROOT,
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      reject(`Failed to start Python process: ${err.message}`);
    });

    child.on('close', (code) => {
      if (code !== 0) {
        reject((stderr || stdout || `Python process exited with code ${code}`).trim());
        return;
      }

      try {
        const parsed = JSON.parse(stdout);
        if (!parsed.ok) {
          reject(parsed.error || 'Unknown analysis error');
          return;
        }
        resolve(parsed.result);
      } catch (err) {
        reject(`Could not parse analyzer output: ${err.message}\n\nRaw output:\n${stdout}`);
      }
    });
  });
}

function isWatchedExecutable(filePath) {
  return WATCHED_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function ensureStableFile(filePath, checks = 3, delayMs = 1500) {
  let lastSignature = null;
  let stableCount = 0;

  while (stableCount < checks) {
    const stat = await fsp.stat(filePath);

    if (!stat.isFile()) {
      throw new Error('Target is not a file.');
    }

    const signature = `${stat.size}:${Math.trunc(stat.mtimeMs)}`;

    if (stat.size > 0 && signature === lastSignature) {
      stableCount += 1;
    } else {
      lastSignature = signature;
      stableCount = 1;
    }

    await sleep(delayMs);
  }

  return lastSignature;
}

function showSuccessNotification(filePath, result) {
  if (!Notification.isSupported()) return;

  const payload = { filePath, result };
  const notification = new Notification({
    title: 'ExeVision auto-scan complete',
    body: `${path.basename(filePath)} → ${result.score_info?.label || 'Done'} (${result.score_info?.score ?? '--'}/100)`
  });

  notification.on('click', () => {
    showMainWindow();
    sendToRenderer('autoscan:complete', payload);
  });

  notification.show();
}

function showErrorNotification(filePath, errorMessage) {
  if (!Notification.isSupported()) return;

  const payload = { filePath, error: errorMessage };
  const notification = new Notification({
    title: 'ExeVision auto-scan failed',
    body: `${path.basename(filePath)} → ${errorMessage}`
  });

  notification.on('click', () => {
    showMainWindow();
    sendToRenderer('autoscan:error', payload);
  });

  notification.show();
}

async function autoAnalyzeFile(filePath) {
  if (!isWatchedExecutable(filePath)) return;
  if (activeScans.has(filePath)) return;

  activeScans.add(filePath);

  try {
    const fingerprint = await ensureStableFile(filePath);
    if (scannedFingerprints.get(filePath) === fingerprint) {
      return;
    }

    const result = await runAnalysis(filePath);
    scannedFingerprints.set(filePath, fingerprint);

    lastAutoScanSuccess = { filePath, result };
    lastAutoScanError = null;

    sendToRenderer('autoscan:complete', lastAutoScanSuccess);
    showSuccessNotification(filePath, result);
  } catch (error) {
    const message = String(error.message || error);

    lastAutoScanError = { filePath, error: message };
    lastAutoScanSuccess = null;

    sendToRenderer('autoscan:error', lastAutoScanError);
    showErrorNotification(filePath, message);
  } finally {
    activeScans.delete(filePath);
  }
}

function startDownloadsWatcher() {
  const downloadsDir = app.getPath('downloads');

  watcher = chokidar.watch(downloadsDir, {
    persistent: true,
    ignoreInitial: true,
    depth: 0,
    awaitWriteFinish: {
      stabilityThreshold: 5000,
      pollInterval: 500
    }
  });

  watcher.on('add', (filePath) => {
    void autoAnalyzeFile(filePath);
  });

  watcher.on('change', (filePath) => {
    void autoAnalyzeFile(filePath);
  });

  watcher.on('error', (error) => {
    console.error('Watcher error:', error);
  });
}

ipcMain.handle('dialog:pickFile', async () => {
  const result = await dialog.showOpenDialog({
    title: 'Choose file to analyze',
    properties: ['openFile'],
    filters: [
      { name: 'Executables', extensions: ['exe', 'dll'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  return result.filePaths[0];
});

ipcMain.handle('analysis:run', async (_event, filePath) => {
  if (!filePath) {
    throw new Error('No file selected.');
  }

  return await runAnalysis(filePath);
});

ipcMain.handle('autoscan:getLastResult', async () => lastAutoScanSuccess);
ipcMain.handle('autoscan:getLastError', async () => lastAutoScanError);
ipcMain.handle('system:getDownloadsPath', async () => app.getPath('downloads'));

app.whenReady().then(() => {
  createWindow();
  maybeCreateTray();
  startDownloadsWatcher();

  if (app.isPackaged) {
    app.setLoginItemSettings({
      openAtLogin: true
    });
  }

  app.on('activate', () => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      createWindow();
    } else {
      showMainWindow();
    }
  });
});

app.on('before-quit', async () => {
  isQuitting = true;
  if (watcher) {
    await watcher.close();
  }
});

app.on('window-all-closed', () => {
  // Keep app alive in background for download monitoring.
});
