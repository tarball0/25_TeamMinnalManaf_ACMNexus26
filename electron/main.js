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
const RENDERER_DIR = path.join(__dirname, 'renderer');
const APP_DIR = path.join(PROJECT_ROOT, 'app');
const CNN_WEIGHTS_PATH = path.join(APP_DIR, 'models', 'ResNet-custom.pth');
const VENV_PYTHON_PATH = path.join(PROJECT_ROOT, '.venv', 'Scripts', 'python.exe');
const VENV_SITE_PACKAGES = path.join(PROJECT_ROOT, '.venv', 'Lib', 'site-packages');
const WATCHED_EXTENSIONS = new Set(['.exe', '.dll']);

let mainWindow = null;
let tray = null;
let watcher = null;
let isQuitting = false;

let lastAutoScanSuccess = null;
let lastAutoScanError = null;
let hasShownBackgroundHint = false;

const activeScans = new Set();
const scannedFingerprints = new Map();
const scanHistory = [];
const MAX_HISTORY_ITEMS = 100;

function getHistoryFilePath() {
  return path.join(app.getPath('userData'), 'scan-history.json');
}

async function loadScanHistory() {
  try {
    const raw = await fsp.readFile(getHistoryFilePath(), 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      scanHistory.splice(0, scanHistory.length, ...parsed);
    }
  } catch (error) {
    if (error && error.code !== 'ENOENT') {
      console.error('Could not load scan history:', error);
    }
  }
}

async function persistScanHistory() {
  try {
    await fsp.mkdir(app.getPath('userData'), { recursive: true });
    await fsp.writeFile(getHistoryFilePath(), JSON.stringify(scanHistory, null, 2), 'utf8');
  } catch (error) {
    console.error('Could not persist scan history:', error);
  }
}

function sanitizeHistoryResult(result) {
  if (!result) return null;

  return {
    file_name: result.file_name,
    timestamp: result.timestamp,
    explanation: result.explanation,
    image_info: result.image_info,
    pe_info: result.pe_info,
    cnn_info: result.cnn_info,
    score_info: result.score_info
  };
}

function recordHistory(entry) {
  scanHistory.unshift(entry);

  if (scanHistory.length > MAX_HISTORY_ITEMS) {
    scanHistory.length = MAX_HISTORY_ITEMS;
  }

  void persistScanHistory();
  sendToRenderer('history:updated', scanHistory);
}

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

  // Hide to background instead of closing - app continues monitoring
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();

      if (!hasShownBackgroundHint) {
        hasShownBackgroundHint = true;
        showBackgroundNotification();
      }
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
  let trayIcon = iconPath ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();

  if (trayIcon.isEmpty()) {
    const svg = `
      <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
        <rect width="64" height="64" rx="16" fill="#10213a"/>
        <path d="M32 10L48 18V30C48 41 41 50 32 54C23 50 16 41 16 30V18L32 10Z" fill="#6ea8fe"/>
        <path d="M32 18L42 23V30C42 38 37 44 32 47C27 44 22 38 22 30V23L32 18Z" fill="#08101c"/>
      </svg>
    `.trim();
    trayIcon = nativeImage.createFromDataURL(`data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`);
  }

  if (trayIcon.isEmpty()) return;

  tray = new Tray(trayIcon);
  tray.setToolTip('Minnalize');

  const menu = Menu.buildFromTemplate([
    { label: 'Open Minnalize', click: showMainWindow },
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

function showBackgroundNotification() {
  if (!Notification.isSupported()) return;

  const notification = new Notification({
    title: 'Minnalize is still running',
    body: 'The window was hidden. Downloads monitoring continues in the background.'
  });

  notification.on('click', showMainWindow);
  notification.show();
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

  // Prefer the project virtualenv so the Python bridge uses the same
  // interpreter that already has torch/torchvision installed.
  if (fs.existsSync(VENV_PYTHON_PATH)) {
    return {
      command: VENV_PYTHON_PATH,
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
    title: 'Minnalize auto-scan complete',
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
    title: 'Minnalize auto-scan failed',
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
    recordHistory({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      filePath,
      fileName: path.basename(filePath),
      timestamp: new Date().toISOString(),
      source: 'automatic',
      status: 'success',
      result: sanitizeHistoryResult(result)
    });

    sendToRenderer('autoscan:complete', lastAutoScanSuccess);
    showSuccessNotification(filePath, result);
  } catch (error) {
    const message = String(error.message || error);

    lastAutoScanError = { filePath, error: message };
    lastAutoScanSuccess = null;
    recordHistory({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      filePath,
      fileName: path.basename(filePath),
      timestamp: new Date().toISOString(),
      source: 'automatic',
      status: 'error',
      error: message
    });

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

  try {
    const result = await runAnalysis(filePath);

    recordHistory({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      filePath,
      fileName: path.basename(filePath),
      timestamp: new Date().toISOString(),
      source: 'manual',
      status: 'success',
      result: sanitizeHistoryResult(result)
    });

    return result;
  } catch (error) {
    const message = String(error.message || error);

    recordHistory({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      filePath,
      fileName: path.basename(filePath),
      timestamp: new Date().toISOString(),
      source: 'manual',
      status: 'error',
      error: message
    });

    throw error;
  }
});

ipcMain.handle('autoscan:getLastResult', async () => lastAutoScanSuccess);
ipcMain.handle('autoscan:getLastError', async () => lastAutoScanError);
ipcMain.handle('system:getDownloadsPath', async () => app.getPath('downloads'));
ipcMain.handle('system:getCnnStatus', async () => {
  const hasCustomWeights = fs.existsSync(CNN_WEIGHTS_PATH);
  const hasTorchFallback =
    fs.existsSync(path.join(VENV_SITE_PACKAGES, 'torch')) &&
    fs.existsSync(path.join(VENV_SITE_PACKAGES, 'torchvision'));

  return {
    available: hasCustomWeights || hasTorchFallback,
    mode: hasCustomWeights ? 'custom' : hasTorchFallback ? 'fallback' : 'unavailable',
    expectedWeights: CNN_WEIGHTS_PATH,
    modelName: hasCustomWeights ? 'ResNet-custom' : 'resnet18'
  };
});
ipcMain.handle('history:getAll', async () => scanHistory);

app.whenReady().then(async () => {
  await loadScanHistory();
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
