const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('node:path');
const { spawn } = require('node:child_process');

const PROJECT_ROOT = path.join(__dirname, '..');

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1100,
    minHeight: 760,
    backgroundColor: '#0b1020',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function getPythonLaunchConfig() {
  const bridgeScript = path.join(PROJECT_ROOT, 'app', 'electron_bridge.py');

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
    const { command, args } = getPythonLaunchConfig();
    const child = spawn(command, [...args, filePath], {
      cwd: PROJECT_ROOT
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
        reject(stderr || `Python process exited with code ${code}`);
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
  return await runAnalysis(filePath);
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
