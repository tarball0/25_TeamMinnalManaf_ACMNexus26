const chooseBtn = document.getElementById('chooseBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const dropZone = document.getElementById('dropZone');
const fileName = document.getElementById('fileName');
const statusPill = document.getElementById('statusPill');
const downloadsInfo = document.getElementById('downloadsInfo');
const historyList = document.getElementById('historyList');
const cnnStatusNote = document.getElementById('cnnStatusNote');

const scoreValue = document.getElementById('scoreValue');
const scoreLabel = document.getElementById('scoreLabel');
const scoreRing = document.getElementById('scoreRing');
const meterBar = document.getElementById('meterBar');
const scoreSummary = document.getElementById('scoreSummary');

const resultImage = document.getElementById('resultImage');
const imagePlaceholder = document.getElementById('imagePlaceholder');

const isPe = document.getElementById('isPe');
const numSections = document.getElementById('numSections');
const avgEntropy = document.getElementById('avgEntropy');
const importsCount = document.getElementById('importsCount');
const signatureStatus = document.getElementById('signatureStatus');
const trustedPublisher = document.getElementById('trustedPublisher');
const signatureSubject = document.getElementById('signatureSubject');

const sectionNames = document.getElementById('sectionNames');
const reasonList = document.getElementById('reasonList');
const explanationText = document.getElementById('explanationText');
const loadingOverlay = document.getElementById('loadingOverlay');

let selectedPath = null;
let currentHistory = [];

function basename(filePath) {
  return String(filePath || '').split(/[\\/]/).pop() || 'Unknown';
}

function formatTime(timestamp) {
  if (!timestamp) return 'Unknown time';

  try {
    return new Date(timestamp).toLocaleString();
  } catch (_error) {
    return String(timestamp);
  }
}

function renderCnnStatus(status) {
  if (!cnnStatusNote) return;

  if (status?.available) {
    cnnStatusNote.classList.add('hidden');
    return;
  }

  cnnStatusNote.classList.remove('hidden');
  cnnStatusNote.textContent =
    `CNN is optional and currently unavailable. Minnalize will continue with PE-only analysis until ${status?.modelName || 'the CNN model'} weights are added at ${status?.expectedWeights || 'the expected model path'}.`;
}

function fileUrl(filePath) {
  const cleaned = String(filePath).replace(/\\/g, '/');
  return new URL(`file:///${cleaned}`).href;
}

function setLoading(isLoading) {
  loadingOverlay.classList.toggle('hidden', !isLoading);
  analyzeBtn.disabled = isLoading || !selectedPath;
  chooseBtn.disabled = isLoading;

  if (isLoading) {
    statusPill.textContent = 'Analyzing';
  } else if (statusPill.textContent === 'Analyzing') {
    statusPill.textContent = selectedPath ? 'Ready' : 'Idle';
  }
}

function resetResults() {
  scoreValue.textContent = '--';
  scoreLabel.textContent = 'Waiting';
  scoreRing?.style.setProperty('--score-angle', '0deg');
  meterBar.style.width = '0%';
  scoreSummary.textContent = 'Select a file and run analysis to see the score.';

  resultImage.style.display = 'none';
  resultImage.src = '';
  imagePlaceholder.style.display = 'block';

  isPe.textContent = '--';
  numSections.textContent = '--';
  avgEntropy.textContent = '--';
  importsCount.textContent = '--';
  signatureStatus.textContent = '--';
  trustedPublisher.textContent = '--';
  signatureSubject.textContent = 'No signature details yet';

  sectionNames.innerHTML = '';
  reasonList.innerHTML = '';
  explanationText.textContent = 'No explanation yet';
}

function updateSelectedFile(filePath, source = 'Manual') {
  selectedPath = filePath;
  fileName.textContent = filePath ? basename(filePath) : 'No file selected';
  fileName.title = filePath || '';
  analyzeBtn.disabled = !filePath;
  statusPill.textContent = filePath ? `${source} ready` : 'Idle';
  resetResults();
}

function addTag(text) {
  const el = document.createElement('span');
  el.className = 'tag';
  el.textContent = text;
  sectionNames.appendChild(el);
}

function addReason(text) {
  const li = document.createElement('li');
  li.textContent = text;
  reasonList.appendChild(li);
}

function scoreTone(score) {
  if (score >= 70) return 'High Risk';
  if (score >= 40) return 'Moderate Risk';
  return 'Low Risk';
}

function renderResult(result, source = 'Manual analysis') {
  const peInfo = result.pe_info || {};
  const scoreInfo = result.score_info || {};
  const imageInfo = result.image_info || {};
  const cnnInfo = result.cnn_info || {};
  const signatureInfo = result.signature_info || {};
  const score = Number(scoreInfo.score ?? 0);
  const clampedScore = Math.max(0, Math.min(100, score));
  const scoreAngle = `${(clampedScore / 100) * 360}deg`;

  scoreValue.textContent = String(scoreInfo.score ?? '--');
  scoreLabel.textContent = scoreInfo.label || 'Waiting';
  scoreRing?.style.setProperty('--score-angle', scoreAngle);
  meterBar.style.width = `${clampedScore}%`;

  if (cnnInfo.available && scoreInfo.blend_mode === 'unsigned_cnn_pe_70_30') {
    const cnnWeight = Math.round((scoreInfo.cnn_weight ?? 0.7) * 100);
    const peWeight = Math.round((scoreInfo.pe_weight ?? 0.3) * 100);
    const top1 = Math.round((cnnInfo.top1_confidence ?? 0) * 100);

    scoreSummary.textContent =
      `${source}: ${scoreTone(scoreInfo.score ?? 0)} from unsigned-file CNN/PE fusion ` +
      `(${cnnWeight}% CNN, ${peWeight}% PE). ` +
      `CNN visual score: ${cnnInfo.visual_score ?? 0}/100, top confidence: ${top1}%.`;
  } else if (scoreInfo.blend_mode === 'signed_pe_only') {
    scoreSummary.textContent =
      `${source}: ${scoreTone(scoreInfo.score ?? 0)} based on PE headers and signature status. ` +
      `CNN evidence is ignored because the file is signed.`;
  } else if (scoreInfo.cnn_used) {
    scoreSummary.textContent =
      `${source}: ${scoreTone(scoreInfo.score ?? 0)} using CNN and PE header scoring.`;
  } else if (cnnInfo.status === 'cnn_skipped') {
    scoreSummary.textContent =
      `${source}: ${scoreTone(scoreInfo.score ?? 0)} based on PE headers and signature status. ` +
      `CNN was skipped because ${cnnInfo.reason || 'the file is signed'}.`;
  } else {
    scoreSummary.textContent =
      `${source}: ${scoreTone(scoreInfo.score ?? 0)} based mainly on PE structure because the CNN was unavailable.`;
  }

  isPe.textContent = peInfo.is_pe ? 'Yes' : 'No';
  numSections.textContent = String(peInfo.num_sections ?? 0);
  avgEntropy.textContent = String(peInfo.avg_section_entropy ?? 0);
  importsCount.textContent = String(peInfo.imports_count ?? 0);
  signatureStatus.textContent = signatureInfo.status || 'Unavailable';
  trustedPublisher.textContent = signatureInfo.trusted_publisher ? 'Yes' : 'No';
  signatureSubject.textContent = signatureInfo.subject || signatureInfo.status_message || 'No signature details available';

  sectionNames.innerHTML = '';
  if (Array.isArray(peInfo.section_names) && peInfo.section_names.length) {
    peInfo.section_names.forEach((name) => addTag(name));
  } else {
    addTag('No sections found');
  }

  reasonList.innerHTML = '';
  if (Array.isArray(scoreInfo.reasons) && scoreInfo.reasons.length) {
    scoreInfo.reasons.forEach((reason) => addReason(reason));
  } else if (cnnInfo.available && Array.isArray(cnnInfo.reasons) && cnnInfo.reasons.length) {
    cnnInfo.reasons.forEach((reason) => addReason(`CNN: ${reason}`));
  } else {
    addReason('No major suspicious indicators were triggered by the current rules.');
  }

  explanationText.textContent = result.explanation || 'No explanation returned';

  if (imageInfo.image_path) {
    resultImage.src = fileUrl(imageInfo.image_path);
    resultImage.style.display = 'block';
    imagePlaceholder.style.display = 'none';
  } else {
    resultImage.style.display = 'none';
    resultImage.src = '';
    imagePlaceholder.style.display = 'block';
  }
}

function renderHistory(historyItems = []) {
  currentHistory = Array.isArray(historyItems) ? historyItems : [];
  historyList.innerHTML = '';

  if (!currentHistory.length) {
    const empty = document.createElement('p');
    empty.className = 'history-empty';
    empty.textContent = 'No scans yet.';
    historyList.appendChild(empty);
    return;
  }

  currentHistory.forEach((item) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'history-item';

    const score = item.result?.score_info?.score;
    const label = item.result?.score_info?.label || (item.status === 'error' ? 'Failed' : 'Scanned');

    button.innerHTML = `
      <div class="history-title-row">
        <strong>${item.fileName || basename(item.filePath)}</strong>
        <span class="history-status history-status-${item.status}">${label}</span>
      </div>
      <div class="history-meta">${item.source === 'automatic' ? 'Downloads auto-scan' : 'Manual scan'} • ${formatTime(item.timestamp)}</div>
      <div class="history-path">${item.filePath || ''}</div>
      <div class="history-summary">${item.status === 'success' ? `Score: ${score ?? '--'}/100` : item.error || 'Analysis failed'}</div>
    `;

    button.addEventListener('click', () => {
      updateSelectedFile(item.filePath, item.source === 'automatic' ? 'Auto-scan history' : 'Manual history');

      if (item.status === 'success' && item.result) {
        renderResult(item.result, item.source === 'automatic' ? 'Automatic Downloads scan history' : 'Manual scan history');
        statusPill.textContent = 'History loaded';
      } else {
        explanationText.textContent = `Previous scan failed:\n${item.error || 'Unknown error'}`;
        statusPill.textContent = 'History error';
      }
    });

    historyList.appendChild(button);
  });
}

chooseBtn.addEventListener('click', async () => {
  try {
    const pickedPath = await window.desktopAPI.pickFile();
    if (!pickedPath) return;

    updateSelectedFile(pickedPath, 'Manual');
  } catch (err) {
    statusPill.textContent = 'Error';
    explanationText.textContent = `File selection failed:\n${String(err)}`;
  }
});

analyzeBtn.addEventListener('click', async () => {
  if (!selectedPath) return;

  setLoading(true);

  try {
    const result = await window.desktopAPI.runAnalysis(selectedPath);
    renderResult(result, 'Manual analysis');
    statusPill.textContent = 'Complete';
  } catch (err) {
    statusPill.textContent = 'Error';
    explanationText.textContent = `Analysis failed:\n${String(err)}`;
    alert(`Analysis failed:\n\n${err}`);
  } finally {
    setLoading(false);
  }
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');

  const file = e.dataTransfer.files?.[0];
  if (!file) return;

  updateSelectedFile(file.path, 'Drag and drop');
});

window.desktopAPI.onAutoScanResult?.(({ filePath, result }) => {
  updateSelectedFile(filePath, 'Auto-scan');
  renderResult(result, 'Automatic Downloads scan');
  statusPill.textContent = 'Auto-scanned';
});

window.desktopAPI.onAutoScanError?.(({ filePath, error }) => {
  updateSelectedFile(filePath, 'Auto-scan');
  explanationText.textContent = `Auto-scan failed:\n${error}`;
  statusPill.textContent = 'Auto-scan error';
});

window.desktopAPI.onHistoryUpdated?.((history) => {
  renderHistory(history);
});

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const cnnStatus = await window.desktopAPI.getCnnStatus?.();
    renderCnnStatus(cnnStatus);

    const downloadsPath = await window.desktopAPI.getDownloadsPath?.();
    if (downloadsPath) {
      downloadsInfo.textContent = `Watching: ${downloadsPath}`;
      downloadsInfo.title = downloadsPath;
    }

    const history = await window.desktopAPI.getHistory?.();
    renderHistory(history);

    const lastResult = await window.desktopAPI.getLastAutoScanResult?.();
    if (lastResult?.filePath && lastResult?.result) {
      updateSelectedFile(lastResult.filePath, 'Auto-scan');
      renderResult(lastResult.result, 'Last automatic Downloads scan');
      statusPill.textContent = 'Last auto-scan';
      return;
    }

    const lastError = await window.desktopAPI.getLastAutoScanError?.();
    if (lastError?.filePath && lastError?.error) {
      updateSelectedFile(lastError.filePath, 'Auto-scan');
      explanationText.textContent = `Auto-scan failed:\n${lastError.error}`;
      statusPill.textContent = 'Last auto-scan error';
    }
  } catch (err) {
    console.error('Failed to restore auto-scan state:', err);
  }
});
