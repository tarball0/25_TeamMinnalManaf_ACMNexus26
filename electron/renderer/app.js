const chooseBtn = document.getElementById('chooseBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const dropZone = document.getElementById('dropZone');
const fileName = document.getElementById('fileName');
const statusPill = document.getElementById('statusPill');

const scoreValue = document.getElementById('scoreValue');
const scoreLabel = document.getElementById('scoreLabel');
const meterBar = document.getElementById('meterBar');
const scoreSummary = document.getElementById('scoreSummary');

const resultImage = document.getElementById('resultImage');
const imagePlaceholder = document.getElementById('imagePlaceholder');

const isPe = document.getElementById('isPe');
const numSections = document.getElementById('numSections');
const avgEntropy = document.getElementById('avgEntropy');
const importsCount = document.getElementById('importsCount');

const sectionNames = document.getElementById('sectionNames');
const reasonList = document.getElementById('reasonList');
const explanationText = document.getElementById('explanationText');
const loadingOverlay = document.getElementById('loadingOverlay');

let selectedPath = null;

function basename(filePath) {
  return filePath.split(/[\\/]/).pop();
}

function fileUrl(p) {
  return `file:///${p.replace(/\\/g, '/')}`;
}

function setLoading(isLoading) {
  loadingOverlay.classList.toggle('hidden', !isLoading);
  analyzeBtn.disabled = isLoading || !selectedPath;
  chooseBtn.disabled = isLoading;
  statusPill.textContent = isLoading ? 'Analyzing' : (selectedPath ? 'Ready' : 'Idle');
}

function resetResults() {
  scoreValue.textContent = '--';
  scoreLabel.textContent = 'Waiting';
  meterBar.style.width = '0%';
  scoreSummary.textContent = 'Select a file and run analysis to see the score.';

  resultImage.style.display = 'none';
  resultImage.src = '';
  imagePlaceholder.style.display = 'block';

  isPe.textContent = '--';
  numSections.textContent = '--';
  avgEntropy.textContent = '--';
  importsCount.textContent = '--';

  sectionNames.innerHTML = '';
  reasonList.innerHTML = '';
  explanationText.textContent = 'No explanation yet';
}

function updateSelectedFile(filePath) {
  selectedPath = filePath;
  fileName.textContent = filePath ? basename(filePath) : 'No file selected';
  analyzeBtn.disabled = !filePath;
  statusPill.textContent = filePath ? 'Ready' : 'Idle';
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

function renderResult(result) {
  const peInfo = result.pe_info || {};
  const scoreInfo = result.score_info || {};
  const imageInfo = result.image_info || {};
  const cnnInfo = result.cnn_info || {};

  scoreValue.textContent = String(scoreInfo.score ?? '--');
  scoreLabel.textContent = scoreInfo.label || 'Waiting';
  meterBar.style.width = `${scoreInfo.score ?? 0}%`;

  if (scoreInfo.cnn_used) {
    scoreSummary.textContent =
      `${scoreTone(scoreInfo.score)} based on PE rules (${scoreInfo.rule_score}/100) ` +
      `with a limited CNN support bonus (+${scoreInfo.cnn_bonus ?? 0}).`;
  } else {
    scoreSummary.textContent =
      `${scoreTone(scoreInfo.score ?? 0)} based mainly on entropy, imports, PE structure, and suspicious section names.`;
  }

  isPe.textContent = peInfo.is_pe ? 'Yes' : 'No';
  numSections.textContent = String(peInfo.num_sections ?? 0);
  avgEntropy.textContent = String(peInfo.avg_section_entropy ?? 0);
  importsCount.textContent = String(peInfo.imports_count ?? 0);

  sectionNames.innerHTML = '';
  if (peInfo.section_names && peInfo.section_names.length) {
    peInfo.section_names.forEach((name) => addTag(name));
  } else {
    addTag('No sections found');
  }

  reasonList.innerHTML = '';
  if (scoreInfo.reasons && scoreInfo.reasons.length) {
    scoreInfo.reasons.forEach((reason) => addReason(reason));
  } else if (cnnInfo.available && cnnInfo.reasons && cnnInfo.reasons.length) {
    cnnInfo.reasons.forEach((reason) => addReason(`CNN: ${reason}`));
  } else {
    addReason('No major suspicious indicators were triggered by the current rules.');
  }

  explanationText.textContent = result.explanation || 'No explanation returned';

  if (imageInfo.image_path) {
    resultImage.src = fileUrl(imageInfo.image_path);
    resultImage.style.display = 'block';
    imagePlaceholder.style.display = 'none';
  }
}

chooseBtn.addEventListener('click', async () => {
  const path = await window.desktopAPI.pickFile();
  if (path) updateSelectedFile(path);
});

analyzeBtn.addEventListener('click', async () => {
  if (!selectedPath) return;

  setLoading(true);

  try {
    const result = await window.desktopAPI.runAnalysis(selectedPath);
    renderResult(result);
    statusPill.textContent = 'Complete';
  } catch (err) {
    statusPill.textContent = 'Error';
    explanationText.textContent = String(err);
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

  updateSelectedFile(file.path);
});
