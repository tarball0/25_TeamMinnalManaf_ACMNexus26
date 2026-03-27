function renderResult(result) {
  const peInfo = result.pe_info || {};
  const scoreInfo = result.score_info || {};
  const imageInfo = result.image_info || {};
  const cnnInfo = result.cnn_info || {};

  scoreValue.textContent = String(scoreInfo.score ?? '--');
  scoreLabel.textContent = scoreInfo.label || 'Waiting';
  meterBar.style.width = `${scoreInfo.score ?? 0}%`;

  if (cnnInfo.available && scoreInfo.blend_mode === 'cnn_primary') {
    const cnnWeight = Math.round((scoreInfo.cnn_weight ?? 0.75) * 100);
    const peWeight = Math.round((scoreInfo.pe_weight ?? 0.25) * 100);
    const top1 = Math.round((cnnInfo.top1_confidence ?? 0) * 100);

    scoreSummary.textContent =
      `${scoreTone(scoreInfo.score ?? 0)} from CNN-primary fusion ` +
      `(${cnnWeight}% CNN, ${peWeight}% PE). ` +
      `CNN visual score: ${cnnInfo.visual_score ?? 0}/100, top confidence: ${top1}%.`;
  } else {
    scoreSummary.textContent =
      `${scoreTone(scoreInfo.score ?? 0)} based mainly on PE structure because the CNN was unavailable.`;
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

window.desktopAPI.onAutoScanResult?.(({ filePath, result }) => {
  selectedPath = filePath;
  fileName.textContent = basename(filePath);
  renderResult(result);
  statusPill.textContent = 'Auto-scanned';
});

window.desktopAPI.onAutoScanError?.(({ filePath, error }) => {
  selectedPath = filePath;
  fileName.textContent = basename(filePath);
  explanationText.textContent = `Auto-scan failed:\n${error}`;
  statusPill.textContent = 'Auto-scan error';
});
