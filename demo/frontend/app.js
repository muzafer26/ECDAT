// ECDAT — Guided Demo-First Prototype Controller
// Manages 3 top-level sections and the 8-step "Try ECDAT" journey

document.addEventListener('DOMContentLoaded', () => {
  // =========================================================================
  // STATE
  // =========================================================================
  let currentRunResult = null;
  let selectedAssetId = null;
  let selectedScenarioId = 'tc01_direct_rsa';
  let currentStep = 'choose';

  const JOURNEY_STEPS = ['choose', 'discover', 'evidence', 'risk', 'migration', 'plan', 'review', 'verify'];

  // =========================================================================
  // TOP-LEVEL SECTION NAVIGATION (Overview, How It Works, Try ECDAT)
  // =========================================================================
  const topTabs = document.querySelectorAll('.top-tab');
  const pageSections = document.querySelectorAll('.page-section');

  function switchSection(sectionId) {
    topTabs.forEach(t => {
      t.classList.toggle('active', t.dataset.section === sectionId);
    });
    pageSections.forEach(s => {
      s.classList.toggle('active', s.id === sectionId);
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  topTabs.forEach(tab => {
    tab.addEventListener('click', () => switchSection(tab.dataset.section));
  });

  // Hero CTA buttons
  const btnHeroTry = document.getElementById('btn-hero-try');
  const btnHeroHow = document.getElementById('btn-hero-how');
  const btnHowTry = document.getElementById('btn-how-try');

  if (btnHeroTry) btnHeroTry.addEventListener('click', () => switchSection('section-try'));
  if (btnHeroHow) btnHeroHow.addEventListener('click', () => switchSection('section-how'));
  if (btnHowTry) btnHowTry.addEventListener('click', () => switchSection('section-try'));

  document.querySelectorAll('.top-tab-jump').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      switchSection(link.dataset.target);
    });
  });

  // Support initial hash navigation
  if (window.location.hash === '#how') {
    switchSection('section-how');
  } else if (window.location.hash === '#try') {
    switchSection('section-try');
  }

  // =========================================================================
  // STATE MANAGEMENT & RESET
  // =========================================================================
  let activeRequestId = 0;

  function resetAnalysisState() {
    currentRunResult = null;
    selectedAssetId = null;

    const el = (id) => document.getElementById(id);

    // Reset Step 2 (Discover)
    if (el('disc-source')) el('disc-source').textContent = '—';
    if (el('disc-duration')) el('disc-duration').textContent = '—';
    if (el('disc-assets-count')) el('disc-assets-count').textContent = '—';
    if (el('disc-priority')) el('disc-priority').textContent = '—';
    if (el('disc-asset-card')) {
      el('disc-asset-card').innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 13.5px;">Awaiting analysis. Select a scenario above and click "Run ECDAT Analysis →".</div>';
    }

    // Reset Step 3 (Evidence)
    if (el('ev-code-file')) el('ev-code-file').textContent = '—';
    if (el('ev-code-snippet')) el('ev-code-snippet').textContent = '// Awaiting scenario analysis...';
    if (el('ev-summary-grid')) {
      el('ev-summary-grid').innerHTML = '<div style="padding: 16px; color: var(--text-muted); font-size: 13px;">Awaiting analysis...</div>';
    }
    if (el('ev-provenance-stepper')) el('ev-provenance-stepper').innerHTML = '';
    if (el('ev-ni-title')) el('ev-ni-title').textContent = 'Provenance Node Inspector';
    if (el('ev-ni-content')) el('ev-ni-content').textContent = '{\n  "status": "awaiting_analysis"\n}';

    // Reset Step 4 (Risk)
    if (el('risk-known-list')) el('risk-known-list').innerHTML = '<li style="color: var(--text-muted);">Awaiting analysis...</li>';
    if (el('risk-unknown-list')) el('risk-unknown-list').innerHTML = '<li style="color: var(--text-muted);">Awaiting analysis...</li>';
    if (el('risk-explanation')) el('risk-explanation').textContent = 'Run scenario analysis to view risk assessment.';
    if (el('risk-dims-grid')) el('risk-dims-grid').innerHTML = '';
    if (el('risk-context-grid')) el('risk-context-grid').innerHTML = '';
    if (el('risk-rules-list')) el('risk-rules-list').innerHTML = '';

    // Reset Step 5 (Migration)
    if (el('mig-from')) el('mig-from').textContent = '—';
    if (el('mig-from-risk')) el('mig-from-risk').textContent = '';
    if (el('mig-status')) el('mig-status').textContent = '—';
    if (el('mig-to')) el('mig-to').textContent = '—';
    if (el('mig-to-standard')) el('mig-to-standard').textContent = '';
    if (el('mig-role-note')) el('mig-role-note').innerHTML = '';
    if (el('mig-hybrid-card')) el('mig-hybrid-card').innerHTML = '';
    if (el('mig-target-details')) el('mig-target-details').innerHTML = '';
    if (el('mig-agility-card')) el('mig-agility-card').innerHTML = '';

    // Reset Step 6 (Plan)
    if (el('plan-milestone-card')) {
      el('plan-milestone-card').innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 13px;">No milestone active. Run analysis first.</div>';
    }
    if (el('plan-all-milestones')) el('plan-all-milestones').innerHTML = '';

    // Reset Step 7 (Review)
    if (el('review-gate-card')) {
      el('review-gate-card').innerHTML = '<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 13px;">No review gate active. Run analysis first.</div>';
    }
    if (el('review-all-gates')) el('review-all-gates').innerHTML = '';

    // Reset lifecycle tracker
    const trackerContainer = el('tracker-container');
    if (trackerContainer) trackerContainer.style.display = 'none';
    if (el('alt-asset-name')) el('alt-asset-name').textContent = 'Selected Asset: None';
    if (el('alt-priority-pill')) {
      el('alt-priority-pill').textContent = '—';
      el('alt-priority-pill').className = 'badge-priority info';
    }

    // Reset stepper indicator states so unanalyzed steps cannot be jumped to
    journeyIndicators.forEach(ind => {
      ind.classList.remove('active', 'completed');
      if (ind.dataset.step === 'choose') {
        ind.classList.add('active');
      }
    });
  }

  // =========================================================================
  // JOURNEY STEP NAVIGATION (8-step guided flow)
  // =========================================================================
  const journeyIndicators = document.querySelectorAll('.journey-step-indicator');
  const journeyPanels = document.querySelectorAll('.journey-panel');

  function goToStep(stepName) {
    const stepIndex = JOURNEY_STEPS.indexOf(stepName);
    if (stepIndex === -1) return;

    // Guard: Prevent advancing to analysis steps if analysis has not been executed
    if (stepName !== 'choose' && !currentRunResult) {
      goToStep('choose');
      return;
    }

    currentStep = stepName;

    // Update tracker container display & active step
    const trackerContainer = document.getElementById('tracker-container');
    if (trackerContainer) {
      if (stepName === 'choose' || !currentRunResult) {
        trackerContainer.style.display = 'none';
      } else {
        trackerContainer.style.display = 'block';
        document.querySelectorAll('.alt-stage').forEach(stage => {
          stage.classList.toggle('current-step', stage.dataset.stage === stepName);
        });
      }
    }

    // Update indicators
    journeyIndicators.forEach(ind => {
      const indStep = ind.dataset.step;
      const indIndex = JOURNEY_STEPS.indexOf(indStep);

      ind.classList.remove('active', 'completed');
      if (indStep === stepName) {
        ind.classList.add('active');
      } else if (indIndex < stepIndex) {
        ind.classList.add('completed');
      }
    });

    // Show correct panel
    journeyPanels.forEach(panel => {
      panel.classList.toggle('active', panel.id === `step-${stepName}`);
    });

    // Scroll journey bar into view smoothly
    const bar = document.getElementById('journey-bar');
    if (bar) {
      bar.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  // Make completed indicators clickable
  journeyIndicators.forEach(ind => {
    ind.addEventListener('click', () => {
      if (ind.classList.contains('completed')) {
        goToStep(ind.dataset.step);
      }
    });
  });

  // Next / Back buttons
  document.querySelectorAll('.btn-next').forEach(btn => {
    btn.addEventListener('click', () => {
      const next = btn.dataset.next;
      if (next) goToStep(next);
    });
  });

  document.querySelectorAll('.btn-back').forEach(btn => {
    btn.addEventListener('click', () => {
      const prev = btn.dataset.prev;
      if (prev) goToStep(prev);
    });
  });

  // =========================================================================
  // SINGLE DEMO PROJECT EXPERIENCE CONTROLLER
  // =========================================================================
  let uploadedFile = null;
  let isUsingBuiltinSample = false;

  const demoDropzone = document.getElementById('demo-dropzone');
  const demoFileInput = document.getElementById('demo-file-input');
  const btnChooseFile = document.getElementById('btn-choose-file');
  const dzPromptText = document.getElementById('dz-prompt-text');
  const dzSelectedDisplay = document.getElementById('dz-selected-display');
  const dzFilenameText = document.getElementById('dz-filename-text');
  const btnClearUpload = document.getElementById('btn-clear-upload');
  const inputValidationMsg = document.getElementById('input-validation-msg');
  const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const runBtnText = document.getElementById('run-btn-text');
  const runSpinner = document.getElementById('run-spinner');
  const btnUseBuiltinSample = document.getElementById('btn-use-builtin-sample');
  const btnInspectSample = document.getElementById('btn-inspect-sample');
  const sampleInspectionBox = document.getElementById('sample-inspection-box');
  const btnCloseInspection = document.getElementById('btn-close-inspection');
  const btnRestart = document.getElementById('btn-restart');

  function showValidationError(msg) {
    if (inputValidationMsg) {
      inputValidationMsg.textContent = msg;
      inputValidationMsg.classList.remove('hidden');
    }
  }

  function clearValidationError() {
    if (inputValidationMsg) {
      inputValidationMsg.textContent = '';
      inputValidationMsg.classList.add('hidden');
    }
  }

  function updateInputControls() {
    const hasProject = (uploadedFile !== null || isUsingBuiltinSample);
    if (btnRunAnalysis) {
      btnRunAnalysis.disabled = !hasProject;
      if (hasProject) {
        btnRunAnalysis.removeAttribute('title');
      } else {
        btnRunAnalysis.setAttribute('title', 'Select or load a project to begin analysis');
      }
    }
  }

  function handleFileSelection(file) {
    clearValidationError();
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (ext !== '.zip' && ext !== '.java') {
      showValidationError('Unsupported file format. The bounded demo adapter accepts Java source files (.java) or sample project archives (.zip).');
      return;
    }
    // Clean reset previous downstream results on new file selection
    resetAnalysisState();

    uploadedFile = file;
    isUsingBuiltinSample = false;
    if (dzPromptText) dzPromptText.classList.add('hidden');
    if (dzSelectedDisplay) dzSelectedDisplay.classList.remove('hidden');
    if (dzFilenameText) dzFilenameText.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    updateInputControls();
  }

  function setBuiltinSample() {
    clearValidationError();
    resetAnalysisState();
    uploadedFile = null;
    isUsingBuiltinSample = true;
    if (demoFileInput) demoFileInput.value = '';
    if (dzPromptText) dzPromptText.classList.add('hidden');
    if (dzSelectedDisplay) dzSelectedDisplay.classList.remove('hidden');
    if (dzFilenameText) dzFilenameText.textContent = 'Selected: ECDAT-Demo-Application.zip (Built-in Sample)';
    updateInputControls();
  }

  function clearFileSelection() {
    uploadedFile = null;
    isUsingBuiltinSample = false;
    if (demoFileInput) demoFileInput.value = '';
    if (dzPromptText) dzPromptText.classList.remove('hidden');
    if (dzSelectedDisplay) dzSelectedDisplay.classList.add('hidden');
    if (dzFilenameText) dzFilenameText.textContent = '';
    clearValidationError();
    resetAnalysisState();
    updateInputControls();
  }

  if (demoDropzone && demoFileInput) {
    demoDropzone.addEventListener('click', (e) => {
      if (e.target !== btnClearUpload) {
        demoFileInput.click();
      }
    });

    if (btnChooseFile) {
      btnChooseFile.addEventListener('click', (e) => {
        e.stopPropagation();
        demoFileInput.click();
      });
    }

    demoDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      demoDropzone.classList.add('dragover');
    });

    demoDropzone.addEventListener('dragleave', () => {
      demoDropzone.classList.remove('dragover');
    });

    demoDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      demoDropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });

    demoFileInput.addEventListener('change', () => {
      if (demoFileInput.files && demoFileInput.files.length > 0) {
        handleFileSelection(demoFileInput.files[0]);
      }
    });
  }

  if (btnClearUpload) {
    btnClearUpload.addEventListener('click', (e) => {
      e.stopPropagation();
      clearFileSelection();
    });
  }

  if (btnUseBuiltinSample) {
    btnUseBuiltinSample.addEventListener('click', () => {
      setBuiltinSample();
    });
  }

  if (btnInspectSample && sampleInspectionBox) {
    btnInspectSample.addEventListener('click', () => {
      sampleInspectionBox.classList.toggle('hidden');
    });
  }

  if (btnCloseInspection && sampleInspectionBox) {
    btnCloseInspection.addEventListener('click', () => {
      sampleInspectionBox.classList.add('hidden');
    });
  }

  if (btnRestart) {
    btnRestart.addEventListener('click', () => {
      resetAnalysisState();
      clearFileSelection();
      goToStep('choose');
    });
  }

  // =========================================================================
  // HEALTH CHECK
  // =========================================================================
  fetch('/api/health')
    .then(r => r.json())
    .then(data => {
      const badge = document.getElementById('core-status-badge');
      if (badge && data.status === 'healthy') {
        badge.innerHTML = '<span class="core-dot"></span> Core Engine Online';
      }
    })
    .catch(err => console.warn('Health check:', err));

  // =========================================================================
  // RUN ANALYSIS — SINGLE PRIMARY EXPERIENCE
  // =========================================================================
  if (btnRunAnalysis) {
    btnRunAnalysis.addEventListener('click', async () => {
      clearValidationError();

      if (!uploadedFile && !isUsingBuiltinSample) {
        showValidationError('Add a demonstration project to begin.');
        resetAnalysisState();
        return;
      }

      const requestId = ++activeRequestId;
      btnRunAnalysis.disabled = true;
      if (runBtnText) runBtnText.textContent = 'Running Bounded Discovery...';
      if (runSpinner) runSpinner.classList.remove('hidden');

      // Clear any previous state before starting
      resetAnalysisState();

      try {
        let resp;
        if (uploadedFile) {
          const formData = new FormData();
          formData.append('file', uploadedFile);
          resp = await fetch('/api/demo-project/analyze', {
            method: 'POST',
            body: formData,
          });
        } else if (isUsingBuiltinSample) {
          resp = await fetch('/api/demo-project/analyze?sample=true', {
            method: 'POST',
          });
        }

        const data = await resp.json();

        if (!resp.ok) {
          const errMsg = data.error || data.error_message || `HTTP ${resp.status}: ${resp.statusText}`;
          throw new Error(errMsg);
        }

        if (requestId !== activeRequestId) return;

        currentRunResult = data;
        selectedScenarioId = 'demo_project';

        // Select primary asset (prefer RSA for canonical single-asset lifecycle)
        if (data.assets && data.assets.length > 0) {
          const rsaAsset = data.assets.find(a => a.algorithm === 'RSA' || a.family === 'RSA');
          selectedAssetId = rsaAsset ? rsaAsset.asset_id : data.assets[0].asset_id;
        } else {
          selectedAssetId = null;
        }

        renderDiscoverStep(data);
        renderEvidenceStep(data);
        renderRiskStep(data);
        renderMigrationStep(data);
        renderPlanStep(data);
        renderReviewStep(data);
        renderLifecycleTracker(data);

        goToStep('discover');

      } catch (err) {
        if (requestId === activeRequestId) {
          console.error('Demo project analysis error:', err);
          resetAnalysisState();
          goToStep('choose');
          showValidationError(`Analysis error: ${err.message}`);
        }
      } finally {
        if (requestId === activeRequestId) {
          updateInputControls();
          if (runBtnText) runBtnText.textContent = 'Analyze Project →';
          if (runSpinner) runSpinner.classList.add('hidden');
        }
      }
    });
  }

  // =========================================================================
  // PRESERVED CONTROLLED SCENARIOS RUNNER (Internal regression support)
  // =========================================================================
  async function runControlledScenario(selectedScenarioId) {
    const isSwitch = (selectedScenarioId !== currentScenarioId);
    if (isSwitch) {
      resetAnalysisState();
    }
    return fetch(`/api/scenarios/${selectedScenarioId}/run`, { method: 'POST' });
  }

  // HELPER: Format display strings
  // =========================================================================
  function formatSource(scenarioId) {
    const map = {
      'tc01_direct_rsa': 'DirectRSAKeyGen.java',
      'tc02_symmetric_aes': 'DirectAESCipher.java',
      'tc06_ed25519': 'DirectEd25519Signature.java',
      'demo_project': 'ECDAT-Demo-Application',
    };
    return map[scenarioId] || scenarioId;
  }

  function getAsset() {
    if (!currentRunResult || !currentRunResult.assets) return null;
    return currentRunResult.assets.find(a => a.asset_id === selectedAssetId) || currentRunResult.assets[0] || null;
  }

  function priorityClass(tier) {
    if (!tier) return 'info';
    if (tier.includes('CRITICAL')) return 'critical';
    if (tier.includes('HIGH')) return 'critical';
    if (tier.includes('REVIEW')) return 'review';
    if (tier.includes('MEDIUM')) return 'review';
    if (tier.includes('LOW') || tier.includes('INFORMATIONAL')) return 'info';
    if (tier.includes('OUT_OF_SCOPE')) return 'out-of-scope';
    return 'info';
  }

  function renderLifecycleTracker(data) {
    const asset = getAsset();
    const trackerContainer = document.getElementById('tracker-container');
    if (!trackerContainer || !asset) return;

    const el = (id) => document.getElementById(id);
    if (el('alt-asset-name')) {
      el('alt-asset-name').textContent = `${asset.algorithm} (${asset.role}) — ${asset.location_display}`;
    }
    if (el('alt-priority-pill')) {
      const pill = el('alt-priority-pill');
      pill.textContent = asset.priority_tier || 'N/A';
      pill.className = `badge-priority ${priorityClass(asset.priority_tier)}`;
    }
    if (el('alt-st-discover')) el('alt-st-discover').textContent = `${asset.algorithm} observed`;
    if (el('alt-st-evidence')) el('alt-st-evidence').textContent = asset.location_display || 'Observed source';
    if (el('alt-st-understand')) el('alt-st-understand').textContent = `${asset.role} (${asset.family})`;
    if (el('alt-st-risk')) {
      el('alt-st-risk').textContent = asset.quantum_exposure_class || asset.risk_category || 'Assessed';
    }
    if (el('alt-st-migration')) {
      const target = (asset.candidate_targets && asset.candidate_targets.length > 0)
        ? asset.candidate_targets[0]
        : (asset.pqc_mapping_status || 'N/A');
      el('alt-st-migration').textContent = target;
    }
    if (el('alt-st-plan')) {
      const hasMilestone = data && data.migration_summary && data.migration_summary.milestones && data.migration_summary.milestones.length > 0;
      el('alt-st-plan').textContent = hasMilestone ? data.migration_summary.milestones[0].milestone_id : 'Scheduled';
    }
    if (el('alt-st-review')) {
      el('alt-st-review').textContent = asset.requires_human_review ? 'Human Review Gate' : 'Pre-approved';
    }
    if (el('alt-st-verify')) {
      el('alt-st-verify').textContent = 'Continuous Diff (Phase 9)';
    }
  }

  // =========================================================================
  // STEP 2: DISCOVER — Render discovery results
  // =========================================================================
  function renderDiscoverStep(data) {
    const el = (id) => document.getElementById(id);

    if (el('disc-source')) el('disc-source').textContent = formatSource(data.scenario_id);
    if (el('disc-duration')) el('disc-duration').textContent = `${data.execution_time_ms || 0} ms`;
    if (el('disc-assets-count')) el('disc-assets-count').textContent = `${(data.assets || []).length} asset(s)`;

    const primaryAsset = data.assets && data.assets.length > 0 ? data.assets[0] : null;
    if (el('disc-priority')) el('disc-priority').textContent = primaryAsset?.priority_tier || 'N/A';

    const container = el('disc-asset-card');
    if (!container) return;

    if (!data.assets || data.assets.length === 0) {
      container.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">
        Zero cryptographic assets detected. This does not certify cryptographic safety.
      </div>`;
      return;
    }

    container.innerHTML = '';
    data.assets.forEach(asset => {
      const targets = (asset.candidate_targets && asset.candidate_targets.length > 0)
        ? asset.candidate_targets.join(', ')
        : (asset.pqc_mapping_status || 'N/A');

      const reviewHtml = asset.requires_human_review
        ? '<span class="badge-review">Review Required</span>'
        : '';

      const row = document.createElement('div');
      row.className = `asset-row${asset.asset_id === selectedAssetId ? ' selected' : ''}`;
      row.innerHTML = `
        <div class="asset-info">
          <span class="asset-family-badge">${asset.family}</span>
          <div class="asset-detail">
            <span class="asset-name">${asset.algorithm} — ${asset.role}</span>
            <span class="asset-location">${asset.location_display}</span>
          </div>
        </div>
        <div class="asset-badges">
          <span class="badge-priority ${priorityClass(asset.priority_tier)}">${asset.priority_tier || 'N/A'}</span>
          ${reviewHtml}
        </div>
      `;

      row.addEventListener('click', () => {
        selectedAssetId = asset.asset_id;
        container.querySelectorAll('.asset-row').forEach(r => r.classList.remove('selected'));
        row.classList.add('selected');
        // Re-render downstream
        renderEvidenceStep(data);
        renderRiskStep(data);
        renderMigrationStep(data);
        renderPlanStep(data);
        renderReviewStep(data);
        renderLifecycleTracker(data);
      });

      container.appendChild(row);
    });
  }

  // =========================================================================
  // STEP 3: EVIDENCE
  // =========================================================================
  function renderEvidenceStep(data) {
    const asset = getAsset();
    if (!asset) return;

    const el = (id) => document.getElementById(id);

    // Code snippet
    if (el('ev-code-file')) el('ev-code-file').textContent = asset.location_display;

    const firstEvId = asset.evidence_ids && asset.evidence_ids.length > 0 ? asset.evidence_ids[0] : null;
    const ev = (data.evidence_records || []).find(e => e.evidence_id === firstEvId);

    if (el('ev-code-snippet')) {
      if (ev && ev.code_snippet) {
        el('ev-code-snippet').textContent = ev.code_snippet;
      } else if (asset.family === 'RSA') {
        el('ev-code-snippet').textContent = `// ${asset.location_display}\nKeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");\n// Key size unevidenced in source pattern match; ECDAT fails closed per R-RISK-06.`;
      } else if (asset.family === 'AES') {
        el('ev-code-snippet').textContent = `// ${asset.location_display}\nCipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\nSecretKey key = new SecretKeySpec(keyBytes, "AES");`;
      } else if (asset.family === 'EDWARDS' || asset.algorithm === 'Ed25519') {
        el('ev-code-snippet').textContent = `// ${asset.location_display}\nSignature sig = Signature.getInstance("Ed25519");`;
      } else {
        el('ev-code-snippet').textContent = `// Cryptographic instantiation observed at:\n// ${asset.location_display}`;
      }
    }

    // Evidence summary grid
    const grid = el('ev-summary-grid');
    if (grid) {
      const scannerName = ev ? `${ev.scanner_name} (v${ev.scanner_version})` : (data.scanner_name ? `${data.scanner_name} (v${data.scanner_version})` : 'DemoSourceScanner');
      const detectionMethod = ev ? ev.detection_method : 'Bounded Java Source Pattern Discovery';

      grid.innerHTML = `
        <div class="ev-item">
          <span class="ev-item-label">Discovery Scanner</span>
          <span class="ev-item-val">${scannerName}</span>
        </div>
        <div class="ev-item">
          <span class="ev-item-label">Detection Method</span>
          <span class="ev-item-val">${detectionMethod}</span>
        </div>
        <div class="ev-item">
          <span class="ev-item-label">Evidence Category</span>
          <span class="ev-item-val">${asset.asset_type} (${asset.family})</span>
        </div>
        <div class="ev-item">
          <span class="ev-item-label">Source Location</span>
          <span class="ev-item-val mono">${asset.location_display}</span>
        </div>
        <div class="ev-item">
          <span class="ev-item-label">Confidence</span>
          <span class="ev-item-val">${asset.confidence}</span>
        </div>
        <div class="ev-item">
          <span class="ev-item-label">Correlation Basis</span>
          <span class="ev-item-val">${asset.correlation_basis || 'single_source_observation'}</span>
        </div>
      `;
    }

    // Provenance chain
    renderProvenanceChain(data, asset);
  }

  function renderProvenanceChain(data, asset) {
    const stepper = document.getElementById('ev-provenance-stepper');
    if (!stepper) return;

    stepper.innerHTML = '';

    const chain = (data.provenance_chain || []).find(c =>
      c.some(n => n.entity_id === asset.asset_id)
    ) || (data.provenance_chain && data.provenance_chain[0]) || [];

    chain.forEach((node, idx) => {
      const stepEl = document.createElement('div');
      stepEl.className = 'prov-step' + (idx === 0 ? ' active-step' : '');
      stepEl.innerHTML = `
        <span class="ps-num-step">0${idx + 1}</span>
        <span class="ps-label-step">${node.step.toUpperCase().replace('_', ' ')}</span>
        <span class="ps-sub-step">${node.label}</span>
      `;

      stepEl.addEventListener('click', () => {
        stepper.querySelectorAll('.prov-step').forEach(s => s.classList.remove('active-step'));
        stepEl.classList.add('active-step');
        inspectNode(node);
      });

      stepper.appendChild(stepEl);

      if (idx < chain.length - 1) {
        const arrow = document.createElement('span');
        arrow.className = 'prov-arrow';
        arrow.innerHTML = '→';
        stepper.appendChild(arrow);
      }
    });

    // Auto-inspect second node (raw evidence) if available
    if (chain.length > 1) {
      inspectNode(chain[1]);
      const steps = stepper.querySelectorAll('.prov-step');
      if (steps[1]) {
        steps.forEach(s => s.classList.remove('active-step'));
        steps[1].classList.add('active-step');
      }
    } else if (chain.length > 0) {
      inspectNode(chain[0]);
    }
  }

  function inspectNode(node) {
    const titleEl = document.getElementById('ev-ni-title');
    const contentEl = document.getElementById('ev-ni-content');

    if (titleEl) titleEl.textContent = `${node.step.toUpperCase()} — ${node.label}`;

    const sanitized = JSON.parse(JSON.stringify(node.details || {}));
    if (typeof sanitized === 'object') {
      for (const [k, v] of Object.entries(sanitized)) {
        if (typeof v === 'string' && (v.includes('\\') || v.includes('/'))) {
          const parts = v.replace(/\\/g, '/').split('/');
          const idx = parts.findIndex(p => p.includes('product') || p.includes('benchmark'));
          if (idx !== -1) sanitized[k] = parts.slice(idx + 1).join('/');
        }
      }
    }

    if (contentEl) {
      contentEl.textContent = JSON.stringify({
        entity_id: node.entity_id,
        step: node.step,
        source_type: node.source_type,
        details: sanitized,
      }, null, 2);
    }
  }

  // =========================================================================
  // STEP 4: RISK
  // =========================================================================
  function renderRiskStep(data) {
    const asset = getAsset();
    if (!asset) return;

    // Known facts
    const knownList = document.getElementById('risk-known-list');
    if (knownList) {
      knownList.innerHTML = '';
      (asset.observed_facts || []).forEach(fact => {
        const li = document.createElement('li');
        li.textContent = fact;
        knownList.appendChild(li);
      });
      if (knownList.children.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No observed facts recorded for this asset.';
        knownList.appendChild(li);
      }
    }

    // Unknown gaps
    const unknownList = document.getElementById('risk-unknown-list');
    if (unknownList) {
      unknownList.innerHTML = '';
      const unknowns = [...(asset.missing_facts || [])];
      if (asset.key_size_bits === null && asset.family === 'RSA') {
        unknowns.unshift('Key length (modulus bits) was not established by scanner source evidence.');
        unknowns.push('Classical security strength remains INDETERMINATE without verified bit-length.');
      }
      if (unknowns.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'All algorithm parameters confirmed by source evidence.';
        unknownList.appendChild(li);
      } else {
        unknowns.forEach(gap => {
          const li = document.createElement('li');
          li.textContent = gap;
          unknownList.appendChild(li);
        });
      }
    }

    // Explanation block
    const explanation = document.getElementById('risk-explanation');
    if (explanation) {
      if (asset.classical_status === 'INDETERMINATE') {
        explanation.innerHTML = `<strong>What does this mean?</strong> ECDAT does not guess. Because the available evidence does not establish the key size, the classical security standing remains <code>INDETERMINATE</code> and the asset routes to <code>${asset.priority_tier || 'REVIEW_REQUIRED'}</code>. Human review is required before approving migration.`;
      } else if (asset.pqc_mapping_status === 'OUT_OF_SCOPE') {
        explanation.innerHTML = `<strong>What does this mean?</strong> This is a symmetric cipher. Symmetric cryptography is evaluated under Grover search resistance, not Shor polynomial factoring. ECDAT correctly classifies it as <code>OUT_OF_SCOPE</code> for public-key PQC replacement.`;
      } else {
        explanation.innerHTML = `<strong>What does this mean?</strong> ECDAT assessed this asset's risk based on its cryptographic role, quantum exposure class, and the evidence available. Priority tier: <code>${asset.priority_tier || 'N/A'}</code>.`;
      }
    }

    // Risk dimensions
    const dimsGrid = document.getElementById('risk-dims-grid');
    if (dimsGrid) {
      const dims = [
        { label: 'Priority Tier', value: asset.priority_tier || 'N/A', cls: asset.priority_tier === 'P_REVIEW_REQUIRED' ? 'warning' : 'info', desc: 'Actionable classification' },
        { label: 'Risk Category', value: asset.risk_category || 'N/A', cls: asset.risk_category === 'NEEDS_REVIEW' ? 'warning' : 'info', desc: 'Technical risk classification' },
        { label: 'Primary Cause', value: asset.primary_risk_cause || 'N/A', cls: 'info', desc: 'Root cause of risk determination' },
        { label: 'Classical Status', value: asset.classical_status || 'UNKNOWN', cls: asset.classical_status === 'INDETERMINATE' ? 'warning' : 'info', desc: 'Pre-quantum security standing' },
        { label: 'Quantum Exposure', value: asset.quantum_exposure_class || 'UNKNOWN', cls: (asset.quantum_exposure_class || '').includes('SHOR') ? 'danger' : 'info', desc: 'Post-quantum vulnerability class' },
      ];

      dimsGrid.innerHTML = dims.map(d => `
        <div class="risk-dim-card">
          <span class="rd-label">${d.label}</span>
          <span class="rd-value ${d.cls}">${d.value}</span>
          <span class="rd-desc">${d.desc}</span>
        </div>
      `).join('');
    }

    // Context (in deep dive)
    const ctxGrid = document.getElementById('risk-context-grid');
    if (ctxGrid) {
      const provenanceLabel = (asset.context_provenance === 'CONTROLLED_DEMONSTRATION_CONTEXT' || asset.context_provenance === 'CONTROLLED_SCENARIO_CONTEXT')
        ? 'CONTROLLED DEMONSTRATION CONTEXT'
        : (asset.context_provenance || 'CONTROLLED DEMONSTRATION CONTEXT');

      ctxGrid.innerHTML = `
        <div class="ctx-item ctx-provenance-highlight">
          <span class="ctx-label">Context Provenance</span>
          <span class="ctx-val">${provenanceLabel} (Simulated enterprise metadata — not discovered from source code)</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-label">System / Service</span>
          <span class="ctx-val">${asset.system ? `${asset.system} (${asset.organization || 'N/A'})` : 'Not Specified'}</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-label">Component</span>
          <span class="ctx-val">${asset.component || 'Unannotated'}</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-label">Business Criticality</span>
          <span class="ctx-val">${asset.business_criticality || 'Unassigned'}</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-label">Data Sensitivity</span>
          <span class="ctx-val">${asset.data_sensitivity ? `${asset.data_sensitivity} (${asset.data_lifetime || 'N/A'})` : 'Not Specified'}</span>
        </div>
        <div class="ctx-item">
          <span class="ctx-label">Network Exposure</span>
          <span class="ctx-val">${asset.network_exposure ? `${asset.network_exposure} [${asset.environment || 'N/A'}]` : 'Unknown'}</span>
        </div>
      `;
    }

    // Rules (in deep dive)
    const rulesList = document.getElementById('risk-rules-list');
    if (rulesList) {
      rulesList.innerHTML = '';
      (asset.triggered_rules || []).forEach(rule => {
        const card = document.createElement('div');
        card.className = 'rule-card';
        card.innerHTML = `
          <div class="rule-header">
            <span class="rule-id">${rule.rule_id}</span>
            <span class="rule-auth">${rule.authority} (${rule.section})</span>
          </div>
          <div class="rule-body">${rule.statement}</div>
        `;
        rulesList.appendChild(card);
      });

      if (asset.assumptions && asset.assumptions.length > 0) {
        const header = document.createElement('div');
        header.className = 'assumptions-header';
        header.textContent = 'Standards Compliance Assumptions:';
        rulesList.appendChild(header);

        asset.assumptions.forEach(asm => {
          const item = document.createElement('div');
          item.className = 'assumption-item';
          item.textContent = `• ${asm}`;
          rulesList.appendChild(item);
        });
      }
    }
  }

  // =========================================================================
  // STEP 5: MIGRATION
  // =========================================================================
  function renderMigrationStep(data) {
    const asset = getAsset();
    if (!asset) return;

    const el = (id) => document.getElementById(id);

    // Transform visual
    if (el('mig-from')) el('mig-from').textContent = `${asset.algorithm} (${asset.role})`;
    if (el('mig-from-risk')) el('mig-from-risk').textContent = asset.quantum_exposure_class
      ? `Vulnerable: ${asset.quantum_exposure_class}`
      : '';
    if (el('mig-status')) el('mig-status').textContent = asset.pqc_mapping_status || 'UNMAPPED';

    const targets = (asset.candidate_targets && asset.candidate_targets.length > 0)
      ? asset.candidate_targets.join(', ')
      : (asset.pqc_mapping_status === 'OUT_OF_SCOPE' ? 'Out of Scope' : 'None');
    if (el('mig-to')) el('mig-to').textContent = targets;

    if (el('mig-to-standard')) {
      if (asset.target_details && asset.target_details.length > 0) {
        el('mig-to-standard').textContent = asset.target_details[0].standard || '';
      } else {
        el('mig-to-standard').textContent = '';
      }
    }

    // Role note
    const roleNote = el('mig-role-note');
    if (roleNote) {
      if (asset.role === 'key_generation' || asset.role === 'key_exchange') {
        roleNote.innerHTML = `<strong>Role-Aware Mapping:</strong> Key establishment / key generation roles map to <code>ML-KEM (NIST FIPS 203)</code>. Digital signature roles map to <code>ML-DSA (NIST FIPS 204)</code> or <code>SLH-DSA (NIST FIPS 205)</code>. Symmetric ciphers are <code>OUT_OF_SCOPE</code>.`;
      } else if (asset.role === 'digital_signature') {
        roleNote.innerHTML = `<strong>Role-Aware Mapping:</strong> Digital signature roles map to <code>ML-DSA (NIST FIPS 204)</code> or <code>SLH-DSA (NIST FIPS 205)</code>, never to KEMs.`;
      } else if (asset.pqc_mapping_status === 'OUT_OF_SCOPE') {
        roleNote.innerHTML = `<strong>Role-Aware Mapping:</strong> Symmetric ciphers are evaluated under Grover search resistance. They are <code>OUT_OF_SCOPE</code> for public-key PQC replacement.`;
      } else {
        roleNote.innerHTML = `<strong>Role-Aware Mapping:</strong> Migration candidates depend on the observed cryptographic role.`;
      }
    }

    // Hybrid card
    const hybridCard = el('mig-hybrid-card');
    if (hybridCard) {
      if (asset.hybrid_candidates && asset.hybrid_candidates.length > 0) {
        const hc = asset.hybrid_candidates[0];
        hybridCard.innerHTML = `
          <div class="hybrid-title">${hc.scheme_name} [${hc.standards_status}]</div>
          <div class="hybrid-desc">${hc.security_property}. Applicable to: ${hc.applicability} per ${hc.standards_reference}.</div>
        `;
      } else {
        hybridCard.innerHTML = `
          <div class="hybrid-title">Hybrid Scheme: Not Applicable</div>
          <div class="hybrid-desc">Symmetric ciphers and non-transitional primitives are decoupled from public-key hybrid combiners (NIST SP 800-227 / RFC 9370).</div>
        `;
      }
    }

    // Target details (deep dive)
    const detailsEl = el('mig-target-details');
    if (detailsEl) {
      if (asset.target_details && asset.target_details.length > 0) {
        let html = '<table class="target-detail-table">';
        asset.target_details.forEach(td => {
          html += `
            <tr><th>Parameter Set</th><td><strong>${td.parameter_set}</strong></td></tr>
            <tr><th>Standard</th><td>${td.standard}</td></tr>
            <tr><th>NIST Category</th><td>${td.nist_category}</td></tr>
            <tr><th>Public Key Size</th><td class="mono">${td.public_key_bytes !== null ? td.public_key_bytes + ' bytes' : 'N/A'}</td></tr>
            <tr><th>Ciphertext/Sig Size</th><td class="mono">${td.ciphertext_or_signature_bytes !== null ? td.ciphertext_or_signature_bytes + ' bytes' : 'N/A'}</td></tr>
            <tr><th>Use Case</th><td>${td.primary_use_case}</td></tr>
            <tr><th>Rationale</th><td>${td.rationale}</td></tr>
          `;
        });
        html += '</table>';
        detailsEl.innerHTML = html;
      } else {
        detailsEl.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:13px;">No PQC target details — asset is out of scope for public-key replacement.</div>';
      }
    }

    // Agility (deep dive)
    const agilityCard = el('mig-agility-card');
    if (agilityCard) {
      agilityCard.innerHTML = `
        <div class="ag-level">Agility Level: ${asset.agility_level || 'NOT_ESTABLISHED'}</div>
        <div class="ag-desc">${(asset.agility_factors && asset.agility_factors.length > 0) ? asset.agility_factors.join('; ') : 'Algorithm instantiated via hardcoded literal. Migration requires code refactoring.'}</div>
      `;
    }
  }

  // =========================================================================
  // STEP 6: PLAN
  // =========================================================================
  function renderPlanStep(data) {
    const asset = getAsset();
    if (!asset) return;

    const milestones = data.migration_summary?.milestones || [];
    const matchingMs = milestones.find(m => (m.target_asset_ids || []).includes(asset.asset_id));

    const card = document.getElementById('plan-milestone-card');
    if (card) {
      if (matchingMs) {
        const blockers = (matchingMs.blockers && matchingMs.blockers.length > 0)
          ? matchingMs.blockers.join('; ')
          : 'None identified';

        card.innerHTML = `
          <div class="ms-header-row">
            <span class="ms-badge">${matchingMs.milestone_id}</span>
            <span class="ms-status-badge">SCHEDULE: ${data.migration_summary?.schedule_status || 'ADVISORY'}</span>
          </div>
          <h3 class="ms-title-text">${matchingMs.title}</h3>
          <p class="ms-desc-text">${matchingMs.rationale}</p>
          <div class="blocker-box">
            <div class="blocker-label">Agility Blocker</div>
            <div class="blocker-content">${blockers}</div>
          </div>
        `;
      } else {
        card.innerHTML = `
          <div style="padding:20px;color:var(--text-muted);text-align:center;">
            No milestone assigned for this specific asset in the current analysis run.
          </div>
        `;
      }
    }

    // All milestones (deep dive)
    const allMs = document.getElementById('plan-all-milestones');
    if (allMs) {
      allMs.innerHTML = '';
      if (milestones.length === 0) {
        allMs.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No milestones generated.</div>';
      } else {
        milestones.forEach(m => {
          const item = document.createElement('div');
          item.className = 'milestone-list-item';
          item.innerHTML = `
            <div class="ms-header-row">
              <span class="ms-badge">${m.milestone_id}</span>
              <span class="ms-status-badge">${data.migration_summary?.schedule_status || 'ADVISORY'}</span>
            </div>
            <h4 class="ms-title-text" style="font-size:15px;">${m.title}</h4>
            <p class="ms-desc-text" style="font-size:12.5px;">${m.rationale}</p>
            <div class="blocker-box">
              <div class="blocker-label">Blockers</div>
              <div class="blocker-content">${(m.blockers && m.blockers.length > 0) ? m.blockers.join('; ') : 'None'}</div>
            </div>
          `;
          allMs.appendChild(item);
        });
      }
    }
  }

  // =========================================================================
  // STEP 7: REVIEW
  // =========================================================================
  function renderReviewStep(data) {
    const asset = getAsset();
    if (!asset) return;

    const gates = data.migration_summary?.review_gates || [];
    const matchingGate = gates.find(g => g.asset_id === asset.asset_id);

    const card = document.getElementById('review-gate-card');
    if (card) {
      if (matchingGate && asset.requires_human_review) {
        card.style.display = 'block';
        card.innerHTML = `
          <div class="rg-header-row">
            <span class="rg-badge">Formal Review Gate (Blocking)</span>
            <span class="rg-id">${matchingGate.gate_id}</span>
          </div>
          <h3 class="rg-title">Human Verification Required Before Scheduling</h3>
          <div class="rg-grid">
            <div class="rg-item">
              <span class="rg-lbl">Gating Trigger</span>
              <span class="rg-val">${matchingGate.reason}</span>
            </div>
            <div class="rg-item">
              <span class="rg-lbl">Missing Information</span>
              <span class="rg-val warning-text">${matchingGate.missing_information}</span>
            </div>
            <div class="rg-item">
              <span class="rg-lbl">Consequence if Unresolved</span>
              <span class="rg-val danger-text">${matchingGate.consequence_if_unresolved}</span>
            </div>
            <div class="rg-item">
              <span class="rg-lbl">Required Human Action</span>
              <span class="rg-val action-text">Analyst confirmation of verified cryptographic parameters before release ticket approval.</span>
            </div>
          </div>
        `;
      } else {
        card.style.display = 'block';
        card.style.borderColor = 'var(--green-border)';
        card.style.borderLeftColor = 'var(--green)';
        card.innerHTML = `
          <div class="rg-header-row">
            <span class="rg-badge" style="background:var(--green-bg);color:var(--green);border-color:var(--green-border);">No Blocking Gate</span>
          </div>
          <h3 class="rg-title" style="color:var(--green);">No blocking review gate is active for this asset</h3>
          <p style="color:var(--text-secondary);font-size:13px;">No blocking review gate is active for this asset. Preserved parameters meet baseline policy rules, but release remains subject to human governance verification.</p>
        `;
      }
    }

    // All gates (deep dive)
    const allGates = document.getElementById('review-all-gates');
    if (allGates) {
      allGates.innerHTML = '';
      if (gates.length === 0) {
        allGates.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">No review gates in current run.</div>';
      } else {
        gates.forEach(g => {
          const item = document.createElement('div');
          item.className = 'milestone-list-item';
          item.innerHTML = `
            <div class="rg-header-row">
              <span class="rg-badge">Blocking Gate</span>
              <span class="rg-id">${g.gate_id}</span>
            </div>
            <div class="rg-grid">
              <div class="rg-item">
                <span class="rg-lbl">Asset</span>
                <span class="rg-val mono">${g.asset_id}</span>
              </div>
              <div class="rg-item">
                <span class="rg-lbl">Trigger</span>
                <span class="rg-val">${g.reason}</span>
              </div>
              <div class="rg-item">
                <span class="rg-lbl">Missing</span>
                <span class="rg-val warning-text">${g.missing_information}</span>
              </div>
            </div>
          `;
          allGates.appendChild(item);
        });
      }
    }
  }

  // =========================================================================
  // SCROLL REVEAL ANIMATIONS (IntersectionObserver — lightweight)
  // =========================================================================
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, {
    threshold: 0.12,
    rootMargin: '0px 0px -40px 0px'
  });

  document.querySelectorAll('.reveal-up, .reveal-section').forEach(el => {
    revealObserver.observe(el);
  });

  // Re-trigger reveals when switching sections (since they start hidden)
  const originalSwitchSection = switchSection;
  switchSection = function(sectionId) {
    originalSwitchSection(sectionId);
    // After section becomes visible, observe its reveal elements
    requestAnimationFrame(() => {
      const section = document.getElementById(sectionId);
      if (section) {
        section.querySelectorAll('.reveal-up, .reveal-section').forEach(el => {
          // Reset and re-observe for re-entry animation
          el.classList.remove('visible');
          revealObserver.observe(el);
        });
      }
    });
  };

  // =========================================================================
  // INITIAL SETUP
  // =========================================================================
  resetAnalysisState();
  goToStep('choose');

  // Trigger hero reveals on initial load
  requestAnimationFrame(() => {
    document.querySelectorAll('#section-overview .reveal-up').forEach(el => {
      el.classList.add('visible');
    });
  });
});
