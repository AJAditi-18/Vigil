'use strict';

function timeAgo(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function escH(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function msgBg(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, response => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve(response);
    });
  });
}

// ── Tab Debt ──────────────────────────────────────────────────────────────────
async function loadTabData() {
  const result = await chrome.storage.local.get('vigil_tabs');
  const tabs   = Object.values(result['vigil_tabs'] || {});
  const now    = Date.now();
  const dayMs  = 864e5;

  document.getElementById('total-tabs').textContent  = tabs.length;
  document.getElementById('unread-tabs').textContent = tabs.filter(t => !t.read).length;
  document.getElementById('old-tabs').textContent    = tabs.filter(t => now - t.openedAt > dayMs).length;

  const sorted = tabs.filter(t => !t.read).sort((a,b) => a.openedAt - b.openedAt).slice(0, 5);
  const list   = document.getElementById('tab-list');
  list.innerHTML = sorted.length === 0
    ? '<li class="empty">No unread tabs — well done!</li>'
    : sorted.map(t => `<li>
        <span class="tab-title">${escH(t.title || t.url)}</span>
        <span class="tab-age">Opened ${timeAgo(now - t.openedAt)}</span>
      </li>`).join('');
}

document.getElementById('cleanup-btn').addEventListener('click', async () => {
  const result  = await chrome.storage.local.get('vigil_tabs');
  const now     = Date.now();
  const dayMs   = 864e5;
  const toClose = Object.values(result['vigil_tabs'] || {})
    .filter(t => !t.read && now - t.openedAt > dayMs).map(t => t.id);
  if (!toClose.length) { alert('No old unread tabs to close!'); return; }
  for (const id of toClose) try { await chrome.tabs.remove(id); } catch {}
  loadTabData();
});

// ── Network ───────────────────────────────────────────────────────────────────
async function loadNetworkSummary() {
  const el = document.getElementById('network-summary');
  try {
    const report = await msgBg({ action: 'getNetworkReport' });
    if (!report?.domains?.length) { el.textContent = 'No requests captured yet.'; return; }
    const trackers = report.domains.filter(d => d.isTracker);
    el.innerHTML = trackers.length === 0
      ? `<span style="color:#4caf50">✓</span> ${report.domains.length} requests — no trackers.`
      : `<span style="color:#f44336">⚠</span> ${report.domains.length} requests · <b style="color:#f44336">${trackers.length} tracker${trackers.length>1?'s':''}</b>.`;
  } catch { el.textContent = 'Could not load.'; }
}

document.getElementById('network-btn').addEventListener('click', async () => {
  await msgBg({ action: 'openNetworkReport' });
  window.close();
});

// ── Clipboard Vault ───────────────────────────────────────────────────────────
async function loadCVSummary() {
  const el = document.getElementById('cv-summary');
  if (!el) return;
  try {
    const result = await msgBg({ action: 'getClipboardCount' });
    const count  = result?.count ?? 0;
    el.innerHTML = count === 0
      ? 'Vault is empty.'
      : `<span style="color:#7b8cde;font-weight:700;">${count}</span> entr${count === 1 ? 'y' : 'ies'} · auto-expires in 60 min.`;
  } catch { el.textContent = 'Could not load.'; }
}

document.getElementById('cv-btn').addEventListener('click', async () => {
  await msgBg({ action: 'openClipboardVault' });
  window.close();
});

// ── Time Machine ──────────────────────────────────────────────────────────────
async function loadTMSummary() {
  const el      = document.getElementById('tm-summary');
  const showBtn = document.getElementById('tm-show-btn');
  try {
    const summary = await msgBg({ action: 'getSnapshotSummary' });
    if (!summary || summary.count === 0) {
      el.textContent = 'No snapshots yet for this page.';
      showBtn.disabled = true; return;
    }
    if (summary.count === 1) {
      el.innerHTML = `Baseline saved <b>${timeAgo(Date.now() - summary.latestTs)}</b>. Visit again to track changes.`;
      showBtn.disabled = true; return;
    }
    let pillClass, pillLabel;
    const cs = summary.changeSize;
    if (!summary.hasChange)  { pillClass='tm-pill-none';     pillLabel='No changes'; }
    else if (cs < 5)         { pillClass='tm-pill-minor';    pillLabel='Minor';      }
    else if (cs < 25)        { pillClass='tm-pill-moderate'; pillLabel='Moderate';   }
    else                     { pillClass='tm-pill-major';    pillLabel='Major';      }
    el.innerHTML =
      `${summary.count} snapshots · last <b>${timeAgo(Date.now() - summary.latestTs)}</b>` +
      `<span class="tm-pill ${pillClass}">${pillLabel}</span>`;
  } catch { el.textContent = 'Could not load snapshot data.'; }
}

document.getElementById('tm-show-btn').addEventListener('click', async () => {
  await msgBg({ action: 'openTimeMachineOverlay' });
  window.close();
});
document.getElementById('tm-history-btn').addEventListener('click', () => openHistoryForCurrentTab());

// ── Link Scorer ───────────────────────────────────────────────────────────────
const SCORE_TIERS = [
  { min:80, label:'Safe',       color:'#4caf50' },
  { min:55, label:'Suspicious', color:'#ff9800' },
  { min:30, label:'Risky',      color:'#ff5722' },
  { min: 0, label:'Dangerous',  color:'#f44336' },
];
function scoreTier(score) { return SCORE_TIERS.find(t => score >= t.min) || SCORE_TIERS[3]; }
function severityColor(s) { return {critical:'#f44336',high:'#ff5722',medium:'#ff9800',low:'#aaa'}[s]||'#aaa'; }

async function loadLSSummary() {
  const el        = document.getElementById('ls-summary');
  const reportBtn = document.getElementById('ls-report-btn');
  try {
    const result = await msgBg({ action: 'getLinkReport' });
    const links  = result?.links ?? [];
    if (!links.length) {
      el.textContent = 'No links scored on this page yet.';
      reportBtn.disabled = true; return;
    }
    const dangerous  = links.filter(l => l.score < 30).length;
    const risky      = links.filter(l => l.score >= 30 && l.score < 55).length;
    const suspicious = links.filter(l => l.score >= 55 && l.score < 80).length;
    const safe       = links.filter(l => l.score >= 80).length;
    const parts = [];
    if (dangerous)  parts.push(`<span style="color:#f44336">☠ ${dangerous} dangerous</span>`);
    if (risky)      parts.push(`<span style="color:#ff5722">⛔ ${risky} risky</span>`);
    if (suspicious) parts.push(`<span style="color:#ff9800">⚠ ${suspicious} suspicious</span>`);
    if (safe)       parts.push(`<span style="color:#4caf50">✓ ${safe} safe</span>`);
    el.innerHTML = `${links.length} links · ` + parts.join(' · ');
    reportBtn.disabled = false;
  } catch {
    el.textContent = 'Could not load.';
    reportBtn.disabled = true;
  }
}

document.getElementById('ls-rescan-btn').addEventListener('click', async () => {
  const el = document.getElementById('ls-summary');
  el.textContent = 'Rescanning…';
  try { await msgBg({ action: 'rescanLinks' }); await loadLSSummary(); }
  catch { el.textContent = 'Rescan failed.'; }
});

document.getElementById('ls-report-btn').addEventListener('click', () => openHistoryForCurrentTab());

// ── URL Checker (paste-a-link) ────────────────────────────────────────────────
document.getElementById('ls-check-btn').addEventListener('click', checkUrl);
document.getElementById('ls-url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') checkUrl();
});

async function checkUrl() {
  const input  = document.getElementById('ls-url-input');
  const result = document.getElementById('ls-url-result');
  let url = input.value.trim();
  if (!url) return;
  // Auto-prepend https:// if missing scheme
  if (!/^https?:\/\//i.test(url) && !/^javascript:/i.test(url)) url = 'https://' + url;

  result.style.display = 'block';
  result.innerHTML = '<span style="color:#555;">Checking…</span>';

  try {
    const resp = await msgBg({ action: 'checkSingleUrl', url });
    if (resp?.error) { result.innerHTML = `<span style="color:#f44336">${escH(resp.error)}</span>`; return; }

    const t = scoreTier(resp.score);
    const paramRows = (resp.params || []).map(p =>
      `<div class="res-param">
        <span class="res-dot" style="background:${severityColor(p.severity)}"></span>
        <span>${escH(p.label)} <span style="color:#444">−${p.penalty}</span></span>
      </div>`
    ).join('');

    result.innerHTML = `
      <div style="margin-bottom:5px;">
        <span class="res-score" style="color:${t.color}">${resp.score}</span>
        <span class="res-label" style="color:${t.color}">${t.label}</span>
      </div>
      <div style="font-size:10px;color:#333;word-break:break-all;margin-bottom:6px;">${escH(resp.url)}</div>
      <div class="res-params">
        ${paramRows || '<span style="color:#4caf50;font-size:10px;">No flags beyond baseline distrust.</span>'}
      </div>`;
  } catch {
    result.innerHTML = '<span style="color:#f44336">Could not check — is a page open?</span>';
  }
}

// ── Form Shadow ───────────────────────────────────────────────────────────────
async function loadFSSummary() {
  const el = document.getElementById('fs-summary');
  try {
    const result = await msgBg({ action: 'getFormCount' });
    const count  = result?.count ?? 0;
    el.innerHTML = count === 0
      ? 'No form receipts stored yet.'
      : `<span style="color:#7b8cde;font-weight:700;">${count}</span> encrypted receipt${count === 1 ? '' : 's'} stored.`;
  } catch { el.textContent = 'Could not load.'; }
}

document.getElementById('fs-history-btn').addEventListener('click', () => openHistoryForCurrentTab());

// ── Open history deep-linked to current tab URL ──────────────────────────────
async function openHistoryForCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.runtime.sendMessage({ action: 'openHistory', url: tab?.url || '' });
  window.close();
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadTabData();
loadNetworkSummary();
loadCVSummary();
loadTMSummary();
loadLSSummary();
loadFSSummary();
// ── Privacy Score ─────────────────────────────────────────────────────────────
const SCORE_COLOR_TIERS = [
  { min: 80, label: 'Trusted',    color: '#4caf50' },
  { min: 60, label: 'Moderate',   color: '#f5c542' },
  { min: 40, label: 'Suspicious', color: '#ff9800' },
  { min:  0, label: 'Dangerous',  color: '#f44336' },
];
function psTier(score) { return SCORE_COLOR_TIERS.find(t => score >= t.min) || SCORE_COLOR_TIERS[3]; }

async function loadPrivacyScore() {
  const numEl   = document.getElementById('ps-score');
  const labelEl = document.getElementById('ps-label');
  const trendEl = document.getElementById('ps-trend');
  const summEl  = document.getElementById('ps-summary');
  try {
    const result = await msgBg({ action: 'getPrivacyScore' });
    if (!result) {
      numEl.textContent   = '—';
      labelEl.textContent = 'No data yet';
      summEl.textContent  = 'Browse a page for a score to appear.';
      return;
    }
    const t = psTier(result.score);
    numEl.textContent    = result.score;
    numEl.style.color    = t.color;
    labelEl.textContent  = t.label;
    labelEl.style.color  = t.color;
    document.getElementById('ps-section').style.borderLeftColor = t.color;

    const issues = (result.breakdown || []).filter(b => b.deduct > 0);
    summEl.innerHTML = issues.length === 0
      ? '<span style="color:#4caf50">No issues found on this page.</span>'
      : issues.map(b => `<span style="color:#aaa;font-size:10px;">−${b.deduct} ${escH(b.label)}</span>`).join('<br>');

    if (result.historyCount > 1) {
      trendEl.textContent = `${result.historyCount} visits tracked`;
    }
  } catch {
    numEl.textContent   = '—';
    labelEl.textContent = 'Could not load';
  }
}

document.getElementById('ps-btn').addEventListener('click', async () => {
  await msgBg({ action: 'openPrivacyScore' });
  window.close();
});

loadPrivacyScore();