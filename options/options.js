'use strict';

// ── Diff global resolver ─────────────────────────────────────────────────────
function getDiffLib() {
  if (typeof Diff   !== 'undefined' && typeof Diff.diffSentences   === 'function') return Diff;
  if (typeof JsDiff !== 'undefined' && typeof JsDiff.diffSentences === 'function') return JsDiff;
  if (typeof Diff   !== 'undefined' && typeof Diff.diffWords       === 'function') return Diff;
  return null;
}

// ── State ─────────────────────────────────────────────────────────────────────
let urlGroups   = {};
let activeUrl   = null;
let activeTab   = 'diff';
let sortMode    = 'recent';
let searchQuery = '';

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  document.getElementById('stats-bar').textContent = 'Loading…';
  document.getElementById('url-list').innerHTML =
    '<div style="padding:20px;text-align:center;color:#333;font-size:12px;">Loading snapshots…</div>';

  if (typeof VigilDB === 'undefined') {
    showFatalError('VigilDB not loaded. Check that content/vigilDB.js is listed in options.html.');
    return;
  }
  try { await VigilDB.ready; }
  catch (err) {
    showFatalError('Database could not open: ' + err.message + '. Try reloading the extension from chrome://extensions.');
    return;
  }

  await loadAll();
  bindEvents();
  loadApiKeyStatus();
  loadGSBKeyStatus();

  // ── Deep-link: auto-select URL passed via ?url= query param ──────────────
  // background.js appends the active tab URL when opening history from the
  // popup (Time Machine, Link Scorer, Form Shadow etc.), so the panel shows
  // the right entry instead of the blank empty-state.
  const deepUrl = new URLSearchParams(location.search).get('url');
  if (deepUrl) {
    let match = Object.keys(urlGroups).find(u => u === deepUrl);
    if (!match) {
      // Strip trailing slash + query for a cleaner pathname match
      try {
        const t = new URL(deepUrl);
        const norm = t.origin + t.pathname.replace(/\/+$/, '');
        match = Object.keys(urlGroups).find(u => {
          try { const n = new URL(u); return (n.origin + n.pathname.replace(/\/+$/, '')) === norm; }
          catch { return false; }
        });
      } catch {}
    }
    if (!match) {
      // Last resort: same hostname, pick most-recently-visited entry
      try {
        const th = new URL(deepUrl).hostname.replace(/^www\./, '');
        match = Object.keys(urlGroups).find(u => {
          try { return new URL(u).hostname.replace(/^www\./, '') === th; } catch { return false; }
        });
      } catch {}
    }
    if (match) {
      selectUrl(match);
      setTimeout(() => {
        const el = document.querySelector('.url-item.active');
        if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }, 100);
    } else {
      document.getElementById('main-panel').innerHTML =
        '<div class="empty-state">' +
        '<p>No snapshots for this page yet</p>' +
        '<small>Vigil hasn\'t saved a snapshot of this page yet.' +
        ' Visit the page and wait a few seconds.</small>' +
        '</div>';
    }
  }
}

function showFatalError(msg) {
  document.getElementById('stats-bar').textContent = 'Database error';
  document.getElementById('url-list').innerHTML = `<div style="padding:20px;color:#f44336;font-size:11px;line-height:1.7;">⚠ ${escapeHtml(msg)}</div>`;
}

async function loadAll() {
  const allUrls = await VigilDB.Snapshots.getAllUrls();
  urlGroups = {};
  for (const snap of allUrls) urlGroups[snap.url] = await VigilDB.Snapshots.getAll(snap.url);
  renderStorageStats();
  renderStatsBar();
  renderUrlList();
}

// ── Storage stats ─────────────────────────────────────────────────────────────
async function renderStorageStats() {
  try {
    const stats = await VigilDB.Stats.getSummary();
    document.getElementById('storage-stats').innerHTML = `
      <span class="stat-label">Snapshots</span>      <span class="stat-value">${stats.snapshots}</span>
      <span class="stat-label">Forms logged</span>   <span class="stat-value">${stats.forms}</span>
      <span class="stat-label">Clipboard entries</span><span class="stat-value">${stats.clipboard}</span>
      <span class="stat-label">Storage used</span>   <span class="stat-value">${stats.sizeMB} MB</span>
    `;
  } catch {
    document.getElementById('storage-stats').innerHTML = `<span class="stat-label" style="grid-column:1/-1;color:#444;">Stats unavailable</span>`;
  }
}

function renderStatsBar() {
  const urlCount  = Object.keys(urlGroups).length;
  const snapCount = Object.values(urlGroups).reduce((a, b) => a + b.length, 0);
  const changed   = Object.values(urlGroups).flat().filter(s => s.changeSize > 0).length;
  document.getElementById('stats-bar').innerHTML =
    `<b>${urlCount}</b> pages &nbsp;·&nbsp; <b>${snapCount}</b> snapshots &nbsp;·&nbsp; <b>${changed}</b> changes detected`;
}

// ── URL list ──────────────────────────────────────────────────────────────────
function getSortedUrls() {
  let urls = Object.keys(urlGroups);
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    urls = urls.filter(url => {
      const title = (urlGroups[url][0]?.title || '').toLowerCase();
      return url.toLowerCase().includes(q) || title.includes(q);
    });
  }
  switch (sortMode) {
    case 'most':    urls.sort((a, b) => urlGroups[b].length - urlGroups[a].length); break;
    case 'changed': urls.sort((a, b) => Math.max(...urlGroups[b].map(s=>s.changeSize||0)) - Math.max(...urlGroups[a].map(s=>s.changeSize||0))); break;
    case 'az':      urls.sort((a, b) => (urlGroups[a][0]?.title||a).toLowerCase().localeCompare((urlGroups[b][0]?.title||b).toLowerCase())); break;
    default:        urls.sort((a, b) => (urlGroups[b][0]?.timestamp||0) - (urlGroups[a][0]?.timestamp||0));
  }
  return urls;
}

function getBadge(snaps) {
  if (snaps.length === 1) return '<span class="badge badge-new">New</span>';
  const max = Math.max(...snaps.map(s => s.changeSize || 0));
  if (max === 0)  return '<span class="badge badge-new">Unchanged</span>';
  if (max < 5)    return '<span class="badge badge-minor">Minor</span>';
  if (max < 25)   return '<span class="badge badge-moderate">Moderate</span>';
  return                  '<span class="badge badge-major">Major</span>';
}

function formatDate(ts) {
  return new Date(ts).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
}
function formatTimeAgo(ms) {
  const s=Math.floor(ms/1000); if(s<60) return `${s}s ago`;
  const m=Math.floor(s/60);   if(m<60) return `${m}m ago`;
  const h=Math.floor(m/60);   if(h<24) return `${h}h ago`;
  return `${Math.floor(h/24)}d ago`;
}
function getDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return url; }
}

function renderUrlList() {
  const list = document.getElementById('url-list');
  const urls = getSortedUrls();
  if (urls.length === 0) {
    list.innerHTML = `<div class="empty-state" style="padding:40px 20px;"><p>${searchQuery ? 'No results found' : 'No snapshots yet'}</p><small>${searchQuery ? 'Try a different search' : 'Browse some pages and Vigil will start tracking them'}</small></div>`;
    return;
  }
  list.innerHTML = urls.map(url => {
    const snaps   = urlGroups[url];
    const latest  = snaps[0];
    if (!latest) return '';
    const domain  = getDomain(url);
    const timeAgo = formatTimeAgo(Date.now() - latest.timestamp);
    const favicon = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=16`;
    return `
      <div class="url-item ${activeUrl === url ? 'active' : ''}" data-url="${encodeURIComponent(url)}">
        <div class="url-item-title">
          <img src="${favicon}" width="12" height="12" style="display:inline;vertical-align:middle;margin-right:4px;border-radius:2px;opacity:0.7;" onerror="this.style.display='none'" />
          ${escapeHtml(latest.title || domain)}
        </div>
        <div class="url-item-domain">${domain}</div>
        <div class="url-item-meta">
          <span>${timeAgo} · ${snaps.length} snapshot${snaps.length !== 1 ? 's' : ''}</span>
          ${getBadge(snaps)}
        </div>
      </div>`;
  }).join('');
  list.querySelectorAll('.url-item').forEach(el => {
    el.addEventListener('click', () => selectUrl(decodeURIComponent(el.dataset.url)));
  });
}

// ── Select URL ────────────────────────────────────────────────────────────────
function selectUrl(url) {
  activeUrl = url;
  activeTab = 'diff';
  renderUrlList();
  renderMainPanel(url);
}

// ── Main panel ────────────────────────────────────────────────────────────────
function renderMainPanel(url) {
  const snaps  = urlGroups[url];
  const latest = snaps[0];
  if (!latest) return;
  const panel  = document.getElementById('main-panel');

  const snapOptions = (selected) => snaps.map((s, i) => `
    <option value="${i}" ${i === selected ? 'selected' : ''}>
      v${snaps.length - i} — ${formatDate(s.timestamp)}${s.changeSize > 0 ? ` (${s.changeSize}% Δ)` : ' (baseline)'}
    </option>`).join('');

  panel.innerHTML = `
    <div class="main-header">
      <div class="main-header-title">${escapeHtml(latest.title || getDomain(url))}</div>
      <div class="main-header-url">${escapeHtml(url)}</div>
      <div class="version-row">
        <label>Compare:</label>
        <select id="snap-a">${snapOptions(1)}</select>
        <label style="color:#555;">→</label>
        <select id="snap-b">${snapOptions(0)}</select>
        <button class="btn btn-primary" id="btn-compare">Compare</button>
        <button class="btn" id="btn-open" title="Open in new tab">↗</button>
        <button class="btn btn-danger" id="btn-delete">Delete</button>
      </div>
    </div>
    <div class="tab-bar">
      <div class="tab ${activeTab==='diff'?'active':''}"     data-tab="diff">Diff</div>
      <div class="tab ${activeTab==='timeline'?'active':''}" data-tab="timeline">Timeline</div>
      <div class="tab ${activeTab==='raw'?'active':''}"      data-tab="raw">Raw</div>
      <div class="tab ${activeTab==='forms'?'active':''}"    data-tab="forms">Forms</div>
      <div class="tab ${activeTab==='ai'?'active':''}"       data-tab="ai">AI Summary</div>
    </div>
    <div class="content-area" id="content-area"></div>`;

  panel.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab;
      panel.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === activeTab));
      renderContent(url);
    });
  });

  panel.querySelector('#btn-compare').addEventListener('click', () => renderContent(url));
  panel.querySelector('#btn-open').addEventListener('click', () => window.open(url, '_blank'));
  panel.querySelector('#btn-delete').addEventListener('click', () => deleteUrl(url));

  renderContent(url);
}

// ── Content routing ───────────────────────────────────────────────────────────
function renderContent(url) {
  const area  = document.getElementById('content-area');
  const snaps = urlGroups[url];
  if (!area || !snaps) return;
  if (activeTab === 'timeline') { renderTimeline(area, snaps); return; }
  if (activeTab === 'raw')      { renderRaw(area, snaps); return; }
  if (activeTab === 'ai')       { renderAISummary(area, snaps, url); return; }
  if (activeTab === 'forms')    { renderForms(area, url); return; }
  renderDiff(area, snaps);
}

// ── Raw ───────────────────────────────────────────────────────────────────────
function renderRaw(area, snaps) {
  const idx  = parseInt(document.getElementById('snap-b')?.value ?? '0');
  const snap = snaps[idx];
  if (!snap) { area.innerHTML = '<div class="empty-state"><p>No snapshot selected</p></div>'; return; }
  let displayText = snap.content || '';
  try { const p = JSON.parse(displayText); if (Array.isArray(p)) displayText = p.join('\n\n'); } catch {}
  area.innerHTML = `<div class="raw-view">${escapeHtml(displayText)}</div>`;
}

// ── Diff ──────────────────────────────────────────────────────────────────────
function renderDiff(area, snaps) {
  if (snaps.length < 2) {
    area.innerHTML = `<div class="empty-state"><p>Only one snapshot saved</p><small>Visit this page again and Vigil will compare versions automatically.</small></div>`;
    return;
  }
  const idxA  = parseInt(document.getElementById('snap-a')?.value ?? '1');
  const idxB  = parseInt(document.getElementById('snap-b')?.value ?? '0');
  const snapA = snaps[idxA], snapB = snaps[idxB];
  if (!snapA || !snapB || snapA.id === snapB.id) {
    area.innerHTML = `<div class="empty-state"><p>Select two different versions to compare</p></div>`;
    return;
  }
  const older = snapA.timestamp < snapB.timestamp ? snapA : snapB;
  const newer = snapA.timestamp < snapB.timestamp ? snapB : snapA;

  function parseSentences(content) {
    try { const p = JSON.parse(content); if (Array.isArray(p)) return p; } catch {}
    return (content || '').split(/\n+/).filter(Boolean);
  }
  const oldSents = parseSentences(older.content);
  const newSents = parseSentences(newer.content);
  const diffLib  = getDiffLib();
  if (!diffLib) { area.innerHTML = `<div class="empty-state"><p>Diff library not loaded</p></div>`; return; }

  let result;
  try {
    result = typeof diffLib.diffArrays === 'function'
      ? diffLib.diffArrays(oldSents, newSents)
      : diffLib.diffSentences(older.content, newer.content);
  } catch (e) {
    area.innerHTML = `<div class="empty-state"><p>Diff failed: ${escapeHtml(e.message)}</p></div>`;
    return;
  }

  if (!result.some(p => p.added || p.removed)) {
    area.innerHTML = `<div class="empty-state"><p>No changes between these versions</p></div>`;
    return;
  }

  const added   = result.filter(p=>p.added).reduce((n,p)=>n+(Array.isArray(p.value)?p.value.length:1),0);
  const removed = result.filter(p=>p.removed).reduce((n,p)=>n+(Array.isArray(p.value)?p.value.length:1),0);
  const diffRows = result.map(part => {
    const text = Array.isArray(part.value) ? part.value.join(' ') : part.value;
    if (part.added)   return `<div class="diff-block diff-added">${escapeHtml(text.trim())}</div>`;
    if (part.removed) return `<div class="diff-block diff-removed">${escapeHtml(text.trim())}</div>`;
    const preview = text.length > 300 ? text.substring(0, 300) + '…' : text;
    return preview.trim() ? `<div class="diff-block diff-unchanged">${escapeHtml(preview)}</div>` : '';
  }).join('');

  const oldIdx = snaps.indexOf(older), newIdx = snaps.indexOf(newer);
  area.innerHTML = `
    <div class="diff-view">
      <div style="display:flex;gap:16px;margin-bottom:12px;padding:8px 12px;background:#12121f;border-radius:6px;font-size:11px;border:1px solid #1e1e3a;">
        <span>Comparing <b style="color:#7b8cde;">v${snaps.length-oldIdx}</b> <span style="color:#444;">(${formatDate(older.timestamp)})</span> → <b style="color:#7b8cde;">v${snaps.length-newIdx}</b> <span style="color:#444;">(${formatDate(newer.timestamp)})</span></span>
        <span style="color:#4caf50;margin-left:auto;">+${added} added</span>
        <span style="color:#f44336;">−${removed} removed</span>
      </div>
      ${diffRows}
    </div>`;
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function renderTimeline(area, snaps) {
  if (!snaps?.length) { area.innerHTML = `<div class="empty-state"><p>No snapshots</p></div>`; return; }
  const entries = snaps.map((snap, i) => {
    const isFirst    = i === snaps.length - 1;
    const dotClass   = isFirst ? 'timeline-dot-new' : snap.changeSize === 0 ? 'timeline-dot-new' : snap.changeSize < 5 ? 'timeline-dot-minor' : snap.changeSize < 25 ? 'timeline-dot-moderate' : 'timeline-dot-major';
    const changeLabel = isFirst ? 'First snapshot saved' : snap.changeSize === 0 ? 'No content change detected' : snap.changeSize < 5 ? `Minor change — ${snap.changeSize}%` : snap.changeSize < 25 ? `Moderate change — ${snap.changeSize}%` : `Major change — ${snap.changeSize}%`;
    return `
      <div class="timeline-entry">
        <div class="timeline-dot ${dotClass}"></div>
        <div class="timeline-content">
          <div class="timeline-header">
            <span class="timeline-date">${formatDate(snap.timestamp)}</span>
            <span style="font-size:10px;color:#333;">v${snaps.length-i} · ${snap.wordCount||0} words</span>
          </div>
          <div class="timeline-body">${changeLabel}</div>
        </div>
      </div>`;
  }).join('');
  area.innerHTML = `<div class="timeline-view">${entries}</div>`;
}

// ── Forms tab ─────────────────────────────────────────────────────────────────
async function renderForms(area, url) {
  area.innerHTML = `<div class="loading">Loading form receipts…</div>`;
  try {
    await VigilDB.ready;
    const all    = await VigilDB.Forms.getAll();
    const forUrl = all.filter(f => f.url === url);
    if (!forUrl.length) {
      area.innerHTML = `<div class="empty-state"><p>No form receipts for this page</p><small>Vigil records an encrypted receipt whenever a form is submitted on a tracked page.</small></div>`;
      return;
    }
    const rows = forUrl.map(f => {
      const hiddenTags = (f.hiddenFields || []).map(h => `<span class="form-hidden-tag">hidden: ${escapeHtml(h)}</span>`).join('');
      const fieldTags  = (f.fields || []).slice(0, 12).map(fn => `<span class="form-field-tag">${escapeHtml(fn)}</span>`).join('');
      const extra      = (f.fields||[]).length > 12 ? `<span style="font-size:10px;color:#444;">+${f.fields.length-12} more</span>` : '';
      return `
        <div class="form-entry">
          <div class="form-entry-header">
            <span class="form-entry-url" title="${escapeHtml(f.url)}">${escapeHtml(getDomain(f.url))}</span>
            <span class="form-entry-time">${formatDate(f.timestamp)}</span>
          </div>
          <div class="form-entry-meta">
            ${hiddenTags ? `<div style="margin-bottom:5px;">${hiddenTags}</div>` : ''}
            <div>${fieldTags}${extra}</div>
            <div style="margin-top:5px;font-size:10px;color:#2a2a4a;">
              ${f.fieldCount||0} field${f.fieldCount!==1?'s':''} · ${f.hasHidden?'<span style="color:#f44336;">has hidden fields</span>':'no hidden fields'} · encrypted receipt stored
            </div>
          </div>
        </div>`;
    }).join('');
    area.innerHTML = `<div class="forms-view">${rows}</div>`;
  } catch (err) {
    area.innerHTML = `<div class="empty-state"><p>Could not load form receipts</p><small>${escapeHtml(err.message)}</small></div>`;
  }
}

// ── AI Summary ────────────────────────────────────────────────────────────────
async function renderAISummary(area, snaps, url) {
  if (snaps.length < 2) {
    area.innerHTML = `<div class="empty-state"><p>Need at least 2 snapshots to summarise changes</p></div>`;
    return;
  }
  const result = await chrome.storage.sync.get('vigil_api_key');
  const apiKey = result['vigil_api_key'];
  if (!apiKey) {
    area.innerHTML = `<div class="empty-state"><p>No API key configured</p><small>Add an Anthropic API key in the sidebar to enable AI summaries.</small></div>`;
    return;
  }
  area.innerHTML = `<div style="flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:8px;color:#444;font-size:12px;padding:40px;">
    <div style="width:18px;height:18px;border:2px solid #7b8cde;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div>
    <style>@keyframes spin{to{transform:rotate(360deg);}}</style>
    Generating AI summary…</div>`;

  function parseSentences(content) {
    try { const p = JSON.parse(content); if (Array.isArray(p)) return p; } catch {}
    return (content || '').split(/\n+/).filter(Boolean);
  }
  const newer   = snaps[0], older = snaps[1];
  const oldText = parseSentences(older.content).join(' ');
  const newText = parseSentences(newer.content).join(' ');
  const domain  = getDomain(url);

  const prompt = `You are analysing changes to a webpage for a privacy-focused browser extension called Vigil.

Page: ${domain}
URL: ${url}

PREVIOUS VERSION (${formatDate(older.timestamp)}):
${oldText.substring(0, 1200)}

CURRENT VERSION (${formatDate(newer.timestamp)}):
${newText.substring(0, 1200)}

Please provide:
1. A 1–2 sentence plain-English summary of what changed
2. Whether any changes are significant for privacy, pricing, legal terms, or user rights (yes/no + brief reason)
3. Severity: Minor / Moderate / Major

Keep it concise and factual. No markdown headers.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 400, messages: [{ role: 'user', content: prompt }] })
    });
    if (!response.ok) { const err = await response.json().catch(()=>({})); throw new Error(err.error?.message || `HTTP ${response.status}`); }
    const data = await response.json();
    const text = data.content?.map(c => c.text || '').join('') || '(No response)';
    area.innerHTML = `
      <div style="padding:20px;flex:1;overflow-y:auto;">
        <div style="background:#12121f;border:1px solid #1e1e3a;border-radius:8px;padding:16px;font-size:12px;line-height:1.8;color:#aaa;">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#7b8cde;margin-bottom:10px;">AI Summary · ${domain}</div>
          <div style="white-space:pre-wrap;">${escapeHtml(text)}</div>
          <div style="margin-top:12px;font-size:10px;color:#2a2a4a;">Compared v${snaps.length-1} (${formatDate(older.timestamp)}) → v${snaps.length} (${formatDate(newer.timestamp)})</div>
        </div>
      </div>`;
  } catch (err) {
    area.innerHTML = `<div class="empty-state"><p>AI summary failed</p><small>${escapeHtml(err.message)}</small></div>`;
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────
async function deleteUrl(url) {
  const count = urlGroups[url]?.length || 0;
  if (!confirm(`Delete all ${count} snapshot${count!==1?'s':''} for this page?\nThis cannot be undone.`)) return;
  await VigilDB.Snapshots.deleteAll(url);
  delete urlGroups[url];
  activeUrl = null;
  renderStatsBar(); renderStorageStats(); renderUrlList();
  document.getElementById('main-panel').innerHTML = `<div class="empty-state"><p>Snapshots deleted</p><small>Select another page from the sidebar</small></div>`;
}

async function clearAll() {
  const total = Object.values(urlGroups).flat().length;
  if (!confirm(`Delete ALL ${total} snapshots across all pages?\nThis also clears tab history, clipboard vault, and form receipts.\nThis cannot be undone.`)) return;
  await VigilDB.Stats.nukeAll();
  urlGroups = {}; activeUrl = null;
  renderStatsBar(); renderStorageStats(); renderUrlList();
  document.getElementById('main-panel').innerHTML = `<div class="empty-state"><p>All data cleared</p><small>Vigil will start fresh as you browse</small></div>`;
}

// ── API Key (Anthropic) ───────────────────────────────────────────────────────
async function loadApiKeyStatus() {
  const result = await chrome.storage.sync.get('vigil_api_key');
  const keyEl  = document.getElementById('api-key-status');
  if (!keyEl) return;
  const key = result['vigil_api_key'];
  keyEl.textContent = key ? `✓ Key saved (${key.substring(0, 10)}…)` : '— No API key set';
  keyEl.style.color = key ? '#4caf50' : '#555';
}

// ── GSB Key (Google Safe Browsing) ────────────────────────────────────────────
async function loadGSBKeyStatus() {
  const result = await chrome.storage.local.get('vigil_gsb_key');
  const keyEl  = document.getElementById('gsb-key-status');
  if (!keyEl) return;
  const key = result['vigil_gsb_key'];
  keyEl.textContent = key ? `✓ Key saved (${key.substring(0, 8)}…)` : '— No key set (local scoring only)';
  keyEl.style.color = key ? '#4caf50' : '#555';
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Event bindings ────────────────────────────────────────────────────────────
function bindEvents() {
  document.getElementById('search-input').addEventListener('input', e => {
    searchQuery = e.target.value.trim(); renderUrlList();
  });
  document.querySelectorAll('.sort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      sortMode = btn.dataset.sort;
      document.querySelectorAll('.sort-btn').forEach(b => b.classList.toggle('active', b.dataset.sort === sortMode));
      renderUrlList();
    });
  });
  document.getElementById('btn-clear-all').addEventListener('click', clearAll);

  // Anthropic key
  document.getElementById('btn-save-key').addEventListener('click', async () => {
    const input = document.getElementById('api-key-input');
    const key   = input?.value.trim();
    if (!key) await chrome.storage.sync.remove('vigil_api_key');
    else { await chrome.storage.sync.set({ vigil_api_key: key }); input.value = ''; }
    loadApiKeyStatus();
  });

  // GSB key
  document.getElementById('btn-save-gsb').addEventListener('click', async () => {
    const input = document.getElementById('gsb-key-input');
    const key   = input?.value.trim();
    if (!key) await chrome.storage.local.remove('vigil_gsb_key');
    else { await chrome.storage.local.set({ vigil_gsb_key: key }); input.value = ''; }
    loadGSBKeyStatus();
  });
}

// ── Start ─────────────────────────────────────────────────────────────────────
init();