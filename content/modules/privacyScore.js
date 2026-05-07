// Vigil — Module 7: Privacy Score  (content/modules/privacyScore.js)
// v1.0  — Synthesises data from all other Vigil modules into a single
//         0-100 site-trust score, stores per-domain history in VigilDB,
//         and renders an on-page score overlay when requested.
// ─────────────────────────────────────────────────────────────────────────────
// SCORE FORMULA  (starts at 100, deductions applied)
//   1a. Trackers:       up to -30  (red×8 + orange×4 + yellow×2)
//   1b. Telemetry:      up to -15  (telemetry/fingerprint×5, analytics×2)
//   1c. Mixed content:  up to -10  (HTTP requests on HTTPS page ×3)
//   2.  Form Shadow:    up to -25  (hidden-field risk ×8 per field)
//   3.  Link Scorer:    up to -20  (dangerous×7 + risky×3)
//   4.  Clipboard:      up to -10  (high activity above 3 entries)
//   5.  HTTP page:      -20        (flat penalty — no encryption)
// Score clamped [0, 100].  Stored per hostname, max 30 history points.
// ─────────────────────────────────────────────────────────────────────────────

'use strict';

const PrivacyScore = (() => {

  const SKIP = ['chrome://', 'chrome-extension://', 'moz-extension://', 'about:', 'file://', 'data:', 'blob:'];
  if (SKIP.some(p => location.href.startsWith(p))) return {};

  // ── Score tier display config ──────────────────────────────────────────────
  const TIERS = [
    { min: 80, label: 'Trusted',     color: '#4caf50', bg: 'rgba(76,175,80,0.10)',    border: '#4caf5066' },
    { min: 60, label: 'Moderate',    color: '#f5c542', bg: 'rgba(245,197,66,0.10)',   border: '#f5c54266' },
    { min: 40, label: 'Suspicious',  color: '#ff9800', bg: 'rgba(255,152,0,0.10)',    border: '#ff980066' },
    { min:  0, label: 'Dangerous',   color: '#f44336', bg: 'rgba(244,67,54,0.10)',    border: '#f4433666' },
  ];
  function tier(score) { return TIERS.find(t => score >= t.min) || TIERS[3]; }

  // ── Gather signals from other modules via background.js ───────────────────
  async function gatherSignals() {
    const signals = { network: null, formCount: 0, linkReport: null, clipCount: 0 };

    const ask = (action, extra = {}) => new Promise(resolve => {
      chrome.runtime.sendMessage({ action, ...extra }, r => {
        if (chrome.runtime.lastError) resolve(null);
        else resolve(r);
      });
    });

    const [net, form, links, clip] = await Promise.allSettled([
      ask('getNetworkReport'),
      ask('getFormCount'),
      ask('getLinkReport'),
      ask('getClipboardCount'),
    ]);

    signals.network    = net.status   === 'fulfilled' ? net.value   : null;
    signals.formCount  = form.status  === 'fulfilled' ? (form.value?.count ?? 0)  : 0;
    signals.linkReport = links.status === 'fulfilled' ? links.value : null;
    signals.clipCount  = clip.status  === 'fulfilled' ? (clip.value?.count ?? 0)  : 0;

    return signals;
  }

  // ── Compute score from gathered signals ───────────────────────────────────
  function computeScore(signals) {
    let score = 100;
    const breakdown = [];

    // ── 1a. Network trackers (max -30) ──────────────────────────────────
    const net = signals.network;
    if (net?.domains?.length) {
      const trackers    = net.domains.filter(d => d.isTracker);
      const redCount    = trackers.filter(d => d.tier === 'red').length;
      const orangeCount = trackers.filter(d => d.tier === 'orange').length;
      const yellowCount = trackers.filter(d => d.tier === 'yellow').length;

      const netDeduct = Math.min(30, redCount * 8 + orangeCount * 4 + yellowCount * 2);
      if (netDeduct > 0) {
        score -= netDeduct;
        breakdown.push({
          label: `${trackers.length} tracker${trackers.length > 1 ? 's' : ''} detected`,
          detail: `${redCount} critical · ${orangeCount} moderate · ${yellowCount} mild`,
          deduct: netDeduct,
          icon: '⬛',
          color: '#f44336',
        });
      } else {
        breakdown.push({ label: 'No trackers detected', deduct: 0, icon: '✓', color: '#4caf50' });
      }

      // ── 1b. Telemetry / fingerprinting / analytics (max -15) ──────────
      // NetworkMap tags domains with a 'category' field:
      // 'telemetry', 'fingerprinting', 'cryptomining', 'analytics', 'social'
      const HIGH_RISK_CATS = ['telemetry', 'fingerprinting', 'cryptomining'];
      const MED_RISK_CATS  = ['analytics', 'social'];
      const highRisk = net.domains.filter(d => HIGH_RISK_CATS.includes(d.category));
      const medRisk  = net.domains.filter(d => MED_RISK_CATS.includes(d.category));
      const telDeduct = Math.min(15, highRisk.length * 5 + medRisk.length * 2);
      if (telDeduct > 0) {
        score -= telDeduct;
        const cats = [...new Set([...highRisk, ...medRisk].map(d => d.category))].join(', ');
        breakdown.push({
          label: `${highRisk.length + medRisk.length} telemetry/tracking endpoint${(highRisk.length + medRisk.length) > 1 ? 's' : ''} found`,
          detail: `Categories detected: ${cats}`,
          deduct: telDeduct,
          icon: '⬛',
          color: '#e91e63',
        });
      }

      // ── 1c. Mixed content — HTTP sub-requests on HTTPS page (max -10) ─
      const mixedContent = net.domains.filter(d => d.protocol === 'http:' && location.protocol === 'https:');
      if (mixedContent.length > 0) {
        const mixDeduct = Math.min(10, mixedContent.length * 3);
        score -= mixDeduct;
        breakdown.push({
          label: `${mixedContent.length} mixed-content HTTP request${mixedContent.length > 1 ? 's' : ''} on HTTPS page`,
          detail: 'Unencrypted sub-resources weaken HTTPS protection',
          deduct: mixDeduct,
          icon: '⬛',
          color: '#ff9800',
        });
      }
    } else {
      breakdown.push({ label: 'Network data not yet available', deduct: 0, icon: '—', color: '#888' });
    }

    // ── 2. Form Shadow (max -25) ─────────────────────────────────────────
    if (signals.formCount > 0) {
      const formDeduct = Math.min(25, signals.formCount * 8);
      score -= formDeduct;
      breakdown.push({
        label: `${signals.formCount} suspicious hidden field${signals.formCount > 1 ? 's' : ''} in forms`,
        deduct: formDeduct,
        icon: '⬛',
        color: '#ff9800',
      });
    } else {
      breakdown.push({ label: 'No hidden form fields found', deduct: 0, icon: '✓', color: '#4caf50' });
    }

    // ── 3. Link Scorer (max -20) ─────────────────────────────────────────
    const links = signals.linkReport?.links ?? [];
    if (links.length > 0) {
      const dangerous = links.filter(l => l.score < 30).length;
      const risky     = links.filter(l => l.score >= 30 && l.score < 55).length;
      const linkDeduct = Math.min(20, dangerous * 7 + risky * 3);
      if (linkDeduct > 0) {
        score -= linkDeduct;
        breakdown.push({
          label: `${dangerous + risky} unsafe link${dangerous + risky > 1 ? 's' : ''} on page`,
          detail: `${dangerous} dangerous · ${risky} risky`,
          deduct: linkDeduct,
          icon: '⬛',
          color: '#ff5722',
        });
      } else {
        breakdown.push({ label: 'All links look safe', deduct: 0, icon: '✓', color: '#4caf50' });
      }
    }

    // ── 4. Clipboard (max -10) ───────────────────────────────────────────
    if (signals.clipCount > 3) {
      const clipDeduct = Math.min(10, (signals.clipCount - 3) * 2);
      score -= clipDeduct;
      breakdown.push({
        label: `High clipboard activity (${signals.clipCount} entries)`,
        deduct: clipDeduct,
        icon: '⬛',
        color: '#ff9800',
      });
    }

    // ── 5. HTTPS page penalty (-20) — flat, no encryption at all ───────────
    if (location.protocol !== 'https:') {
      score -= 20;
      breakdown.push({
        label: 'Page loaded over plain HTTP — all traffic is unencrypted',
        deduct: 20,
        icon: '⬛',
        color: '#f44336',
      });
    }

    return { score: Math.max(0, Math.min(100, Math.round(score))), breakdown };
  }

  // ── Persist score to VigilDB ──────────────────────────────────────────────
  async function persistScore(hostname, score) {
    try {
      await VigilDB.ready;
      const key     = `privacy_score_${hostname}`;
      const stored  = await chrome.storage.local.get(key);
      const history = stored[key] || [];
      history.push({ score, ts: Date.now() });
      if (history.length > 30) history.splice(0, history.length - 30);
      await chrome.storage.local.set({ [key]: history });
    } catch (e) {
      console.warn('[Vigil PrivacyScore] Failed to persist:', e);
    }
  }

  // ── Load score history for current host ───────────────────────────────────
  async function loadHistory(hostname) {
    try {
      const key    = `privacy_score_${hostname}`;
      const stored = await chrome.storage.local.get(key);
      return stored[key] || [];
    } catch { return []; }
  }

  // ── Mini sparkline SVG ────────────────────────────────────────────────────
  function sparkline(history, width = 140, height = 32) {
    if (history.length < 2) return '';
    const pts  = history.slice(-15);
    const W    = width, H = height, pad = 2;
    const minV = Math.min(...pts.map(p => p.score));
    const maxV = Math.max(...pts.map(p => p.score));
    const range = maxV - minV || 1;
    const xs = pts.map((_, i) => pad + (i / (pts.length - 1)) * (W - pad * 2));
    const ys = pts.map(p => H - pad - ((p.score - minV) / range) * (H - pad * 2));
    const d  = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');
    const lastTier = tier(pts[pts.length - 1].score);
    return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <polyline points="${xs.map((x,i)=>`${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ')}"
        fill="none" stroke="${lastTier.color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="${xs[xs.length-1].toFixed(1)}" cy="${ys[ys.length-1].toFixed(1)}" r="3" fill="${lastTier.color}"/>
    </svg>`;
  }

  // ── Overlay UI ────────────────────────────────────────────────────────────
  function esc(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  async function showOverlay() {
    const existing = document.getElementById('vigil-pscore-overlay');
    if (existing) { existing.remove(); return; }

    const signals  = await gatherSignals();
    const { score, breakdown } = computeScore(signals);
    const t        = tier(score);
    const hostname = location.hostname;

    await persistScore(hostname, score);
    const history  = await loadHistory(hostname);

    const trend = (() => {
      if (history.length < 2) return '';
      const prev = history[history.length - 2].score;
      const diff = score - prev;
      if (diff > 3)  return `<span style="color:#4caf50;font-size:11px;"> ▲ +${diff} vs last visit</span>`;
      if (diff < -3) return `<span style="color:#f44336;font-size:11px;"> ▼ ${diff} vs last visit</span>`;
      return `<span style="color:#888;font-size:11px;"> — stable vs last visit</span>`;
    })();

    const spark = sparkline(history);

    const rows = breakdown.map(b => `
      <div style="display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:0.5px solid rgba(128,128,128,0.12);">
        <span style="font-size:11px;margin-top:1px;color:${b.color};">${b.deduct > 0 ? '−' + b.deduct : '✓'}</span>
        <div>
          <div style="font-size:11px;color:#ddd;">${esc(b.label)}</div>
          ${b.detail ? `<div style="font-size:10px;color:#999;">${esc(b.detail)}</div>` : ''}
        </div>
      </div>`).join('');

    const overlay = document.createElement('div');
    overlay.id = 'vigil-pscore-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-label', 'Vigil Privacy Score');
    overlay.style.cssText = `
      position:fixed; bottom:20px; right:20px; z-index:2147483647;
      width:280px; background:#1e1e2e; border-radius:12px;
      border:1px solid ${t.border}; font-family:system-ui,sans-serif;
      box-shadow:0 8px 32px rgba(0,0,0,0.5); overflow:hidden;`;

    overlay.innerHTML = `
      <div style="background:${t.bg};border-bottom:1px solid ${t.border};padding:14px 16px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px;">
          <span style="font-size:11px;font-weight:500;color:#aaa;letter-spacing:0.07em;text-transform:uppercase;">Vigil Privacy Score</span>
          <button id="vigil-pscore-close" style="background:none;border:none;color:#888;font-size:16px;cursor:pointer;line-height:1;padding:0;">×</button>
        </div>
        <div style="display:flex;align-items:flex-end;gap:10px;margin-top:6px;">
          <span style="font-size:42px;font-weight:700;line-height:1;color:${t.color};">${score}</span>
          <div>
            <div style="font-size:14px;font-weight:600;color:${t.color};">${t.label}</div>
            <div style="font-size:10px;color:#888;">${esc(hostname)}</div>
          </div>
        </div>
        ${trend}
        ${spark ? `<div style="margin-top:8px;opacity:0.85;">${spark}</div>` : ''}
        ${history.length > 1 ? `<div style="font-size:10px;color:#666;margin-top:4px;">${history.length} visits tracked</div>` : ''}
      </div>
      <div style="padding:8px 16px 12px;">
        <div style="font-size:10px;color:#777;font-weight:500;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.07em;">Score breakdown</div>
        ${rows}
      </div>`;

    document.body.appendChild(overlay);
    document.getElementById('vigil-pscore-close').addEventListener('click', () => overlay.remove());
  }

  // ── Compute & return summary (for popup use) ──────────────────────────────
  async function getSummary() {
    const signals  = await gatherSignals();
    const { score, breakdown } = computeScore(signals);
    const hostname = location.hostname;
    await persistScore(hostname, score);
    const history  = await loadHistory(hostname);
    return { score, breakdown, hostname, historyCount: history.length };
  }

  // ── Message listener ──────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'openPrivacyScore') {
      showOverlay();
      sendResponse({ ok: true });
      return true;
    }
    if (msg.action === 'getPrivacyScore') {
      getSummary().then(sendResponse).catch(() => sendResponse(null));
      return true;
    }
  });

  return { getSummary, showOverlay };

})();