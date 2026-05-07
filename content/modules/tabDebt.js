// Vigil — Module 4: Tab Debt Tracker (content script side)
// Handles in-page rendering of tab debt data when requested from popup.
// All tracking logic lives in background.js (chrome.tabs API is restricted to
// background/service-worker context). This module is a thin UI layer only.

;(function () {
  'use strict';

  const SKIP = ['chrome://', 'chrome-extension://', 'moz-extension://', 'about:', 'file://', 'data:', 'blob:'];
  if (SKIP.some(p => location.href.startsWith(p))) return;

  // ── Message listener ───────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'openTabDebt') {
      showTabDebtOverlay(msg.data || {});
      sendResponse({ ok: true });
      return true;
    }
    if (msg.action === 'getTabDebtSummary') {
      chrome.storage.local.get('vigil_tabs', result => {
        const tabs = Object.values(result['vigil_tabs'] || {});
        const now  = Date.now();
        const dayMs = 864e5;
        sendResponse({
          total:  tabs.length,
          unread: tabs.filter(t => !t.read).length,
          old:    tabs.filter(t => now - t.openedAt > dayMs).length,
        });
      });
      return true;
    }
  });

  // ── Overlay UI ─────────────────────────────────────────────────────────────
  function showTabDebtOverlay(data) {
    const existing = document.getElementById('vigil-tabdebt-overlay');
    if (existing) { existing.remove(); return; }

    const tabs  = data.tabs || [];
    const now   = Date.now();
    const dayMs = 864e5;

    function timeAgo(ms) {
      const s = Math.floor(ms / 1000);
      if (s < 60)  return `${s}s ago`;
      const m = Math.floor(s / 60);
      if (m < 60)  return `${m}m ago`;
      const h = Math.floor(m / 60);
      if (h < 24)  return `${h}h ago`;
      return `${Math.floor(h / 24)}d ago`;
    }

    function esc(s) {
      return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    const unread = tabs.filter(t => !t.read).sort((a, b) => a.openedAt - b.openedAt);
    const old    = unread.filter(t => now - t.openedAt > dayMs);

    const rows = unread.slice(0, 10).map(t => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:6px 0;border-bottom:1px solid #eee;font-size:12px;">
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                     color:#222;max-width:280px;" title="${esc(t.url)}">${esc(t.title || t.url)}</span>
        <span style="color:#888;font-size:11px;margin-left:12px;white-space:nowrap;">
          ${timeAgo(now - t.openedAt)}
        </span>
      </div>`).join('');

    const overlay = document.createElement('div');
    overlay.id = 'vigil-tabdebt-overlay';
    overlay.style.cssText = `
      position:fixed;top:20px;right:20px;z-index:2147483647;
      width:380px;max-height:520px;overflow-y:auto;
      background:#fff;border:1.5px solid #ddd;border-radius:10px;
      box-shadow:0 8px 32px rgba(0,0,0,0.18);
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      padding:0;
    `;

    overlay.innerHTML = `
      <div style="background:#1a1a2e;color:#fff;padding:14px 16px;border-radius:8px 8px 0 0;
                  display:flex;align-items:center;justify-content:space-between;">
        <span style="font-weight:700;font-size:14px;">📋 Tab Debt Tracker</span>
        <button id="vigil-td-close" style="background:none;border:none;color:#fff;
                font-size:18px;cursor:pointer;padding:0;line-height:1;">×</button>
      </div>
      <div style="padding:14px 16px;">
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px;">
          <div style="text-align:center;background:#f5f5f5;border-radius:8px;padding:10px;">
            <div style="font-size:22px;font-weight:700;color:#1a1a2e;">${tabs.length}</div>
            <div style="font-size:10px;color:#666;margin-top:2px;">Open tabs</div>
          </div>
          <div style="text-align:center;background:#fff3e0;border-radius:8px;padding:10px;">
            <div style="font-size:22px;font-weight:700;color:#e65100;">${unread.length}</div>
            <div style="font-size:10px;color:#666;margin-top:2px;">Unread</div>
          </div>
          <div style="text-align:center;background:#fce4ec;border-radius:8px;padding:10px;">
            <div style="font-size:22px;font-weight:700;color:#c62828;">${old.length}</div>
            <div style="font-size:10px;color:#666;margin-top:2px;">Older than 1d</div>
          </div>
        </div>
        <div style="font-size:12px;font-weight:600;color:#555;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px;">
          Oldest Unread Tabs
        </div>
        <div id="vigil-td-list">
          ${rows || '<div style="color:#888;font-size:12px;padding:8px 0;">🎉 No unread tabs — inbox zero!</div>'}
        </div>
        ${old.length > 0 ? `
        <button id="vigil-td-cleanup" style="margin-top:14px;width:100%;padding:9px;
          background:#f44336;color:#fff;border:none;border-radius:6px;
          font-size:12px;font-weight:600;cursor:pointer;">
          Close ${old.length} unread tab${old.length > 1 ? 's' : ''} older than 1 day
        </button>` : ''}
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('vigil-td-close').onclick = () => overlay.remove();

    const cleanupBtn = document.getElementById('vigil-td-cleanup');
    if (cleanupBtn) {
      cleanupBtn.onclick = async () => {
        chrome.storage.local.get('vigil_tabs', async result => {
          const tabData = result['vigil_tabs'] || {};
          const oldIds  = Object.values(tabData)
            .filter(t => !t.read && now - t.openedAt > dayMs)
            .map(t => t.id);
          for (const id of oldIds) {
            try { await chrome.tabs.remove(id); } catch {}
          }
          overlay.remove();
        });
      };
    }
  }

})();
