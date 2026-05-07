// ============================================================
// Vigil — Form Shadow  (content/modules/formShadow.js)
// v2.0  — replaces raw IndexedDB + alert() with:
//   • VigilDB.Forms integration (shared Dexie store)
//   • Vigil-style in-page overlay (green / yellow / orange / red)
//   • Per-field severity classification
//   • User confirmation flow (Continue / Cancel)
// ============================================================

'use strict';

const FormShadow = (() => {

  // ── Severity tiers ────────────────────────────────────────────────────────
  const TIER = {
    SAFE:     { id: 'safe',     label: 'No Hidden Fields',  color: '#4caf50', bg: 'rgba(76,175,80,0.12)',    border: '#4caf5055', icon: '✓', autoDismiss: 3500 },
    CAUTION:  { id: 'caution',  label: 'Low Risk',          color: '#f5c542', bg: 'rgba(245,197,66,0.10)',   border: '#f5c54255', icon: '⚑', autoDismiss: false },
    WARNING:  { id: 'warning',  label: 'Moderate Risk',     color: '#ff9800', bg: 'rgba(255,152,0,0.10)',    border: '#ff980055', icon: '⚠', autoDismiss: false },
    DANGER:   { id: 'danger',   label: 'High Risk',         color: '#f44336', bg: 'rgba(244,67,54,0.12)',    border: '#f4433655', icon: '⛔', autoDismiss: false },
  };

  // ── Known-benign field name patterns (CSRF tokens, redirects, etc.) ───────
  const BENIGN_PATTERNS = [
    /^csrf/i, /token$/i, /^_token/i, /^authenticity/i, /^nonce$/i,
    /^__requestverification/i, /^utf8$/i, /^redirect/i, /^return_?url/i,
    /^form_?id$/i, /^page$/i, /^step$/i, /^action$/i, /^method$/i,
    /^submit$/i, /^button$/i, /^_method$/i, /^_encoding$/i,
  ];

  // ── Known-suspicious field name patterns ─────────────────────────────────
  const SUSPICIOUS_PATTERNS = [
    /fingerprint/i, /fp_/i, /^fp$/i, /device_?id/i, /tracking/i,
    /^_ga$/i, /^fbp$/i, /^fbclid$/i, /user_?agent/i, /screen_?res/i,
    /timezone/i, /canvas/i, /^uid$/i, /^uuid$/i, /beacon/i,
    /telemetry/i, /analytics/i, /session_?id/i, /visitor/i, /client_?id/i,
  ];

  // ── Classify a single hidden field ───────────────────────────────────────
  function classifyField(name) {
    const n = (name || '').toLowerCase();
    if (SUSPICIOUS_PATTERNS.some(rx => rx.test(n))) {
      return { risk: 'danger',  reason: 'Matches known tracking/fingerprinting pattern' };
    }
    if (BENIGN_PATTERNS.some(rx => rx.test(n))) {
      return { risk: 'benign', reason: 'Common security token or form metadata' };
    }
    return { risk: 'unknown', reason: 'Purpose unclear — value sent without your knowledge' };
  }

  // ── Compute overall severity from classified fields ───────────────────────
  function computeTier(classifiedFields) {
    if (classifiedFields.length === 0) return TIER.SAFE;

    const dangerCount  = classifiedFields.filter(f => f.risk === 'danger').length;
    const unknownCount = classifiedFields.filter(f => f.risk === 'unknown').length;
    const total        = classifiedFields.length;

    if (dangerCount >= 1 || total >= 6) return TIER.DANGER;
    if (unknownCount >= 3 || total >= 3) return TIER.WARNING;
    if (total >= 1)                       return TIER.CAUTION;
    return TIER.SAFE;
  }

  // ── Escape HTML ───────────────────────────────────────────────────────────
  function escH(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Detect hidden fields + classify ──────────────────────────────────────
  function detectAndClassify(elements) {
    const fields = [];
    elements.forEach(el => {
      const style = window.getComputedStyle(el);
      const isHidden =
        el.type === 'hidden'           ||
        style.display === 'none'       ||
        style.visibility === 'hidden'  ||
        el.offsetParent === null;

      if (isHidden) {
        const name = el.name || el.id || 'unknown';
        const info = classifyField(name);
        fields.push({
          name,
          type:   el.type || 'hidden',
          elType: el.tagName.toLowerCase(),
          ...info
        });
      }
    });
    return fields;
  }

  // ── Build & inject the overlay ────────────────────────────────────────────
  function showOverlay(tier, hiddenFields, onContinue, onCancel) {
    document.getElementById('vigil-fs-overlay')?.remove();

    const isSafe = tier.id === 'safe';

    const fieldRows = hiddenFields.map(f => {
      const riskColors = {
        danger:  { color: '#f44336', bg: 'rgba(244,67,54,0.12)',  label: 'Tracking' },
        unknown: { color: '#ff9800', bg: 'rgba(255,152,0,0.10)',  label: 'Unknown'  },
        benign:  { color: '#4caf50', bg: 'rgba(76,175,80,0.10)',  label: 'Benign'   },
      };
      const rc = riskColors[f.risk] || riskColors.unknown;
      return `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 10px;
          background:${rc.bg};border-radius:7px;border:1px solid ${rc.color}22;margin-bottom:5px;">
          <div style="flex:0 0 auto;margin-top:1px;">
            <span style="display:inline-block;padding:1px 7px;border-radius:10px;
              font-size:10px;font-weight:700;background:${rc.bg};color:${rc.color};
              border:1px solid ${rc.color}44;">${escH(rc.label)}</span>
          </div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;color:#dde0f0;font-weight:600;
              white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
              title="${escH(f.name)}">${escH(f.name)}</div>
            <div style="font-size:11px;color:#666;margin-top:2px;line-height:1.4;">${escH(f.reason)}</div>
          </div>
        </div>`;
    }).join('');

    const safeBody = `
      <div style="display:flex;align-items:center;gap:10px;padding:12px 0;">
        <span style="font-size:22px;">✓</span>
        <div>
          <div style="font-size:13px;color:#4caf50;font-weight:600;">No hidden fields detected</div>
          <div style="font-size:11px;color:#555;margin-top:3px;">This form only contains visible fields.</div>
        </div>
      </div>`;

    const warningBody = `
      <div style="font-size:11.5px;color:#888;margin-bottom:10px;line-height:1.6;">
        This form is submitting <b style="color:${tier.color}">${hiddenFields.length} hidden field${hiddenFields.length>1?'s':''}</b>
        you cannot see. Review them below before continuing.
      </div>
      <div style="max-height:180px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#2a2a4a transparent;">
        ${fieldRows}
      </div>`;

    const footerBtns = isSafe ? `
      <button id="vfs-ok"
        style="background:transparent;border:1px solid #4caf50;color:#4caf50;
          border-radius:6px;padding:4px 14px;font-size:12px;cursor:pointer;
          font-family:inherit;transition:background .15s;">
        OK
      </button>` : `
      <div style="display:flex;gap:8px;margin-left:auto;">
        <button id="vfs-cancel"
          style="background:transparent;border:1px solid #2a2a4a;color:#666;
            border-radius:6px;padding:4px 14px;font-size:12px;cursor:pointer;
            font-family:inherit;transition:all .15s;">
          Cancel submit
        </button>
        <button id="vfs-continue"
          style="background:transparent;border:1px solid ${tier.color};color:${tier.color};
            border-radius:6px;padding:4px 14px;font-size:12px;cursor:pointer;
            font-family:inherit;transition:background .15s;">
          Continue anyway →
        </button>
      </div>`;

    const o = document.createElement('div');
    o.id = 'vigil-fs-overlay';
    o.innerHTML = `
      <style>
        #vigil-fs-overlay {
          position: fixed;
          top: 18px;
          right: 18px;
          width: 380px;
          background: #0e0e1a;
          border: 1px solid #22224a;
          border-top: 3px solid ${tier.color};
          border-radius: 12px;
          z-index: 2147483647;
          font-family: system-ui, -apple-system, sans-serif;
          font-size: 13px;
          color: #dde0f0;
          box-shadow: 0 12px 48px rgba(0,0,0,.80);
          overflow: hidden;
          animation: vfs-in 0.22s cubic-bezier(.22,1,.36,1);
        }
        @keyframes vfs-in {
          from { opacity:0; transform:translateY(-12px) scale(.97); }
          to   { opacity:1; transform:none; }
        }
        #vfs-cancel:hover   { border-color:#888 !important; color:#aaa !important; }
        #vfs-continue:hover { background:${tier.bg} !important; }
        #vfs-ok:hover       { background:rgba(76,175,80,.12) !important; }
        #vfs-xbtn:hover     { color:#aaa !important; }
      </style>

      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:center;
        padding:10px 14px;background:#141428;border-bottom:1px solid #22224a;
        cursor:move;user-select:none;" id="vfs-drag">
        <div style="display:flex;align-items:center;gap:9px;">
          <span style="font-weight:800;font-size:11px;letter-spacing:2.5px;color:#7b8cde;">VIGIL</span>
          <span style="font-size:11px;color:#888;">Form Shadow</span>
          <span style="display:inline-block;padding:1px 8px;border-radius:10px;
            font-size:10px;font-weight:700;
            background:${tier.bg};color:${tier.color};
            border:1px solid ${tier.border};">
            ${tier.icon} ${escH(tier.label)}
          </span>
        </div>
        <button id="vfs-xbtn"
          style="background:transparent;border:none;color:#3a3a5a;
            font-size:22px;cursor:pointer;line-height:1;
            padding:0 2px;font-family:inherit;transition:color .15s;">×</button>
      </div>

      <!-- Body -->
      <div style="padding:14px 16px;">
        ${isSafe ? safeBody : warningBody}
      </div>

      <!-- Footer -->
      <div style="display:flex;align-items:center;padding:9px 14px;
        border-top:1px solid #1a1a38;background:#141428;">
        <span style="font-size:10px;color:#2a2a4a;">
          ${isSafe ? 'Submission will proceed.' : 'Submission is paused.'}
        </span>
        ${footerBtns}
      </div>`;

    document.documentElement.appendChild(o);

    // ── Drag support ──────────────────────────────────────────────────────
    let dx = 0, dy = 0, dragging = false;
    const drag = o.querySelector('#vfs-drag');
    drag.addEventListener('mousedown', e => {
      dragging = true;
      dx = e.clientX - o.getBoundingClientRect().left;
      dy = e.clientY - o.getBoundingClientRect().top;
    });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      o.style.right  = 'auto';
      o.style.left   = (e.clientX - dx) + 'px';
      o.style.top    = (e.clientY - dy) + 'px';
    });
    document.addEventListener('mouseup', () => { dragging = false; });

    // ── Button listeners ──────────────────────────────────────────────────
    o.querySelector('#vfs-xbtn').onclick = () => {
      o.remove();
      if (isSafe) onContinue();
    };

    if (isSafe) {
      o.querySelector('#vfs-ok')?.addEventListener('click', () => {
        o.remove();
        onContinue();
      });
    } else {
      o.querySelector('#vfs-cancel')?.addEventListener('click', () => {
        o.remove();
        onCancel();
      });
      o.querySelector('#vfs-continue')?.addEventListener('click', () => {
        o.remove();
        onContinue();
      });
    }

    // ── Auto-dismiss (safe tier only) ─────────────────────────────────────
    if (tier.autoDismiss) {
      const bar = document.createElement('div');
      bar.style.cssText = `height:2px;background:${tier.color};
        width:100%;transition:width linear ${tier.autoDismiss}ms;`;
      o.appendChild(bar);
      // Trigger CSS transition after paint
      requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = '0%'; }));

      setTimeout(() => {
        if (document.getElementById('vigil-fs-overlay') === o) {
          o.remove();
          onContinue();
        }
      }, tier.autoDismiss);
    }

    return o;
  }

  // ── AES-GCM encrypt ───────────────────────────────────────────────────────
  async function encrypt(record) {
    const key      = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt','decrypt']);
    const iv       = crypto.getRandomValues(new Uint8Array(12));
    const encoded  = new TextEncoder().encode(JSON.stringify(record));
    const cipher   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    return {
      iv:   Array.from(iv),
      data: Array.from(new Uint8Array(cipher))
    };
  }

  // ── SHA-256 tamper-evidence hash ──────────────────────────────────────────
  async function sha256(record) {
    const buf = await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(JSON.stringify(record)));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // ── Main form intercept ───────────────────────────────────────────────────
  async function handleSubmit(event) {
    event.preventDefault();

    const form     = event.target;
    const elements = [...form.querySelectorAll('input, textarea, select')];

    // Scrape visible field values (mask passwords)
    const formData = {};
    elements.forEach(el => {
      formData[el.name || el.id || 'unknown'] =
        el.type === 'password' ? '••••••' : el.value;
    });

    // Classify hidden fields
    const hidden    = detectAndClassify(elements);
    const tier      = computeTier(hidden);
    const fieldNames = hidden.map(f => f.name);

    // Build receipt for storage
    const receipt = {
      url:         window.location.href,
      timestamp:   new Date().toISOString(),
      formData,
      hiddenFields: fieldNames,
      severity:    tier.id,
    };

    // Fire-and-forget storage (don't block the UX on it)
    (async () => {
      try {
        await VigilDB.ready;
        const hash      = await sha256(receipt);
        const encrypted = await encrypt(receipt);
        await VigilDB.Forms.save(
          receipt.url,
          elements.filter(el => el.type !== 'hidden').map(el => el.name || el.id || 'unknown'),
          fieldNames,
          encrypted
        );
        console.log('[Vigil FormShadow] Receipt stored. Hash:', hash, '| Severity:', tier.id);
      } catch (err) {
        console.warn('[Vigil FormShadow] Storage failed (non-fatal):', err);
      }
    })();

    // Show overlay — resolves via onContinue / onCancel callbacks
    showOverlay(
      tier,
      hidden,
      () => {
        // Continue: re-submit the form natively
        // Temporarily detach our listener to avoid re-triggering
        form.removeEventListener('submit', handleSubmit);
        form.submit();
        // Re-attach asynchronously so future submits are still watched
        setTimeout(() => form.addEventListener('submit', handleSubmit), 0);
      },
      () => {
        // Cancel: do nothing — submission stays blocked
        console.log('[Vigil FormShadow] User cancelled form submission.');
      }
    );
  }

  // ── Attach to all forms (including dynamically added ones) ────────────────
  function attach(root) {
    root.querySelectorAll('form').forEach(form => {
      if (!form.__vigilAttached) {
        form.addEventListener('submit', handleSubmit);
        form.__vigilAttached = true;
      }
    });
  }

  function init() {
    attach(document);

    // Watch for dynamically injected forms
    const mo = new MutationObserver(mutations => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          if (node.tagName === 'FORM') {
            if (!node.__vigilAttached) {
              node.addEventListener('submit', handleSubmit);
              node.__vigilAttached = true;
            }
          } else {
            attach(node);
          }
        }
      }
    });
    mo.observe(document.body || document.documentElement, {
      childList: true, subtree: true
    });

    console.log('[Vigil FormShadow] Initialised — watching', document.querySelectorAll('form').length, 'form(s)');
  }

  // Wait for DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { init, classifyField, computeTier, TIER };

})();