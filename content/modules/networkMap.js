// Vigil — Module 2: Network Request Storyteller (Content Script Side)
// v0.4 — Multi-tier trust scoring with strict assessment
//
// TRUST TIERS (strict — matches what Brave blocks):
//   🔴 RED   (#f44336) — Advertising, Fingerprinting, Cryptomining
//   🟠 ORANGE (#ff9800) — Analytics, Social trackers, Disconnect-listed
//   🟡 YELLOW (#f5c542) — "Privacy-light" data collectors:
//      any domain that collects behavioural data even if not blocked
//      by default in uBlock. This includes CDNs with telemetry known
//      to Disconnect, and any domain matching the YELLOW_PATTERNS list.
//   🔵 BLUE  (#607d8b) — Pure CDN / content delivery (no telemetry known)
//   🟢 GREEN (#4caf50) — First-party or unrecognised (clean)
//
// The yellow tier is the key addition: sites like Google Fonts, Cloudflare
// analytics, Hotjar, etc. appear yellow even if not technically "trackers"
// in a narrow sense. Brave shields them — so Vigil now flags them too.

;(function () {
  'use strict';

  const SKIP_PREFIXES = [
    'chrome://', 'chrome-extension://', 'moz-extension://',
    'about:', 'file://', 'data:', 'blob:'
  ];
  if (SKIP_PREFIXES.some(p => location.href.startsWith(p))) return;

  // ─── Yellow-tier domains (data-collecting but not in Disconnect) ──────────
  // These are domains that Brave blocks in "Standard" shields mode or that
  // are known to collect behavioural / telemetry data even without cookies.
  const YELLOW_DOMAINS = new Set([
    // Google services with data collection
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'accounts.google.com', 'apis.google.com',
    'translate.googleapis.com', 'www.google-analytics.com',
    // Cloudflare telemetry endpoints
    'static.cloudflareinsights.com', 'beacon.cloudflare.com',
    // Microsoft telemetry
    'dc.services.visualstudio.com', 'browser.events.data.microsoft.com',
    'browser.pipe.aria.microsoft.com',
    // Hotjar (session recording)
    'static.hotjar.com', 'vars.hotjar.com', 'vc.hotjar.io',
    // FullStory
    'edge.fullstory.com', 'rs.fullstory.com',
    // Segment
    'cdn.segment.com', 'api.segment.io',
    // Intercom
    'widget.intercom.io', 'nexus-websocket-a.intercom.io',
    // Zendesk / Zopim
    'static.zdassets.com', 'ekr.zdassets.com',
    // Sentry (error tracking — collects user data)
    'browser.sentry-cdn.com', 'o0.ingest.sentry.io',
    // New Relic
    'js-agent.newrelic.com', 'bam.nr-data.net',
    // Datadog RUM
    'rum.browser-intake-datadoghq.com', 'logs.browser-intake-datadoghq.com',
    // Amplitude
    'api2.amplitude.com', 'api.amplitude.com',
    // Mixpanel
    'api.mixpanel.com', 'cdn.mxpnl.com',
    // Heap
    'heapanalytics.com', 'cdn.heapanalytics.com',
    // OneSignal (push notifications)
    'onesignal.com', 'cdn.onesignal.com',
    // Braze (marketing automation)
    'sdk.fra-01.braze.eu', 'sdk.iad-01.braze.com',
    // Optimizely / split testing
    'cdn.optimizely.com', 'logx.optimizely.com',
    // AB Tasty
    'cdn.abtasty.com',
    // Mouseflow
    'cdn.mouseflow.com',
    // Lucky Orange
    'lo.io', 'luckyorange.com',
    // Crazyegg
    'script.crazyegg.com',
    // Quantcast (consent + measurement)
    'quantcast.com', 'quantcast.mgr.consensu.org',
    // OneTrust / consent managers that also profile
    'cdn.cookielaw.org', 'geolocation.onetrust.com',
    // Linkedin Insight (cross-site tracking)
    'snap.licdn.com',
    // Pinterest tag
    'ct.pinterest.com',
    // Quora pixel
    'qpxl.quora.com',
    // Reddit pixel
    'alb.reddit.com', 'events.reddit.com',
    // TikTok pixel
    'analytics.tiktok.com', 'business-api.tiktok.com',
    // Chartbeat
    'static.chartbeat.com', 'ping.chartbeat.net',
    // Parse.ly
    'srv.relaymedia.com', 'p.parsely.com',
    // Comscore
    'sb.scorecardresearch.com', 'beacon.krxd.net',
    // Nielsen
    'secure-dcr.imrworldwide.com',
    // SpeedCurve / Boomerang RUM
    'rum.speedcurve.com',
    // Clarity (Microsoft)
    'www.clarity.ms', 'z.clarity.ms',
  ]);

  // Hostname suffixes that always get yellow (partial match)
  const YELLOW_SUFFIXES = [
    '.hotjar.com', '.fullstory.com', '.segment.com', '.segment.io',
    '.amplitude.com', '.mixpanel.com', '.heap.io', '.heapanalytics.com',
    '.clarity.ms', '.crazyegg.com', '.mouseflow.com', '.newrelic.com',
    '.nr-data.net', '.braze.com', '.braze.eu', '.optimizely.com',
    '.abtasty.com', '.quantcast.com', '.onetrust.com', '.cookielaw.org',
    '.parsely.com', '.chartbeat.com', '.scorecardresearch.com',
    '.comscore.com', '.imrworldwide.com',
  ];

  // ─── Trust tier definitions ───────────────────────────────────────────────
  const TIERS = {
    red: {
      color: '#f44336', bg: 'rgba(244,67,54,0.18)',
      dot: '#f44336', label: '⛔ Blocked (tracker/ad)',
      score: 0, icon: '⛔'
    },
    orange: {
      color: '#ff9800', bg: 'rgba(255,152,0,0.18)',
      dot: '#ff9800', label: '⚠ Data collector',
      score: 1, icon: '⚠'
    },
    yellow: {
      color: '#f5c542', bg: 'rgba(245,197,66,0.15)',
      dot: '#f5c542', label: '⚡ Telemetry / profiling',
      score: 2, icon: '⚡'
    },
    blue: {
      color: '#607d8b', bg: 'rgba(96,125,139,0.15)',
      dot: '#607d8b', label: 'CDN / delivery',
      score: 3, icon: '📦'
    },
    green: {
      color: '#4caf50', bg: 'rgba(76,175,80,0.12)',
      dot: '#4caf50', label: 'First-party / clean',
      score: 4, icon: '✓'
    },
  };

  // Map Disconnect categories to tiers
  const CATEGORY_TIER = {
    'Advertising':    'red',
    'Fingerprinting': 'red',
    'Cryptomining':   'red',
    'Social':         'orange',
    'Analytics':      'orange',
    'Disconnect':     'orange',
    'Content':        'blue',
  };

  // ─── Tier resolver ────────────────────────────────────────────────────────
  function resolveTier(domain) {
    // 1. Check Disconnect tracker data (provided by background via trackerInfo)
    if (domain.trackerInfo?.category) {
      return CATEGORY_TIER[domain.trackerInfo.category] || 'orange';
    }
    // 2. Check yellow-tier exact matches
    const host = (domain.hostname || '').toLowerCase().replace(/^www\./, '');
    if (YELLOW_DOMAINS.has(host)) return 'yellow';
    // 3. Check yellow suffix patterns
    if (YELLOW_SUFFIXES.some(sfx => host.endsWith(sfx))) return 'yellow';
    // 4. Disconnect content CDN
    if (domain.isTracker) return 'orange';
    // 5. Clean
    return 'green';
  }

  // ─── State ────────────────────────────────────────────────────────────────
  let reportData  = null;
  let overlayOpen = false;
  const OVERLAY_ID = 'vigil-network-overlay';

  // ─── Message listener ─────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === 'networkReport' && msg.data) {
      reportData = msg.data;
      if (overlayOpen && document.getElementById(OVERLAY_ID)) {
        updateOverlay(reportData);
      }
    }
    if (msg.action === 'openNetworkReport') {
      if (msg.data) reportData = msg.data;
      if (reportData) toggleOverlay(reportData);
      else showPlaceholderOverlay();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlayOpen) closeOverlay();
  });

  // ─── Toggle / open / close ───────────────────────────────────────────────
  function toggleOverlay(data) {
    document.getElementById(OVERLAY_ID) ? closeOverlay() : showOverlay(data);
  }
  function closeOverlay() {
    document.getElementById(OVERLAY_ID)?.remove();
    overlayOpen = false;
  }
  function showPlaceholderOverlay() {
    if (document.getElementById(OVERLAY_ID)) { closeOverlay(); return; }
    const overlay = buildShell();
    overlay.querySelector('#vigil-net-body').innerHTML = `
      <div style="padding:32px 20px;text-align:center;color:#333;font-size:12px;line-height:1.8;">
        <div style="font-size:28px;margin-bottom:10px;">📡</div>
        <div style="color:#555;">No network data captured yet.</div>
        <div style="color:#2a2a4a;font-size:11px;margin-top:6px;">Reload the page to start recording requests.</div>
      </div>`;
    document.body.appendChild(overlay);
    bindOverlayEvents(overlay);
    makeDraggable(overlay, overlay.querySelector('#vigil-net-handle'));
    overlayOpen = true;
  }
  function showOverlay(data) {
    const overlay = buildOverlayFromData(data);
    document.body.appendChild(overlay);
    bindOverlayEvents(overlay);
    makeDraggable(overlay, overlay.querySelector('#vigil-net-handle'));
    overlayOpen = true;
  }
  function updateOverlay(data) {
    const existing = document.getElementById(OVERLAY_ID);
    if (!existing) return;
    const fresh = buildOverlayFromData(data);
    const { left, top } = existing.style;
    if (left && top) {
      fresh.style.right = fresh.style.bottom = 'auto';
      fresh.style.left = left; fresh.style.top = top;
    }
    existing.replaceWith(fresh);
    bindOverlayEvents(fresh);
    makeDraggable(fresh, fresh.querySelector('#vigil-net-handle'));
  }

  // ─── Full overlay builder ─────────────────────────────────────────────────
  function buildOverlayFromData(data) {
    // Annotate each domain with its resolved tier
    const annotated = data.domains.map(d => ({ ...d, tier: resolveTier(d) }));

    const byTier = {
      red:    annotated.filter(d => d.tier === 'red'),
      orange: annotated.filter(d => d.tier === 'orange'),
      yellow: annotated.filter(d => d.tier === 'yellow'),
      blue:   annotated.filter(d => d.tier === 'blue'),
      green:  annotated.filter(d => d.tier === 'green'),
    };

    const risky   = [...byTier.red, ...byTier.orange, ...byTier.yellow];
    const overlay = buildShell();

    // ── Stat row ──
    const statRow = overlay.querySelector('#vigil-net-stats');
    statRow.appendChild(makeStatCell(data.domains.length,   'Total',     '#7b8cde'));
    statRow.appendChild(makeStatCell(byTier.red.length,     '⛔ Blocked', byTier.red.length    > 0 ? '#f44336' : '#444'));
    statRow.appendChild(makeStatCell(byTier.orange.length,  '⚠ Collect', byTier.orange.length > 0 ? '#ff9800' : '#444'));
    statRow.appendChild(makeStatCell(byTier.yellow.length,  '⚡ Telemetry',byTier.yellow.length> 0 ? '#f5c542' : '#444'));

    // ── Narrative ──
    overlay.querySelector('#vigil-net-narrative').innerHTML =
      buildNarrative(data, annotated, byTier);

    // ── Tier pills ──
    if (risky.length > 0) {
      const pills = overlay.querySelector('#vigil-net-pills');
      pills.style.display = 'flex';
      [
        { tier:'red',    doms: byTier.red },
        { tier:'orange', doms: byTier.orange },
        { tier:'yellow', doms: byTier.yellow },
      ].forEach(({ tier, doms }) => {
        if (!doms.length) return;
        const t = TIERS[tier];
        const pill = document.createElement('div');
        pill.style.cssText = `
          display:inline-flex;align-items:center;gap:5px;
          padding:3px 9px;border-radius:12px;font-size:10px;
          background:${t.bg};color:${t.color};border:1px solid ${t.color}44;`;
        pill.textContent = `${doms.length} ${t.label}`;
        pills.appendChild(pill);
      });
    }

    renderDomainList(overlay.querySelector('#vigil-net-list'), annotated);
    overlay.querySelector('#vigil-net-time').textContent = new Date().toLocaleTimeString();
    return overlay;
  }

  // ─── Shell ────────────────────────────────────────────────────────────────
  function buildShell() {
    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.setAttribute('role', 'dialog');
    overlay.style.cssText = `
      position:fixed;bottom:16px;right:16px;
      width:480px;max-height:75vh;min-height:180px;
      background:#12121f;border:1px solid #2a2a4a;
      border-top:3px solid #7b8cde;border-radius:10px;
      z-index:2147483647;
      font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;
      font-size:13px;color:#e0e0e0;
      box-shadow:0 8px 32px rgba(0,0,0,0.65);
      display:flex;flex-direction:column;overflow:hidden;user-select:none;`;

    const header = document.createElement('div');
    header.id = 'vigil-net-handle';
    header.style.cssText = `
      display:flex;justify-content:space-between;align-items:center;
      padding:11px 14px;border-bottom:1px solid #2a2a4a;
      background:#1a1a2e;cursor:move;flex-shrink:0;`;
    header.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-weight:700;font-size:11px;letter-spacing:2px;color:#7b8cde;">VIGIL</span>
        <span style="font-size:11px;color:#888;">Network Map</span>
      </div>`;
    const closeBtn = document.createElement('button');
    closeBtn.id = 'vigil-net-close';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.style.cssText = `background:transparent;border:none;color:#555;
      font-size:20px;cursor:pointer;line-height:1;padding:0 2px;transition:color 0.15s;`;
    closeBtn.textContent = '×';
    closeBtn.addEventListener('mouseover', () => { closeBtn.style.color = '#ccc'; });
    closeBtn.addEventListener('mouseout',  () => { closeBtn.style.color = '#555'; });
    header.appendChild(closeBtn);
    overlay.appendChild(header);

    // Tier legend
    const legend = document.createElement('div');
    legend.style.cssText = `
      display:flex;gap:10px;padding:7px 14px;
      border-bottom:1px solid #1e1e3a;background:#0f0f1a;
      flex-shrink:0;flex-wrap:wrap;`;
    [
      ['#f44336','⛔ Ads/FP/Crypto'],
      ['#ff9800','⚠ Analytics/Social'],
      ['#f5c542','⚡ Telemetry'],
      ['#607d8b','📦 CDN'],
      ['#4caf50','✓ Clean'],
    ].forEach(([color, label]) => {
      const el = document.createElement('span');
      el.style.cssText = `font-size:10px;color:${color};display:flex;align-items:center;gap:3px;`;
      el.textContent = label;
      legend.appendChild(el);
    });
    overlay.appendChild(legend);

    const statRow = document.createElement('div');
    statRow.id = 'vigil-net-stats';
    statRow.style.cssText = `display:flex;border-bottom:1px solid #2a2a4a;flex-shrink:0;`;
    overlay.appendChild(statRow);

    const narrative = document.createElement('div');
    narrative.id = 'vigil-net-narrative';
    narrative.style.cssText = `
      padding:10px 14px;font-size:12px;line-height:1.7;color:#888;
      border-bottom:1px solid #1e1e3a;flex-shrink:0;`;
    overlay.appendChild(narrative);

    const pills = document.createElement('div');
    pills.id = 'vigil-net-pills';
    pills.style.cssText = `
      display:none;gap:6px;flex-wrap:wrap;
      padding:8px 14px;border-bottom:1px solid #1e1e3a;flex-shrink:0;`;
    overlay.appendChild(pills);

    const body = document.createElement('div');
    body.id = 'vigil-net-body';
    body.style.cssText = `flex:1;overflow-y:auto;
      scrollbar-width:thin;scrollbar-color:#2a2a4a transparent;`;
    const list = document.createElement('div');
    list.id = 'vigil-net-list';
    body.appendChild(list);
    overlay.appendChild(body);

    const foot = document.createElement('div');
    foot.style.cssText = `display:flex;justify-content:space-between;align-items:center;
      padding:7px 14px;border-top:1px solid #1e1e3a;
      background:#0f0f1a;font-size:10px;color:#333;flex-shrink:0;`;
    foot.innerHTML = `<span>Updated <span id="vigil-net-time">—</span></span>
      <span style="color:#2a2a4a;">Strict assessment • Vigil v0.4</span>`;
    overlay.appendChild(foot);

    return overlay;
  }

  // ─── Bind close ───────────────────────────────────────────────────────────
  function bindOverlayEvents(overlay) {
    overlay.querySelector('#vigil-net-close').addEventListener('click', closeOverlay);
  }

  // ─── Stat cell ────────────────────────────────────────────────────────────
  function makeStatCell(value, label, color) {
    const cell = document.createElement('div');
    cell.style.cssText = `flex:1;padding:8px 6px;text-align:center;border-right:1px solid #2a2a4a;`;
    const num = document.createElement('div');
    num.style.cssText = `font-size:16px;font-weight:700;color:${color};`;
    num.textContent = value;
    const lbl = document.createElement('div');
    lbl.style.cssText = `font-size:9px;color:#444;margin-top:2px;white-space:nowrap;`;
    lbl.textContent = label;
    cell.appendChild(num); cell.appendChild(lbl);
    return cell;
  }

  // ─── Narrative ────────────────────────────────────────────────────────────
  function buildNarrative(data, annotated, byTier) {
    const unique = new Set(annotated.map(d => d.hostname)).size;
    const parts = [];

    if (byTier.red.length === 0 && byTier.orange.length === 0 && byTier.yellow.length === 0) {
      return `<span style="color:#4caf50;">✓</span> No trackers or telemetry detected. ` +
        `${data.domains.length} request${data.domains.length !== 1 ? 's' : ''} to ` +
        `<b style="color:#e0e0e0;">${unique}</b> domain${unique !== 1 ? 's' : ''}.`;
    }

    parts.push(`Contacted <b style="color:#e0e0e0;">${unique} domain${unique !== 1 ? 's' : ''}</b>.`);

    if (byTier.red.length)    parts.push(`<span style="color:#f44336;">⛔ ${byTier.red.length} ad/tracker/fingerprinter domains (Brave blocks these).</span>`);
    if (byTier.orange.length) parts.push(`<span style="color:#ff9800;">⚠ ${byTier.orange.length} analytics/social tracker domain${byTier.orange.length !== 1 ? 's' : ''}.</span>`);
    if (byTier.yellow.length) parts.push(`<span style="color:#f5c542;">⚡ ${byTier.yellow.length} telemetry/profiling domain${byTier.yellow.length !== 1 ? 's' : ''} (Brave Standard shields).</span>`);

    return parts.join(' ');
  }

  // ─── Domain list ─────────────────────────────────────────────────────────
  function renderDomainList(container, domains) {
    const tierOrder = { red:0, orange:1, yellow:2, blue:3, green:4 };
    const sorted = [...domains].sort((a, b) => {
      const td = (tierOrder[a.tier] || 4) - (tierOrder[b.tier] || 4);
      if (td !== 0) return td;
      return (b.count || 0) - (a.count || 0);
    });

    if (sorted.length === 0) {
      container.innerHTML = `<div style="padding:24px;text-align:center;color:#333;font-size:12px;">No network requests recorded.</div>`;
      return;
    }

    sorted.forEach(domain => {
      const t = TIERS[domain.tier] || TIERS.green;

      const row = document.createElement('div');
      row.style.cssText = `
        display:flex;align-items:center;gap:10px;
        padding:8px 14px;border-bottom:1px solid #0f0f1a;
        transition:background 0.12s;cursor:default;`;
      row.addEventListener('mouseover', () => { row.style.background = '#1a1a2e'; });
      row.addEventListener('mouseout',  () => { row.style.background = 'transparent'; });

      // Colored left bar
      const bar = document.createElement('div');
      bar.style.cssText = `width:3px;height:32px;border-radius:2px;flex-shrink:0;background:${t.color};opacity:0.8;`;

      const infoCol = document.createElement('div');
      infoCol.style.cssText = 'flex:1;min-width:0;';

      const hostnameEl = document.createElement('div');
      hostnameEl.style.cssText = `font-size:12px;color:#ccc;
        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;user-select:text;`;
      hostnameEl.textContent = domain.hostname;

      const subLabel = document.createElement('div');
      subLabel.style.cssText = `font-size:10px;color:${t.color};`;
      // Include category if available
      const cat = domain.trackerInfo?.category || domain.trackerInfo?.label;
      subLabel.textContent = cat
        ? `${t.icon} ${t.label} · ${cat}`
        : `${t.icon} ${t.label}`;

      infoCol.appendChild(hostnameEl);
      infoCol.appendChild(subLabel);

      const countEl = document.createElement('div');
      countEl.style.cssText = `font-size:11px;color:#444;flex-shrink:0;text-align:right;`;
      countEl.textContent = `${domain.count || 1} req`;

      const badge = document.createElement('div');
      badge.style.cssText = `padding:2px 7px;border-radius:3px;font-size:10px;
        background:${t.bg};color:${t.color};border:1px solid ${t.color}44;
        flex-shrink:0;white-space:nowrap;min-width:50px;text-align:center;`;
      badge.textContent = domain.tier.toUpperCase();

      row.appendChild(bar);
      row.appendChild(infoCol);
      row.appendChild(countEl);
      row.appendChild(badge);
      container.appendChild(row);
    });
  }

  // ─── Drag ─────────────────────────────────────────────────────────────────
  function makeDraggable(el, handle) {
    let dragging = false, sx = 0, sy = 0, ox = 0, oy = 0;
    handle.addEventListener('mousedown', e => {
      if (e.target.tagName === 'BUTTON') return;
      dragging = true;
      sx = e.clientX; sy = e.clientY;
      const r = el.getBoundingClientRect();
      ox = r.left; oy = r.top;
      el.style.right = el.style.bottom = 'auto';
      el.style.left = ox + 'px'; el.style.top = oy + 'px';
      e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      el.style.left = Math.max(0, ox + e.clientX - sx) + 'px';
      el.style.top  = Math.max(0, oy + e.clientY - sy) + 'px';
    });
    document.addEventListener('mouseup', () => { dragging = false; });
  }

  console.log('[Vigil] networkMap v1.4 loaded on', location.hostname);
})();