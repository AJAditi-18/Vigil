// Vigil — Module 6: Link Credibility Scorer v4.0
// Fixes: (1) all parameters shown with descriptions, (2) 2s hover delay,
//        (3) strict scoring — malicious links score <30, clean HTTPS ~80
'use strict';

const LinkScorer = (() => {

  const SCORED_ATTR = 'data-vigil-ls';
  const GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  const BASELINE = 20;

  // ── Tiers ──────────────────────────────────────────────────────────────────
  const THRESHOLDS = [
    { min:80, label:'Safe',       color:'#4caf50', border:'#4caf50', icon:'✓'  },
    { min:55, label:'Suspicious', color:'#ff9800', border:'#ff9800', icon:'⚠'  },
    { min:30, label:'Risky',      color:'#ff5722', border:'#ff5722', icon:'⛔' },
    { min: 0, label:'Dangerous',  color:'#f44336', border:'#f44336', icon:'☠' },
  ];
  function tier(score) { return THRESHOLDS.find(t => score >= t.min) || THRESHOLDS[3]; }
  function severityColor(s) { return {critical:'#f44336',high:'#ff5722',medium:'#ff9800',low:'#aaa'}[s]||'#aaa'; }

  // ── Lookup tables ──────────────────────────────────────────────────────────
  const BRANDS = new Set(['paypal','apple','microsoft','google','amazon','netflix','facebook','instagram','twitter','whatsapp','linkedin','dropbox','icloud','wellsfargo','bankofamerica','chase','citibank','hsbc','barclays','ebay','steam','discord','github','adobe','spotify','yahoo','outlook','office','onedrive','sharepoint']);

  const TRUSTED_APEXES = new Set(['google.com','microsoft.com','apple.com','amazon.com','github.com','facebook.com','twitter.com','x.com','linkedin.com','instagram.com','paypal.com','netflix.com','spotify.com','adobe.com','dropbox.com','yahoo.com','outlook.com','discord.com','steampowered.com','ebay.com','amazon.co.uk','amazon.de','amazon.fr','bbc.com','bbc.co.uk','wikipedia.org','reddit.com','stackoverflow.com','cloudflare.com','akamai.com','fastly.com']);

  const SHORTENERS = new Set(['bit.ly','t.co','tinyurl.com','goo.gl','ow.ly','buff.ly','short.link','rb.gy','cutt.ly','is.gd','v.gd','tiny.cc','bl.ink','shorturl.at','lnkd.in']);

  const BAD_TLDS = new Set(['tk','ml','ga','cf','gq','xyz','top','click','download','loan','win','racing','review','stream','date','faith','science','party','trade','webcam','accountant','cricket','work','men','bid','pw','gdn','zip','mov']);

  const SUSPICIOUS_KW = ['login','signin','secure','verify','update','confirm','banking','webscr','checkout','password','credential','validate','suspend','unlock','recover'];

  // ── Parameter descriptions ─────────────────────────────────────────────────
  const PARAM_DESC = {
    baseline: 'Every external link starts with a baseline distrust penalty of 20. Unknown does not mean safe — a link must earn trust through HTTPS, a clean domain, and no suspicious signals.',
    P1:       'The link uses HTTP instead of HTTPS. The connection is unencrypted — anyone on the same network can intercept or modify data in transit. All legitimate modern sites use HTTPS.',
    P_IP:     'The link points to a raw IP address (e.g. 192.168.1.1) instead of a domain name. Legitimate services use domain names. Raw IPs are common in malware distribution and phishing.',
    P3:       'The domain contains Punycode (xn--) or non-ASCII Unicode characters visually identical to Latin letters (e.g. Cyrillic a vs Latin a). Used to create fake domains that look real.',
    P_CRED:   'Credentials are embedded in the URL as user:password@domain. A phishing technique that makes users think they are visiting a trusted host while actually navigating elsewhere.',
    P_PORT:   'The link uses a non-standard TCP port (not 80 or 443). Legitimate websites rarely require non-standard ports. Common in phishing kits running on compromised servers.',
    P9:       'The domain uses a TLD heavily associated with free hosting abuse and phishing (.tk, .ml, .ga, .cf, .gq, .xyz, etc.). Legitimate businesses rarely register on these TLDs.',
    P_BRAND:  'The domain contains a well-known brand name (PayPal, Apple, Microsoft, Google, etc.) but is NOT the official domain for that brand. Classic phishing: "paypal-secure.com", "apple.com.verify.tk".',
    P_DIGIT:  'The domain uses digit substitution (0 for o, 1 for i/l, 3 for e) — typosquatting/impersonation. Examples: "paypa1.com", "g00gle.com", "micros0ft.com".',
    P_KW:     'The registered domain itself contains security-sensitive words like login, secure, verify, update, banking. Legitimate sites put these in URL paths, not domain names. Classic phishing pattern.',
    P4:       'The visible link text shows one URL (e.g. "paypal.com") but the actual href destination is a different domain. Classic phishing: display a trusted brand, link to a malicious site.',
    P5c:      'The URL has an unusually deep subdomain chain (4+ levels). Often used to hide the actual registered domain to the far right, e.g. "secure.login.verify.evil.com".',
    P_HYP:    'Multiple hyphens in the domain are a common typosquatting signal. Legitimate branded domains rarely use more than one hyphen. Example: "my-bank-secure-login.com".',
    P8:       'The URL contains a redirect parameter (url=, redirect=, goto=, return=, etc.) that forwards the browser elsewhere. Used to chain a legitimate-looking domain to a malicious destination.',
    P_SHORT:  'This is a URL shortener service (bit.ly, t.co, tinyurl, etc.). The real destination is completely hidden. Vigil cannot evaluate the final destination without following the redirect.',
    P10:      'The URL is unusually long (150+ characters). Very long URLs are sometimes used to hide the real destination through visual noise, or to stuff obfuscated redirect parameters.',
    P_ENC:    'The hostname contains URL-encoded characters (%XX sequences). Legitimate domain names never use percent-encoding. This is an obfuscation technique to evade detection.',
    P_AT:     'The URL contains multiple @ signs, exploiting how browsers handle credentials. The browser navigates to the part after the last @, while users see the (fake) trusted host before it.',
    P6:       'The URL uses a dangerous scheme (javascript:, data:, vbscript:) instead of http/https. These execute code directly in the browser when clicked. Never legitimate in a hyperlink.',
    P7:       'Google Safe Browsing has confirmed this URL is associated with malware, phishing, or unwanted software. This is a live database of actively malicious URLs maintained by Google.',
  };

  // ── Homograph detection ────────────────────────────────────────────────────
  function containsHomograph(hostname) {
    if (/xn--/i.test(hostname)) return true;
    for (const ch of hostname) { if (ch.codePointAt(0) > 127) return true; }
    return false;
  }

  // ── Anchor text mismatch ───────────────────────────────────────────────────
  function anchorMismatch(anchor, destHost) {
    const text = (anchor.textContent || '').trim().toLowerCase();
    if (!text || text.length < 5) return 0;
    if (!/^https?:\/\//i.test(text) && !/^www\./i.test(text)) return 0;
    let displayHost;
    try {
      displayHost = new URL(text.startsWith('http') ? text : 'https://' + text)
        .hostname.toLowerCase().replace(/^www\./, '');
    } catch { return 0; }
    const actual = destHost.toLowerCase().replace(/^www\./, '');
    if (displayHost === actual) return 0;
    if (actual.endsWith('.' + displayHost) || displayHost.endsWith('.' + actual)) return 1;
    if (displayHost.split('.').slice(-2).join('.') === actual.split('.').slice(-2).join('.')) return 2;
    return 3;
  }

  // ── Core scorer ────────────────────────────────────────────────────────────
  function scoreUrl(urlStr, anchorEl = null) {
    let absoluteUrl;
    try { absoluteUrl = new URL(urlStr, window.location.href).href; }
    catch { return { score:5, params:[{id:'P6',label:'Unparseable URL',severity:'critical',penalty:95}], url:urlStr, gsbHit:false }; }

    const scheme = absoluteUrl.split(':')[0].toLowerCase();
    if (!['http','https','javascript','data','vbscript'].includes(scheme)) return null;

    if (/^(javascript|data|vbscript):/i.test(absoluteUrl))
      return { score:0, params:[{id:'P6',label:'Dangerous scheme (javascript:/data:)',severity:'critical',penalty:100}], url:absoluteUrl, gsbHit:false };

    let parsed;
    try { parsed = new URL(absoluteUrl); } catch { return null; }
    try { if (new URL(absoluteUrl).origin === window.location.origin) return null; } catch {}

    const hostname = parsed.hostname.toLowerCase();
    const host     = hostname.replace(/^www\./, '');
    const parts    = host.split('.');
    const tld      = parts[parts.length - 1];
    const apex     = parts.slice(-2).join('.');
    const stem     = parts.slice(0, -1).join('.');
    const trusted  = TRUSTED_APEXES.has(apex);

    let totalPenalty = BASELINE;
    const params = [];
    const add = (id, label, severity, p) => { params.push({id, label, severity, penalty:p}); totalPenalty += p; };

    if (parsed.protocol === 'http:')                                     add('P1',     'Plain HTTP — unencrypted connection',                             'high',     30);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname))                      add('P_IP',   'Raw IP address — no domain name',                                 'high',     40);
    if (containsHomograph(hostname))                                      add('P3',     'Homograph/IDN attack — lookalike characters in domain',            'critical', 50);
    if (parsed.username || parsed.password)                               add('P_CRED', 'Credentials embedded in URL',                                     'critical', 50);
    if (parsed.port && !['80','443',''].includes(parsed.port))            add('P_PORT', 'Non-standard port :' + parsed.port,                               'medium',   18);
    if (BAD_TLDS.has(tld))                                                add('P9',     'High-risk free/phishing TLD (.' + tld + ')',                       'high',     28);
    if (!trusted) {
      for (const b of BRANDS) {
        if (host.includes(b)) { add('P_BRAND', 'Brand impersonation — "' + b + '" in non-official domain', 'critical', 45); break; }
      }
    }
    if (!trusted && /[0-9]/.test(parts.slice(0,-1).join('')))            add('P_DIGIT','Digit substitution in domain — impersonation signal',             'high',     25);
    if (!trusted) {
      const hits = SUSPICIOUS_KW.filter(k => stem.includes(k)).length;
      if (hits >= 2)     add('P_KW', 'Multiple suspicious keywords in domain (' + hits + ' matches)', 'high',   30);
      else if (hits ===1) add('P_KW', 'Suspicious keyword in domain stem',                             'medium', 15);
    }
    if (anchorEl) {
      const mm = anchorMismatch(anchorEl, hostname);
      if (mm === 1) add('P4', 'Anchor text mismatch — minor subdomain difference',                 'low',      10);
      if (mm === 2) add('P4', 'Anchor text mismatch — displayed domain differs from actual',       'medium',   25);
      if (mm === 3) add('P4', 'Anchor text mismatch — displayed domain is completely different',   'critical', 45);
    }
    if (parts.length >= 5)                     add('P5c', 'Deeply nested subdomains (' + (parts.length-1) + ' levels)', 'medium', 20);
    else if (parts.length >= 4 && !trusted)    add('P5c', 'Multiple subdomains (' + (parts.length-1) + ' levels)',      'low',     8);
    const hyphens = (stem.match(/-/g) || []).length;
    if (hyphens >= 4)      add('P_HYP', 'Many hyphens in domain (' + hyphens + ') — typosquatting', 'medium', 20);
    else if (hyphens >= 2) add('P_HYP', 'Multiple hyphens in domain (' + hyphens + ')',              'low',    10);
    if (/[?&](url|redirect|return|goto|next|target|dest|location|forward|continue|redir)=/i.test(parsed.search))
                                                                          add('P8',     'Open redirect parameter in query string',                          'medium',   20);
    if (SHORTENERS.has(host))                                             add('P_SHORT','URL shortener — real destination is hidden',                       'medium',   25);
    if (absoluteUrl.length > 300)                                         add('P10',    'Very long URL (' + absoluteUrl.length + ' chars) — obfuscation',   'low',      18);
    else if (absoluteUrl.length > 150)                                    add('P10',    'Long URL (' + absoluteUrl.length + ' chars)',                       'low',       8);
    if (/%[0-9a-f]{2}/i.test(hostname))                                   add('P_ENC',  'URL-encoded characters in hostname',                               'high',     25);
    if ((absoluteUrl.match(/@/g)||[]).length > 1)                         add('P_AT',   'Multiple @ signs — URL confusion attack',                          'critical', 40);

    const score = Math.max(0, Math.min(100, 100 - totalPenalty));
    return { score, params, url: absoluteUrl, gsbHit: false };
  }

  // ── Tooltip builder ────────────────────────────────────────────────────────
  let currentTip = null;
  let currentTipAnchor = null;
  let hideTimer = null;
  let hoverTimer = null;

  function buildTooltip(result) {
    const t   = tier(result.score);
    const url = result.url.length > 64 ? result.url.slice(0, 61) + '…' : result.url;
    const arcR = 18, arcC = +(2 * Math.PI * arcR).toFixed(1);
    const arcD = +((result.score / 100) * arcC).toFixed(1);
    const totalPen = Math.min(100, BASELINE + result.params.reduce((a,p) => a + p.penalty, 0));

    const makeRow = (id, label, severity, penalty) => {
      const desc = PARAM_DESC[id] || 'No additional detail available.';
      const col  = id === 'baseline' ? '#555' : severityColor(severity);
      const pen  = id === 'baseline' ? BASELINE : penalty;
      return `<div class="vr"><div class="vh" data-id="${id}"><span class="vd" style="background:${col}"></span><span class="vn">${label}</span><span class="vp" style="color:${col}">−${pen}</span><span class="vi">ⓘ</span></div><div class="vx">${desc}</div></div>`;
    };

    const rows = [makeRow('baseline','External link baseline distrust','',0)]
      .concat(result.params.map(p => makeRow(p.id, p.label, p.severity, p.penalty)))
      .join('');

    const clean = result.params.length === 0
      ? `<div style="font-size:11px;color:#4caf50;padding:4px 0 2px;">No flags detected beyond baseline.</div>` : '';

    const gsb = result.gsbHit
      ? `<div style="margin-top:6px;padding:5px 8px;background:rgba(244,67,54,0.12);border:1px solid rgba(244,67,54,0.35);border-radius:4px;font-size:10px;color:#f44336;font-weight:700;">☠ Google Safe Browsing confirmed malicious</div>` : '';

    return `<div id="vls-tip" style="z-index:2147483647;position:fixed;background:#10101c;border:1px solid ${t.border};border-top:3px solid ${t.border};border-radius:10px;width:312px;box-shadow:0 12px 44px rgba(0,0,0,0.82);font-family:system-ui,-apple-system,sans-serif;font-size:12px;color:#e0e0e0;pointer-events:auto;user-select:none;">
<style>
.vr{margin-bottom:1px;}
.vh{display:flex;align-items:center;gap:5px;cursor:pointer;padding:4px 2px;border-radius:4px;transition:background 0.12s;}
.vh:hover{background:rgba(255,255,255,0.04);}
.vd{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.vn{flex:1;font-size:11px;color:#ccc;line-height:1.4;}
.vp{font-size:11px;font-weight:700;flex-shrink:0;min-width:28px;text-align:right;}
.vi{font-size:10px;color:#444;flex-shrink:0;padding-left:2px;transition:color 0.12s;}
.vh:hover .vi{color:#7b8cde;}
.vx{display:none;font-size:10px;color:#666;line-height:1.6;padding:5px 8px 6px 14px;margin:2px 0 5px 0;border-left:2px solid #1e1e3a;border-radius:0 4px 4px 0;background:rgba(0,0,0,0.22);}
.vx.open{display:block;}
</style>
<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-bottom:1px solid #1a1a32;">
  <div style="position:relative;flex-shrink:0;width:44px;height:44px;">
    <svg width="44" height="44" style="transform:rotate(-90deg);">
      <circle cx="22" cy="22" r="${arcR}" fill="none" stroke="#1a1a32" stroke-width="3.5"/>
      <circle cx="22" cy="22" r="${arcR}" fill="none" stroke="${t.color}" stroke-width="3.5" stroke-dasharray="${arcD} ${arcC}" stroke-linecap="round"/>
    </svg>
    <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800;color:${t.color};">${result.score}</div>
  </div>
  <div style="flex:1;min-width:0;">
    <div style="font-size:14px;font-weight:700;color:${t.color};">${t.icon} ${t.label}</div>
    <div style="font-size:10px;color:#444;margin-top:1px;">Vigil Link Score — hover to keep open</div>
  </div>
</div>
<div style="padding:5px 12px;font-size:10px;color:#333;word-break:break-all;border-bottom:1px solid #1a1a32;background:#0c0c18;">${url}</div>
<div style="padding:8px 12px;max-height:240px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e1e3a transparent;">
  <div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#2a2a4a;margin-bottom:7px;">Score breakdown — click ⓘ to expand</div>
  ${rows}${clean}${gsb}
</div>
<div style="padding:5px 12px;border-top:1px solid #1a1a32;display:flex;justify-content:space-between;align-items:center;">
  <span style="font-size:9px;color:#222;">Vigil v4.0</span>
  <span style="font-size:10px;color:#333;">100 − ${totalPen} = <b style="color:${t.color}">${result.score}</b></span>
</div>
</div>`;
  }

  function bindExpandCollapse(tip) {
    tip.querySelectorAll('.vh').forEach(head => {
      head.addEventListener('click', e => {
        e.stopPropagation();
        const detail = head.nextElementSibling;
        if (!detail || !detail.classList.contains('vx')) return;
        const open = detail.classList.toggle('open');
        const icon = head.querySelector('.vi');
        if (icon) icon.textContent = open ? '▴' : 'ⓘ';
      });
    });
  }

  function showTip(result, anchor) {
    removeTip();
    const tmp = document.createElement('div');
    tmp.innerHTML = buildTooltip(result);
    const tip = tmp.firstElementChild;
    document.documentElement.appendChild(tip);
    currentTip = tip;
    currentTipAnchor = anchor;

    tip.addEventListener('mouseenter', () => clearTimeout(hideTimer));
    tip.addEventListener('mouseleave', () => { hideTimer = setTimeout(removeTip, 200); });
    bindExpandCollapse(tip);
    positionTip(anchor);
  }

  function positionTip(anchor) {
    const tip = currentTip;
    if (!tip) return;
    const rect = typeof anchor.getBoundingClientRect === 'function'
      ? anchor.getBoundingClientRect() : { top:0, left:0, bottom:0, right:0 };
    const tipW = 316, tipH = tip.offsetHeight || 290;
    const vw = window.innerWidth, vh = window.innerHeight;
    let left = rect.left, top = rect.bottom + 8;
    if (left + tipW > vw - 12) left = vw - tipW - 12;
    if (left < 8) left = 8;
    if (top + tipH > vh - 12) top = rect.top - tipH - 8;
    if (top < 8) top = 8;
    tip.style.left = left + 'px';
    tip.style.top  = top + 'px';
  }

  function removeTip() {
    clearTimeout(hoverTimer);
    hoverTimer = null;
    currentTip?.remove();
    currentTip = null;
    currentTipAnchor = null;
  }

  // ── Result store ───────────────────────────────────────────────────────────
  const pageResults = new Map();

  // ── Attach hover — 2 second delay ─────────────────────────────────────────
  function attachHover(anchor, result) {
    if (anchor.hasAttribute(SCORED_ATTR)) return;
    anchor.setAttribute(SCORED_ATTR, String(result.score));

    const t = tier(result.score);
    if (result.score < 80) {
      anchor.addEventListener('mouseenter', () => { anchor.style.textDecorationColor = t.color; });
      anchor.addEventListener('mouseleave', () => { anchor.style.textDecorationColor = ''; });
    }

    anchor.addEventListener('mouseenter', () => {
      clearTimeout(hideTimer);
      hoverTimer = setTimeout(() => showTip(result, anchor), 2000);
    });

    anchor.addEventListener('mouseleave', () => {
      clearTimeout(hoverTimer);
      hideTimer = setTimeout(() => {
        if (currentTipAnchor === anchor) removeTip();
      }, 200);
    });
  }

  // ── Text-selection scanner ─────────────────────────────────────────────────
  function setupTextSelectionScanner() {
    document.addEventListener('mouseup', e => {
      setTimeout(() => {
        const sel = window.getSelection()?.toString().trim() || '';
        if (sel.length < 10 || sel.length > 2000) return;
        const m = sel.match(/https?:\/\/[^\s"'<>]+/i);
        if (!m) return;
        const rawUrl = m[0].replace(/[.,;:!?)]+$/, '');
        let parsed;
        try { parsed = new URL(rawUrl); } catch { return; }
        if (!['http:','https:'].includes(parsed.protocol)) return;
        try { if (parsed.origin === window.location.origin) return; } catch {}
        const result = scoreUrl(rawUrl, null);
        if (!result) return;
        showSelectionTip(result, e.clientX, e.clientY);
      }, 50);
    });
  }

  function showSelectionTip(result, cx, cy) {
    document.getElementById('vls-sel-tip')?.remove();
    const tmp = document.createElement('div');
    tmp.innerHTML = buildTooltip(result);
    const tip = tmp.firstElementChild;
    tip.id = 'vls-sel-tip';
    const vw = window.innerWidth, vh = window.innerHeight;
    let left = cx + 10, top = cy + 10;
    if (left + 316 > vw - 12) left = vw - 316 - 12;
    if (top + 290 > vh - 12) top = cy - 300;
    tip.style.left = left + 'px';
    tip.style.top  = top + 'px';
    document.documentElement.appendChild(tip);
    bindExpandCollapse(tip);
    const dismiss = ev => { if (!tip.contains(ev.target)) { tip.remove(); document.removeEventListener('mousedown', dismiss); } };
    setTimeout(() => document.addEventListener('mousedown', dismiss), 10);
    setTimeout(() => { if (tip.isConnected) tip.remove(); }, 30000);
  }

  // ── Main scanner ───────────────────────────────────────────────────────────
  async function scanLinks(root = document) {
    const anchors = Array.from(root.querySelectorAll('a[href]'))
      .filter(a => !a.hasAttribute(SCORED_ATTR));
    for (const anchor of anchors) {
      const href = anchor.getAttribute('href') || '';
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) continue;
      const result = scoreUrl(href, anchor);
      if (!result) continue;
      pageResults.set(result.url, result);
      attachHover(anchor, result);
    }
    const suspicious = [...pageResults.values()].filter(r => r.score < 80 && !r.gsbHit);
    if (!suspicious.length) return;
    const { vigil_gsb_key } = await chrome.storage.local.get('vigil_gsb_key').catch(() => ({}));
    if (!vigil_gsb_key) return;
    const hits = await checkGSB(suspicious.map(r => r.url).slice(0, 500), vigil_gsb_key);
    for (const [, result] of pageResults) {
      if (hits.has(result.url)) {
        result.gsbHit = true;
        result.score  = Math.min(result.score, 5);
        result.params.unshift({id:'P7', label:'Google Safe Browsing — confirmed malicious', severity:'critical', penalty:95});
      }
    }
  }

  async function checkGSB(urls, apiKey) {
    const hits = new Set();
    if (!apiKey || !urls.length) return hits;
    try {
      const res = await fetch(`${GSB_ENDPOINT}?key=${apiKey}`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          client: { clientId:'vigil-extension', clientVersion:'4.0.0' },
          threatInfo: {
            threatTypes:      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes:    ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries:    urls.map(u => ({ url:u })),
          }
        })
      });
      const json = await res.json();
      (json.matches || []).forEach(m => hits.add(m.threat?.url));
    } catch (err) { console.warn('[Vigil LinkScorer] GSB check failed:', err.message); }
    return hits;
  }

  function watchMutations() {
    let debounce = null;
    new MutationObserver(() => {
      clearTimeout(debounce);
      debounce = setTimeout(() => scanLinks(), 1200);
    }).observe(document.body, { childList:true, subtree:true });
  }

  async function init() {
    const skip = ['chrome://','chrome-extension://','moz-extension://','about:','file://','data:','blob:'];
    if (skip.some(p => location.href.startsWith(p))) return;

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        clearTimeout(hoverTimer);
        removeTip();
        document.getElementById('vls-sel-tip')?.remove();
      }
    });
    document.addEventListener('mouseover', e => {
      if (currentTip && currentTip.contains(e.target)) clearTimeout(hideTimer);
    });

    await scanLinks();
    watchMutations();
    setupTextSelectionScanner();

    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (msg.action === 'rescanLinks') {
        document.querySelectorAll(`[${SCORED_ATTR}]`).forEach(el => el.removeAttribute(SCORED_ATTR));
        pageResults.clear(); removeTip(); document.getElementById('vls-sel-tip')?.remove();
        scanLinks().then(() => sendResponse({ ok:true }));
        return true;
      }
      if (msg.action === 'getLinkReport') {
        sendResponse({ links: [...pageResults.values()].map(r => ({
          url: r.url, score: r.score, label: tier(r.score).label,
          params: r.params.map(p => p.label), gsbHit: r.gsbHit,
        }))});
        return true;
      }
      if (msg.action === 'checkSingleUrl') {
        const result = scoreUrl(msg.url, null);
        if (!result) { sendResponse({ error:'Could not parse URL' }); return true; }
        const tk = tier(result.score);
        sendResponse({ score:result.score, label:tk.label, color:tk.color, params:result.params, url:result.url });
        return true;
      }
    });

    console.log('[Vigil] linkScorer v4.0 loaded on', location.hostname);
  }

  return { init, scoreUrl, tier };
})();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => LinkScorer.init());
} else {
  LinkScorer.init();
}