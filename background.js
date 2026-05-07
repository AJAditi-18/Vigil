// Vigil — Background Service Worker v1.5
'use strict';

const TAB_KEY = 'vigil_tabs';

// ─────────────────────────────────────────────────────────────────────────────
// MODULE 2 — Network
// ─────────────────────────────────────────────────────────────────────────────

let disconnectMap     = null;
let disconnectLoading = false;
const networkState    = new Map();
const PUSH_INTERVAL   = 2000;

async function loadDisconnectList() {
  if (disconnectMap)     return disconnectMap;
  if (disconnectLoading) {
    for (let i = 0; i < 50; i++) {
      await sleep(100);
      if (disconnectMap) return disconnectMap;
    }
    return new Map();
  }
  disconnectLoading = true;
  disconnectMap     = new Map();
  try {
    const res  = await fetch(chrome.runtime.getURL('data/disconnect.json'));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    Object.entries(json.categories || {}).forEach(([category, companies]) => {
      Object.values(companies).forEach(company => {
        Object.values(company).forEach(entry => {
          if (Array.isArray(entry)) entry.forEach(d => disconnectMap.set(d.toLowerCase(), category));
        });
      });
    });
    console.log(`[Vigil BG] Disconnect list loaded: ${disconnectMap.size} domains`);
  } catch (err) {
    console.error('[Vigil BG] disconnect.json failed:', err.message);
  }
  disconnectLoading = false;
  return disconnectMap;
}

const CATEGORY_INFO = {
  'Advertising':    { label:'Ad network',            color:'#f44336', bg:'rgba(244,67,54,0.15)',   trust:0, tier:'red'    },
  'Analytics':      { label:'Analytics',             color:'#ff9800', bg:'rgba(255,152,0,0.15)',   trust:2, tier:'orange' },
  'Social':         { label:'Social tracker',        color:'#9c27b0', bg:'rgba(156,39,176,0.15)',  trust:1, tier:'orange' },
  'Fingerprinting': { label:'Fingerprinter',         color:'#e91e63', bg:'rgba(233,30,99,0.15)',   trust:0, tier:'red'    },
  'Cryptomining':   { label:'Cryptominer',           color:'#ff5722', bg:'rgba(255,87,34,0.15)',   trust:0, tier:'red'    },
  'Content':        { label:'Content delivery',      color:'#607d8b', bg:'rgba(96,125,139,0.15)',  trust:3, tier:'blue'   },
  'Disconnect':     { label:'Tracked by Disconnect', color:'#ff9800', bg:'rgba(255,152,0,0.15)',   trust:1, tier:'orange' },
};

function lookupTracker(hostname, map) {
  if (!hostname || !map || map.size === 0) return null;
  const host = hostname.toLowerCase().replace(/^www\./, '');
  if (map.has(host)) { const cat = map.get(host); return { category: cat, ...(CATEGORY_INFO[cat] || {}) }; }
  const parts = host.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    if (map.has(parent)) { const cat = map.get(parent); return { category: cat, ...(CATEGORY_INFO[cat] || {}) }; }
  }
  return null;
}

function extractContentLength(details) {
  if (details.responseHeaders) {
    const cl = details.responseHeaders.find(h => h.name.toLowerCase() === 'content-length');
    if (cl && cl.value) return parseInt(cl.value, 10) || 0;
  }
  return details.responseHeadersSize || 0;
}

async function ensureState(tabId, fallbackUrl = 'unknown') {
  if (!networkState.has(tabId)) {
    let tabUrl = fallbackUrl;
    try { const t = await chrome.tabs.get(tabId); tabUrl = t.url || fallbackUrl; } catch { }
    networkState.set(tabId, { url: tabUrl, domains: new Map(), totalBytes: 0, blocked: 0 });
  }
  return networkState.get(tabId);
}

chrome.webRequest.onCompleted.addListener(async (details) => {
  if (!details.url.startsWith('http') || details.tabId < 0) return;
  const dmap = await loadDisconnectList();
  let hostname;
  try { hostname = new URL(details.url).hostname.toLowerCase(); } catch { return; }
  const state = await ensureState(details.tabId);
  if (!state.domains.has(hostname)) {
    const info = lookupTracker(hostname, dmap);
    state.domains.set(hostname, { hostname, count: 0, isTracker: !!info, category: info?.category || null, trackerInfo: info, tier: info?.tier || null, blocked: false });
  }
  const entry = state.domains.get(hostname);
  entry.count++;
  state.totalBytes += extractContentLength(details);
}, { urls: ['<all_urls>'], types: ['xmlhttprequest','script','image','stylesheet','font','other'] });

chrome.webRequest.onErrorOccurred.addListener(async (details) => {
  if (!details.url.startsWith('http') || details.tabId < 0) return;
  if (!details.error || !details.error.includes('BLOCKED')) return;
  const dmap = await loadDisconnectList();
  let hostname;
  try { hostname = new URL(details.url).hostname.toLowerCase(); } catch { return; }
  const state = await ensureState(details.tabId);
  if (!state.domains.has(hostname)) {
    const info = lookupTracker(hostname, dmap);
    state.domains.set(hostname, { hostname, count: 0, isTracker: !!info, category: info?.category || null, trackerInfo: info, tier: info?.tier || null, blocked: true });
  }
  const entry = state.domains.get(hostname);
  entry.count++;
  entry.blocked = true;
  state.blocked = (state.blocked || 0) + 1;
}, { urls: ['<all_urls>'] });

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !details.url.startsWith('http')) return;
  networkState.set(details.tabId, { url: details.url, domains: new Map(), totalBytes: 0, blocked: 0 });
});

function buildReport(tabId) {
  const s = networkState.get(tabId);
  if (!s) return null;
  return { tabId, url: s.url, domains: Array.from(s.domains.values()), totalBytes: s.totalBytes || 0, blocked: s.blocked || 0, capturedAt: Date.now() };
}

setInterval(async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tab || tab.id < 0 || !networkState.has(tab.id)) return;
    const report = buildReport(tab.id);
    if (report) chrome.tabs.sendMessage(tab.id, { action: 'networkReport', data: report }).catch(() => {});
  } catch { }
}, PUSH_INTERVAL);

// ─────────────────────────────────────────────────────────────────────────────
// TAB LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

chrome.tabs.onCreated.addListener(async (tab) => {
  const data = await getTabData();
  data[tab.id] = { id: tab.id, url: tab.pendingUrl || tab.url || 'unknown', title: tab.title || 'New Tab', openedAt: Date.now(), lastVisited: Date.now(), visitCount: 0, read: false };
  await saveTabData(data);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const data = await getTabData();
  if (data[tabId]) { data[tabId].lastVisited = Date.now(); data[tabId].visitCount += 1; data[tabId].read = true; }
  await saveTabData(data);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const data = await getTabData();
  if (data[tabId]) { data[tabId].url = tab.url; data[tabId].title = tab.title; }
  else { data[tabId] = { id: tabId, url: tab.url, title: tab.title, openedAt: Date.now(), lastVisited: Date.now(), visitCount: 0, read: false }; }
  await saveTabData(data);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  networkState.delete(tabId);
  const data = await getTabData();
  if (data[tabId]) {
    const history = await getTabHistory();
    history.push({ ...data[tabId], closedAt: Date.now() });
    if (history.length > 100) history.shift();
    await chrome.storage.local.set({ vigil_tab_history: history });
    delete data[tabId];
    await saveTabData(data);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function getTabData()    { return (await chrome.storage.local.get(TAB_KEY))[TAB_KEY] || {}; }
async function saveTabData(d)  { await chrome.storage.local.set({ [TAB_KEY]: d }); }
async function getTabHistory() { return (await chrome.storage.local.get('vigil_tab_history'))['vigil_tab_history'] || []; }

// ─────────────────────────────────────────────────────────────────────────────
// ALARMS
// ─────────────────────────────────────────────────────────────────────────────

chrome.alarms.create('vigil_daily_cleanup',    { periodInMinutes: 1440 });
chrome.alarms.create('vigil_clipboard_expiry', { periodInMinutes: 5    });
chrome.alarms.create('vigil_legal_recheck',    { periodInMinutes: 60   });

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'vigil_clipboard_expiry') {
    chrome.tabs.query({}, tabs => {
      for (const tab of tabs) {
        if (tab.id && tab.id > 0) chrome.tabs.sendMessage(tab.id, { action: 'purgeClipboard' }).catch(() => {});
      }
    });
  }
  if (alarm.name === 'vigil_daily_cleanup') {
    chrome.tabs.query({}, tabs => {
      const liveIds = new Set(tabs.map(t => t.id));
      for (const id of networkState.keys()) { if (!liveIds.has(id)) networkState.delete(id); }
    });
  }
  if (alarm.name === 'vigil_legal_recheck') { recheckLegalLinks(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// LEGAL LINK RECHECK
// ─────────────────────────────────────────────────────────────────────────────

async function recheckLegalLinks() {
  let links;
  try { const res = await chrome.storage.local.get('vigil_legal_links'); links = res['vigil_legal_links'] || []; } catch { return; }
  if (!links.length) return;
  const hashes = ((await chrome.storage.local.get('vigil_legal_hashes'))['vigil_legal_hashes']) || {};
  for (const link of links) {
    try {
      const resp = await fetch(link.url, { cache: 'no-store', credentials: 'omit' });
      if (!resp.ok) continue;
      const text   = await resp.text();
      const sample = text.replace(/\s+/g, ' ').substring(0, 8000);
      const hash   = djb2(sample) + '_' + sample.length;
      if (hashes[link.url] && hashes[link.url] !== hash) {
        chrome.notifications.create(`vigil-legal-${Date.now()}`, {
          type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon2.png'),
          title: '⚖ Vigil — Legal document changed',
          message: `${link.label || link.domain}: "${link.url.replace(/^https?:\/\//, '').substring(0, 60)}" was updated.`,
        });
      }
      hashes[link.url] = hash;
    } catch { }
  }
  try { await chrome.storage.local.set({ vigil_legal_hashes: hashes }); } catch { }
}

function djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE ROUTER
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.action === 'openHistory') {
    // Resolve the page URL to deep-link into the right history entry.
    // Callers may pass msg.url (the active page's href) explicitly;
    // background falls back to the current active tab so the history page
    // auto-selects and scrolls to that entry instead of showing a blank panel.
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const pageUrl = msg.url || tabs?.[0]?.url || '';
      const base    = chrome.runtime.getURL('options/options.html');
      const dest    = pageUrl ? base + '?url=' + encodeURIComponent(pageUrl) : base;
      chrome.tabs.create({ url: dest });
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.action === 'showNotification') {
    const p = msg.payload || {};
    const legalPrefix = p.legalMode ? '⚖ Legal doc — ' : '';
    chrome.notifications.create(`vigil-${Date.now()}`, {
      type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon2.png'),
      title:   `Vigil — ${legalPrefix}Page changed (${p.severity || 'Change'})`,
      message: `${p.domain || 'Unknown site'}: +${p.added || 0} added, −${p.removed || 0} removed`
    });
    sendResponse({ ok: true });
    return;
  }

  if (msg.action === 'getNetworkReport') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      sendResponse(tabs?.[0] ? buildReport(tabs[0].id) : null);
    });
    return true;
  }

  if (msg.action === 'openNetworkReport') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      const report = buildReport(tab.id);
      const doOpen = () => { chrome.tabs.sendMessage(tab.id, { action: 'openNetworkReport', data: report }).catch(() => {}); sendResponse({ ok: true }); };
      if (report) { chrome.tabs.sendMessage(tab.id, { action: 'networkReport', data: report }).catch(() => {}).finally(doOpen); }
      else { doOpen(); }
    });
    return true;
  }

  if (msg.action === 'openTimeMachineOverlay') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'openTimeMachineOverlay' }).catch(() => {});
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.action === 'getSnapshotSummary') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab || !tab.url || !tab.url.startsWith('http')) { sendResponse(null); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'getSnapshotSummary' }, response => {
        if (chrome.runtime.lastError) sendResponse(null);
        else sendResponse(response);
      });
    });
    return true;
  }

  if (msg.action === 'openClipboardVault') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'openClipboardVault' }).catch(() => {});
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.action === 'getClipboardCount') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ count: 0 }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'getClipboardCount' }, response => {
        if (chrome.runtime.lastError) sendResponse({ count: 0 });
        else sendResponse(response || { count: 0 });
      });
    });
    return true;
  }

  // ── Link Scorer ────────────────────────────────────────────────────────────
  if (msg.action === 'rescanLinks') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'rescanLinks' }, response => {
        if (chrome.runtime.lastError) sendResponse({ ok: false });
        else sendResponse(response || { ok: true });
      });
    });
    return true;
  }

  if (msg.action === 'getLinkReport') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ links: [] }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'getLinkReport' }, response => {
        if (chrome.runtime.lastError) sendResponse({ links: [] });
        else sendResponse(response || { links: [] });
      });
    });
    return true;
  }

  if (msg.action === 'checkSingleUrl') {
    sendResponse(bgScoreUrl(msg.url));
    return true;
  }

  // ── Tab Debt ───────────────────────────────────────────────────────────────
  if (msg.action === 'openTabDebt') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      chrome.storage.local.get('vigil_tabs', result => {
        const tabArr = Object.values(result['vigil_tabs'] || {});
        chrome.tabs.sendMessage(tab.id, { action: 'openTabDebt', data: { tabs: tabArr } }).catch(() => {});
        sendResponse({ ok: true });
      });
    });
    return true;
  }

  // ── Form Shadow ────────────────────────────────────────────────────────────
  if (msg.action === 'getFormCount') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ count: 0 }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'getFormCount' }, response => {
        if (chrome.runtime.lastError) sendResponse({ count: 0 });
        else sendResponse(response || { count: 0 });
      });
    });
    return true;
  }

  // ── Module 7 — Privacy Score ──────────────────────────────────────────────
  if (msg.action === 'openPrivacyScore') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse({ ok: false }); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'openPrivacyScore' }, response => {
        if (chrome.runtime.lastError) sendResponse({ ok: false });
        else sendResponse(response || { ok: true });
      });
    });
    return true;
  }

  if (msg.action === 'getPrivacyScore') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
      const tab = tabs?.[0];
      if (!tab) { sendResponse(null); return; }
      chrome.tabs.sendMessage(tab.id, { action: 'getPrivacyScore' }, response => {
        if (chrome.runtime.lastError) sendResponse(null);
        else sendResponse(response);
      });
    });
    return true;
  }

});

// ─────────────────────────────────────────────────────────────────────────────
// UTILS + STARTUP
// ─────────────────────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }


// ─────────────────────────────────────────────────────────────────────────────
// LINK SCORER — self-contained URL scorer for popup (no content script needed)
// ─────────────────────────────────────────────────────────────────────────────

const BG_BRANDS = new Set(['paypal','apple','microsoft','google','amazon','netflix','facebook','instagram','twitter','whatsapp','linkedin','dropbox','icloud','wellsfargo','bankofamerica','chase','citibank','hsbc','barclays','ebay','steam','discord','github','adobe','spotify','yahoo','outlook','office','onedrive','sharepoint']);

const BG_TRUSTED_APEXES = new Set(['google.com','microsoft.com','apple.com','amazon.com','github.com','facebook.com','twitter.com','x.com','linkedin.com','instagram.com','paypal.com','netflix.com','spotify.com','adobe.com','dropbox.com','yahoo.com','outlook.com','discord.com','steampowered.com','ebay.com','amazon.co.uk','amazon.de','amazon.fr','bbc.com','bbc.co.uk','wikipedia.org','reddit.com','stackoverflow.com','cloudflare.com','akamai.com','fastly.com']);

const BG_SHORTENERS = new Set(['bit.ly','t.co','tinyurl.com','goo.gl','ow.ly','buff.ly','short.link','rb.gy','cutt.ly','is.gd','v.gd','tiny.cc','bl.ink','shorturl.at','lnkd.in']);

const BG_BAD_TLDS = new Set(['tk','ml','ga','cf','gq','xyz','top','click','download','loan','win','racing','review','stream','date','faith','science','party','trade','webcam','accountant','cricket','work','men','bid','pw','gdn','zip','mov']);

const BG_SUSPICIOUS_KW = ['login','signin','secure','verify','update','confirm','banking','webscr','checkout','password','credential','validate','suspend','unlock','recover'];

const BG_TIERS = [
  { min:80, label:'Safe',       color:'#4caf50' },
  { min:55, label:'Suspicious', color:'#ff9800' },
  { min:30, label:'Risky',      color:'#ff5722' },
  { min: 0, label:'Dangerous',  color:'#f44336' },
];
function bgTier(s) { return BG_TIERS.find(t => s >= t.min) || BG_TIERS[3]; }

function bgScoreUrl(rawUrl) {
  let url, parsed;
  try {
    const s = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl;
    url = new URL(s).href;
    parsed = new URL(url);
  } catch { return { error: 'Invalid URL' }; }

  if (/^(javascript|data|vbscript):/i.test(url))
    return { score:0, label:'Dangerous', color:'#f44336',
      params:[{id:'P6',label:'Dangerous scheme (javascript:/data:)',severity:'critical',penalty:100}], url };

  const hostname = parsed.hostname.toLowerCase();
  const host     = hostname.replace(/^www\./, '');
  const parts    = host.split('.');
  const tld      = parts[parts.length - 1];
  const apex     = parts.slice(-2).join('.');
  const stem     = parts.slice(0, -1).join('.');
  const trusted  = BG_TRUSTED_APEXES.has(apex);

  let penalty = 20;
  const params = [];
  const add = (id, label, severity, p) => { params.push({id, label, severity, penalty:p}); penalty += p; };

  if (parsed.protocol === 'http:') add('P1','Plain HTTP — unencrypted connection','high',30);

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) add('P_IP','Raw IP address — no domain name','high',40);

  if (/xn--/i.test(hostname)) { add('P3','Punycode/IDN — possible homograph attack','critical',50); }
  else { for (const ch of hostname) { if (ch.codePointAt(0)>127){add('P3','Non-ASCII characters in hostname','critical',50);break;} } }

  if (parsed.username || parsed.password) add('P_CRED','Credentials embedded in URL','critical',50);
  if (parsed.port && !['80','443',''].includes(parsed.port)) add('P_PORT','Non-standard port :'+parsed.port,'medium',18);
  if (BG_BAD_TLDS.has(tld)) add('P9','High-risk free/phishing TLD (.'+tld+')','high',28);

  if (!trusted) {
    for (const b of BG_BRANDS) {
      if (host.includes(b)) { add('P_BRAND','Brand impersonation — "'+b+'" in non-official domain','critical',45); break; }
    }
  }

  if (!trusted && /[0-9]/.test(parts.slice(0,-1).join(''))) add('P_DIGIT','Digit substitution in domain — impersonation signal','high',25);

  if (!trusted) {
    const hits = BG_SUSPICIOUS_KW.filter(k => stem.includes(k)).length;
    if (hits >= 2) add('P_KW','Multiple suspicious keywords in domain ('+hits+' matches)','high',30);
    else if (hits === 1) add('P_KW','Suspicious keyword in domain','medium',15);
  }

  if (parts.length >= 5) add('P5c','Deeply nested subdomains ('+( parts.length-1)+' levels)','medium',20);
  else if (parts.length >= 4 && !trusted) add('P5c','Multiple subdomains ('+(parts.length-1)+' levels)','low',8);

  const hyphens = (stem.match(/-/g) || []).length;
  if (hyphens >= 4) add('P_HYP','Many hyphens in domain ('+hyphens+') — typosquatting','medium',20);
  else if (hyphens >= 2) add('P_HYP','Multiple hyphens in domain ('+hyphens+')','low',10);

  if (/[?&](url|redirect|return|goto|next|target|dest|location|forward|continue|redir)=/i.test(parsed.search))
    add('P8','Open redirect parameter in query string','medium',20);

  if (BG_SHORTENERS.has(host)) add('P_SHORT','URL shortener — real destination is hidden','medium',25);

  if (url.length > 300) add('P10','Very long URL ('+url.length+' chars) — obfuscation','low',18);
  else if (url.length > 150) add('P10','Long URL ('+url.length+' chars)','low',8);

  if (/%[0-9a-f]{2}/i.test(hostname)) add('P_ENC','URL-encoded characters in hostname','high',25);
  if ((url.match(/@/g)||[]).length > 1) add('P_AT','Multiple @ signs — URL confusion attack','critical',40);

  const score = Math.max(0, Math.min(100, 100 - penalty));
  const t = bgTier(score);
  return { score, label: t.label, color: t.color, params, url };
}

loadDisconnectList().then(() => {
  console.log('[Vigil] Background worker v1.6 ready.');
});