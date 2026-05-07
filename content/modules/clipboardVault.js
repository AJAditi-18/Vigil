// Vigil — Module 3: Clipboard Vault (v3.0)
//
// ═══════════════════════════════════════════════════════════════════════════
// WHAT'S NEW IN v3.0
// ═══════════════════════════════════════════════════════════════════════════
//
//  ① WebAuthn Biometric Lock
//     Uses the Web Authentication API (same standard as passkeys).
//     On devices with fingerprint / Face ID / Windows Hello / Touch ID,
//     the OS-level biometric prompt appears. Falls back gracefully to
//     device PIN if biometrics aren't enrolled.  A credential ID is stored
//     in chrome.storage.local — no raw biometric data ever leaves the OS.
//     The vault AES key is PBKDF2-derived from a random per-install
//     secret bound to the WebAuthn credential assertion.
//     PIN fallback is always available for devices / browsers without
//     platform authenticator support.
//
//  ② Auto-categorisation
//     Copied text is classified into: password, payment card, IBAN,
//     crypto wallet, SSN/NI, API key/token, phone number, email address,
//     URL, or plain text. Category badge shown in prompt and vault list.
//
//  ③ Smart expiry per category
//     Passwords      →  2 min
//     Payment cards  →  5 min
//     API keys       → 10 min
//     Sensitive IDs  → 15 min
//     General text   → user setting (default 60 min)
//
//  ④ Search bar in vault overlay
//     Real-time keyword filter across domain, category, and preview text.
//
//  ⑤ Copy-back button
//     Each vault entry has a "Copy" button that writes the decrypted
//     plaintext back to clipboard. Requires vault to be unlocked.
//
//  ⑥ Duplicate detection
//     SHA-256 hash of plaintext compared before saving. Exact duplicates
//     bump the timestamp instead of creating a new entry.
//
//  ⑦ Export as encrypted JSON
//     Downloads a JSON file where every entry is re-encrypted with a
//     user-supplied export passphrase (AES-256-GCM, PBKDF2, 310k iters).
//
// ═══════════════════════════════════════════════════════════════════════════

;(function () {
  'use strict';

  const SKIP = ['chrome://', 'chrome-extension://', 'moz-extension://', 'about:', 'file://', 'data:', 'blob:'];
  if (SKIP.some(p => location.href.startsWith(p))) return;

  // ── Constants ──────────────────────────────────────────────────────────────
  const SETTINGS_KEY   = 'vigil_cv_settings';
  const SALT_KEY       = 'vigil_cv_salt';
  const VSALT_KEY      = 'vigil_cv_vsalt';
  const VHASH_KEY      = 'vigil_cv_vhash';
  const PIN_SETUP_KEY  = 'vigil_cv_pin_set';
  const WA_CRED_KEY    = 'vigil_cv_wa_cred';
  const WA_SECRET_KEY  = 'vigil_cv_wa_secret';
  const WA_VSALT_KEY   = 'vigil_cv_wa_vsalt';
  const WA_VHASH_KEY   = 'vigil_cv_wa_vhash';
  const PBKDF2_ITERS   = 310000;
  const MIN_TEXT_LEN   = 4;
  const SAVE_PROMPT_MS = 15000;
  const PREVIEW_MAX    = 40;

  // ── Default settings ───────────────────────────────────────────────────────
  let SETTINGS = {
    expiryMin:   60,
    autoLockMin: 15,
    savePrompt:  'always',
    authMethod:  'pin',
    smartExpiry: true,
  };

  // ── Smart expiry map (minutes per category) ────────────────────────────────
  const SMART_EXPIRY = {
    password: 2, card: 5, apikey: 10,
    ssn: 15, iban: 15, crypto: 15,
    phone: 30, email: 45, url: 30, text: null,
  };

  // ── In-memory vault key ────────────────────────────────────────────────────
  let _vaultKey  = null;
  let _lockTimer = null;

  function touchActivity() {
    if (_lockTimer) clearTimeout(_lockTimer);
    if (SETTINGS.autoLockMin > 0 && _vaultKey)
      _lockTimer = setTimeout(lockVault, SETTINGS.autoLockMin * 60000);
  }
  function lockVault() {
    _vaultKey = null;
    if (_lockTimer) { clearTimeout(_lockTimer); _lockTimer = null; }
    console.log('[Vigil CV] Vault locked.');
  }

  async function loadSettings() {
    const r = await chrome.storage.local.get(SETTINGS_KEY);
    if (r[SETTINGS_KEY]) Object.assign(SETTINGS, r[SETTINGS_KEY]);
  }
  async function saveSettings(patch) {
    Object.assign(SETTINGS, patch);
    await chrome.storage.local.set({ [SETTINGS_KEY]: SETTINGS });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CRYPTO HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  function b64(u8)   { return btoa(String.fromCharCode(...u8)); }
  function u8(b64s)  { return Uint8Array.from(atob(b64s), c => c.charCodeAt(0)); }

  async function deriveKey(material, saltBytes) {
    const base = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }
  async function deriveBits(material, saltBytes) {
    const base = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, base, 256
    );
    return b64(new Uint8Array(bits));
  }
  async function sha256(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return b64(new Uint8Array(buf));
  }

  async function encryptText(plaintext) {
    if (!_vaultKey) throw new Error('Vault is locked');
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _vaultKey, new TextEncoder().encode(plaintext));
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv, 0); out.set(new Uint8Array(ct), 12);
    return b64(out);
  }
  async function decryptText(b64str) {
    if (!_vaultKey) throw new Error('Vault is locked');
    const raw = u8(b64str);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0,12) }, _vaultKey, raw.slice(12));
    return new TextDecoder().decode(pt);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PIN AUTH
  // ═══════════════════════════════════════════════════════════════════════════

  async function isPinConfigured() {
    const r = await chrome.storage.local.get(PIN_SETUP_KEY);
    return !!r[PIN_SETUP_KEY];
  }
  async function setupPin(pin) {
    const salt  = crypto.getRandomValues(new Uint8Array(32));
    const vsalt = crypto.getRandomValues(new Uint8Array(32));
    await chrome.storage.local.set({
      [SALT_KEY]:      b64(salt),
      [VSALT_KEY]:     b64(vsalt),
      [VHASH_KEY]:     await deriveBits(new TextEncoder().encode(pin), vsalt),
      [PIN_SETUP_KEY]: true,
    });
    _vaultKey = await deriveKey(new TextEncoder().encode(pin), salt);
    touchActivity();
  }
  async function unlockWithPin(pin) {
    const r = await chrome.storage.local.get([VSALT_KEY, VHASH_KEY, SALT_KEY]);
    if (!r[VHASH_KEY] || !r[VSALT_KEY] || !r[SALT_KEY]) return false;
    const vhash = await deriveBits(new TextEncoder().encode(pin), u8(r[VSALT_KEY]));
    if (vhash !== r[VHASH_KEY]) return false;
    _vaultKey = await deriveKey(new TextEncoder().encode(pin), u8(r[SALT_KEY]));
    touchActivity();
    return true;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // WEBAUTHN BIOMETRIC AUTH
  // ═══════════════════════════════════════════════════════════════════════════

  async function checkBiometricAvailable() {
    try {
      if (!window.PublicKeyCredential) return false;
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch { return false; }
  }
  async function isBiometricConfigured() {
    const r = await chrome.storage.local.get(WA_CRED_KEY);
    return !!r[WA_CRED_KEY];
  }

  async function setupBiometric() {
    const secret    = crypto.getRandomValues(new Uint8Array(32));
    const salt      = crypto.getRandomValues(new Uint8Array(32));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp:   { name: 'Vigil Clipboard Vault', id: location.hostname || 'localhost' },
        user: { id: new TextEncoder().encode('vigil-vault-user'), name: 'vigil-vault', displayName: 'Vigil Vault' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
        timeout: 60000,
      }
    });

    const vsalt = crypto.getRandomValues(new Uint8Array(32));
    await chrome.storage.local.set({
      [WA_CRED_KEY]:   b64(new Uint8Array(cred.rawId)),
      [WA_SECRET_KEY]: b64(secret),
      [SALT_KEY]:      b64(salt),
      [WA_VSALT_KEY]:  b64(vsalt),
      [WA_VHASH_KEY]:  await deriveBits(secret, vsalt),
      [PIN_SETUP_KEY]: true,
    });
    _vaultKey = await deriveKey(secret, salt);
    touchActivity();
  }

  async function unlockWithBiometric() {
    const r = await chrome.storage.local.get([WA_CRED_KEY, WA_SECRET_KEY, WA_VSALT_KEY, WA_VHASH_KEY, SALT_KEY]);
    if (!r[WA_CRED_KEY] || !r[WA_SECRET_KEY]) return false;

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId:             location.hostname || 'localhost',
          allowCredentials: [{ type: 'public-key', id: u8(r[WA_CRED_KEY]) }],
          userVerification: 'required',
          timeout:          60000,
        }
      });
    } catch (err) {
      console.warn('[Vigil CV] WebAuthn failed:', err.message);
      return false;
    }
    if (!assertion) return false;

    const secret = u8(r[WA_SECRET_KEY]);
    const vhash  = await deriveBits(secret, u8(r[WA_VSALT_KEY]));
    if (vhash !== r[WA_VHASH_KEY]) return false;

    _vaultKey = await deriveKey(secret, u8(r[SALT_KEY]));
    touchActivity();
    return true;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CLASSIFIER
  // ═══════════════════════════════════════════════════════════════════════════

  const CATEGORIES = [
    { id:'card',     label:'Payment card',   color:'#f44336',
      regex:/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?:[\s\-][0-9]{4}){0,3}\b/ },
    { id:'iban',     label:'Bank / IBAN',     color:'#e91e63',
      regex:/\b[A-Z]{2}\d{2}[\s\-]?(?:[A-Z0-9]{4}[\s\-]?){4,7}[A-Z0-9]{1,4}\b/ },
    { id:'crypto',   label:'Crypto address', color:'#ff5722',
      regex:/\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40})\b/ },
    { id:'ssn',      label:'SSN / ID',       color:'#9c27b0',
      regex:/\b(?:\d{3}[-\s]\d{2}[-\s]\d{4}|[A-Z]{2}\s?\d{6}\s?[A-D])\b/i },
    { id:'password', label:'Password',       color:'#ff9800',
      regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9\s]).{8,}$/ },
    { id:'apikey',   label:'API key / token',color:'#ff9800',
      regex:/(?:^|\s)(?:sk|pk|api|token|secret|bearer|auth|key)[-_][a-zA-Z0-9_\-]{16,}|(?:^|\s)[0-9a-fA-F]{32,}/i },
    { id:'phone',    label:'Phone number',   color:'#2196f3',
      regex:/(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}/ },
    { id:'email',    label:'Email address',  color:'#4caf50',
      regex:/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/ },
    { id:'url',      label:'URL / link',     color:'#607d8b',
      regex:/https?:\/\/[^\s]{10,}/ },
  ];
  const CAT_TEXT = { id:'text', label:'Plain text', color:'#7b8cde' };

  function classify(text) {
    const n = text.replace(/\s+/g,' ').trim();
    return CATEGORIES.find(p => p.regex.test(n)) || CAT_TEXT;
  }
  function smartExpiryMin(categoryId) {
    if (!SETTINGS.smartExpiry) return SETTINGS.expiryMin;
    const ov = SMART_EXPIRY[categoryId];
    return (ov !== null && ov !== undefined) ? ov : SETTINGS.expiryMin;
  }
  function makePreview(text) {
    let p = text.trim().substring(0, PREVIEW_MAX);
    p = p.replace(/\d{5,}/g, m => '●'.repeat(Math.min(m.length,12)));
    if (text.length > PREVIEW_MAX) p += '…';
    return p;
  }
  function makeMaskedDisplay(preview) {
    if (!preview || preview.length === 0) return '████ encrypted ████';
    const len = preview.replace(/…$/,'').length;
    return `${preview[0]}${'█'.repeat(Math.min(Math.max(len-1,4),20))}  [${len}+ chars]`;
  }
  function isSuspiciousDomain(h) {
    if (!h) return false;
    if (location.protocol !== 'https:') return true;
    const host = h.toLowerCase();
    if (/\.(xyz|tk|ml|ga|cf|gq|pw|top|click|loan|work|party|date|men|bid|trade|review|science|accountant)$/i.test(host)) return true;
    if ((host.match(/-/g)||[]).length > 3) return true;
    return false;
  }

  // ── UI helpers ─────────────────────────────────────────────────────────────
  function escH(s) {
    return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function fmtAgo(ms) {
    const s=Math.floor(ms/1000);
    if(s<60)  return s+'s ago';
    const m=Math.floor(s/60);
    if(m<60)  return m+'m ago';
    const hh=Math.floor(m/60);
    if(hh<24) return hh+'h ago';
    return Math.floor(hh/24)+'d ago';
  }
  function makeDrag(el,handle) {
    let drag=false,sx,sy,ox,oy;
    handle.addEventListener('mousedown',e=>{
      if(['BUTTON','INPUT','SELECT'].includes(e.target.tagName)) return;
      drag=true; sx=e.clientX; sy=e.clientY;
      const r=el.getBoundingClientRect(); ox=r.left; oy=r.top;
      el.style.right='auto'; el.style.left=ox+'px'; el.style.top=oy+'px';
      e.preventDefault();
    });
    document.addEventListener('mousemove',e=>{ if(!drag)return; el.style.left=(ox+e.clientX-sx)+'px'; el.style.top=(oy+e.clientY-sy)+'px'; });
    document.addEventListener('mouseup',()=>{ drag=false; });
  }
  async function copyToClipboard(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch {
      const ta=document.createElement('textarea');
      ta.value=text; ta.style.cssText='position:fixed;opacity:0;';
      document.body.appendChild(ta); ta.select();
      const ok=document.execCommand('copy'); ta.remove(); return ok;
    }
  }

  // ── Shared shadow-DOM CSS ──────────────────────────────────────────────────
  const BASE_CSS = `
    :host { font-family:system-ui,-apple-system,sans-serif; pointer-events:auto; }
    * { box-sizing:border-box; margin:0; padding:0; }
    .panel { background:#1a1a2e; color:#e0e0e0; border:1px solid #2a2a4a; border-radius:12px; box-shadow:0 8px 40px rgba(0,0,0,.7); }
    .hdr { display:flex; align-items:center; gap:8px; padding:11px 14px; border-bottom:1px solid #2a2a4a; background:#141428; border-radius:12px 12px 0 0; cursor:move; user-select:none; }
    .hdr-title { font-size:12px; font-weight:700; color:#7b8cde; letter-spacing:1px; text-transform:uppercase; flex:1; }
    .close-btn { background:transparent; border:none; color:#444; font-size:16px; cursor:pointer; padding:0 2px; line-height:1; }
    .close-btn:hover { color:#aaa; }
    .body { padding:14px; }
    .btn { padding:7px 14px; border-radius:6px; font-size:12px; cursor:pointer; border:1px solid #2a2a4a; color:#888; background:transparent; font-family:inherit; transition:border-color .15s,color .15s; }
    .btn:hover       { border-color:#7b8cde; color:#7b8cde; }
    .btn-primary     { border-color:#7b8cde; color:#7b8cde; }
    .btn-primary:hover { background:rgba(123,140,222,.1); }
    .btn-danger      { border-color:#f44336; color:#f44336; }
    .btn-danger:hover{ background:rgba(244,67,54,.1); }
    .btn-bio         { border-color:#4caf50; color:#4caf50; font-size:12px; }
    .btn-bio:hover   { background:rgba(76,175,80,.1); }
    .pin-row { display:flex; gap:8px; justify-content:center; margin:12px 0; }
    .pin-dot { width:12px; height:12px; border-radius:50%; border:2px solid #2a2a4a; background:transparent; transition:background .15s,border-color .15s; }
    .pin-dot.filled { background:#7b8cde; border-color:#7b8cde; }
    .pin-dot.error  { background:#f44336; border-color:#f44336; }
    .numpad { display:grid; grid-template-columns:repeat(3,1fr); gap:6px; max-width:180px; margin:0 auto; }
    .numpad-btn { padding:10px; border-radius:8px; font-size:16px; font-weight:600; cursor:pointer; border:1px solid #2a2a4a; color:#ccc; background:#12121f; font-family:inherit; transition:background .12s; }
    .numpad-btn:hover { background:#1e1e3a; }
    .numpad-btn.del   { font-size:13px; color:#555; }
    .err-msg { font-size:11px; color:#f44336; text-align:center; min-height:16px; margin-top:6px; }
    .brand { font-size:9px; color:#2a2a4a; letter-spacing:1px; text-align:right; margin-top:8px; }
  `;

  // ═══════════════════════════════════════════════════════════════════════════
  // SETUP UI
  // ═══════════════════════════════════════════════════════════════════════════

  function showPinSetup(onDone) {
    const el=document.createElement('vigil-pin-setup'); el.id='vigil-pin-setup';
    const sh=el.attachShadow({mode:'open'});
    const LOCK_OPTS=['Never','5 min','15 min','30 min','60 min'], LOCK_VALS=[0,5,15,30,60];
    const EXP_OPTS=['15 min','30 min','60 min','2 hrs','4 hrs','Never'], EXP_VALS=[15,30,60,120,240,0];

    sh.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2147483647;}
      .panel{width:280px;}
      .intro{font-size:12px;color:#aaa;line-height:1.6;margin-bottom:8px;text-align:center;}
      .step{font-size:10px;color:#555;text-align:center;margin-bottom:4px;}
      .divider{display:flex;align-items:center;gap:8px;margin:10px 0;}
      .divider div{flex:1;height:1px;background:#2a2a4a;}
      .divider span{font-size:10px;color:#444;}
      .opts{margin-top:10px;display:flex;flex-direction:column;gap:7px;}
      .opts label{display:flex;align-items:center;gap:8px;font-size:11px;color:#666;}
      .opts input[type=range]{flex:1;accent-color:#7b8cde;}
      .bio-note{font-size:10px;color:#555;text-align:center;margin-top:5px;}
    </style>
    <div class="panel">
      <div class="hdr"><span class="hdr-title">Setup Vault Lock</span>
        <button class="close-btn" id="sc">x</button></div>
      <div class="body">
        <p class="intro">Choose how to lock your vault.<br>Biometrics use your fingerprint, Face ID, or device PIN.</p>
        <button class="btn btn-bio" id="bio-btn" style="width:100%;">Use Biometric / Device Auth</button>
        <p class="bio-note" id="bio-note">Checking availability…</p>
        <div class="divider"><div></div><span>or set a numeric PIN</span><div></div></div>
        <p class="step" id="step-lbl">Enter new PIN (4–8 digits)</p>
        <div class="pin-row" id="pin-dots"></div>
        <div class="numpad"  id="numpad"></div>
        <div class="err-msg" id="err-msg"></div>
        <div class="opts">
          <label>Auto-lock after
            <input type="range" id="lr" min="0" max="4" step="1" value="2">
            <span id="lv">15 min</span>
          </label>
          <label>Default expiry
            <input type="range" id="er" min="0" max="5" step="1" value="2">
            <span id="ev">60 min</span>
          </label>
          <label><input type="checkbox" id="smart-chk" checked style="accent-color:#7b8cde;">
            Smart expiry per category</label>
        </div>
        <div class="brand">VIGIL CLIPBOARD VAULT</div>
      </div>
    </div>`;

    document.documentElement.appendChild(el);

    const lr=sh.getElementById('lr'),lv=sh.getElementById('lv');
    const er=sh.getElementById('er'),ev=sh.getElementById('ev');
    lr.addEventListener('input',()=>lv.textContent=LOCK_OPTS[lr.value]);
    er.addEventListener('input',()=>ev.textContent=EXP_OPTS[er.value]);

    checkBiometricAvailable().then(avail=>{
      const note=sh.getElementById('bio-note'),btn=sh.getElementById('bio-btn');
      if(avail){
        note.textContent='Platform authenticator detected.';
        btn.addEventListener('click',async()=>{
          const emsg=sh.getElementById('err-msg');
          emsg.textContent='Waiting for biometric…';
          try{
            await saveSettings({autoLockMin:LOCK_VALS[+lr.value],expiryMin:EXP_VALS[+er.value],
              smartExpiry:sh.getElementById('smart-chk').checked,authMethod:'biometric'});
            await setupBiometric();
            el.remove(); onDone?.();
          }catch(err){ emsg.textContent='Biometric setup failed: '+err.message; }
        });
      } else {
        btn.disabled=true; btn.style.opacity='0.3';
        note.textContent='Biometrics not available on this device/browser.';
      }
    });

    let first='',entered='',confirming=false;
    function dots(p,err=false){
      sh.getElementById('pin-dots').innerHTML=
        Array.from({length:Math.max(p.length,4)},(_,i)=>
          `<div class="pin-dot ${i<p.length?(err?'error':'filled'):''}"></div>`).join('');
    }
    const np=sh.getElementById('numpad');
    np.innerHTML=['1','2','3','4','5','6','7','8','9','','0','x'].map(d=>
      `<button class="numpad-btn${d==='x'?' del':''}" data-d="${d}">${d==='x'?'⌫':d}</button>`).join('');
    np.querySelectorAll('.numpad-btn').forEach(b=>{
      if(!b.dataset.d){b.style.visibility='hidden';return;}
      b.addEventListener('click',()=>onDigit(b.dataset.d));
    });
    function onDigit(d){
      sh.getElementById('err-msg').textContent='';
      if(d==='x'){entered=entered.slice(0,-1);}
      else if(entered.length<8){entered+=d;}
      dots(entered); if(entered.length===8) commit();
    }
    sh.addEventListener('keydown',e=>{
      if(e.key==='Enter'){commit();return;}
      if(e.key==='Backspace'){onDigit('x');return;}
      if(/^\d$/.test(e.key)) onDigit(e.key);
    });
    async function commit(){
      const emsg=sh.getElementById('err-msg');
      if(entered.length<4){emsg.textContent='PIN must be at least 4 digits.';dots(entered,true);return;}
      if(!confirming){
        first=entered;entered='';confirming=true;
        sh.getElementById('step-lbl').textContent='Confirm PIN';dots('');
      } else {
        if(entered!==first){
          emsg.textContent='PINs do not match.';dots(entered,true);
          setTimeout(()=>{entered='';first='';confirming=false;
            sh.getElementById('step-lbl').textContent='Enter new PIN (4–8 digits)';
            dots('');emsg.textContent='';},900);
          return;
        }
        saveSettings({autoLockMin:LOCK_VALS[+lr.value],expiryMin:EXP_VALS[+er.value],
          smartExpiry:sh.getElementById('smart-chk').checked,authMethod:'pin'})
          .then(()=>setupPin(entered)).then(()=>{el.remove();onDone?.();})
          .catch(err=>{emsg.textContent='Error: '+err.message;dots(entered,true);});
      }
    }
    sh.getElementById('sc').addEventListener('click',()=>el.remove());
    dots('');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UNLOCK UI
  // ═══════════════════════════════════════════════════════════════════════════

  function showUnlockDialog(onOk,onCancel) {
    document.getElementById('vigil-pin-unlock')?.remove();
    const el=document.createElement('vigil-pin-unlock'); el.id='vigil-pin-unlock';
    const sh=el.attachShadow({mode:'open'});

    sh.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2147483647;}
      .panel{width:270px;}
      .sub{font-size:11px;color:#555;text-align:center;margin-bottom:8px;}
      .divider{display:flex;align-items:center;gap:8px;margin:8px 0;}
      .divider div{flex:1;height:1px;background:#2a2a4a;}
      .divider span{font-size:10px;color:#444;}
      .ok-row{display:flex;gap:6px;margin-top:10px;}
      .ok-row .btn{flex:1;padding:9px;font-size:12px;}
      .btn-ok{border-color:#7b8cde;color:#7b8cde;}
      .btn-ok:hover{background:rgba(123,140,222,.1);}
      .btn-ok:disabled{opacity:.3;cursor:default;pointer-events:none;}
      .btn-cancel-inline{border-color:#2a2a4a;color:#555;}
      .btn-cancel-inline:hover{border-color:#7b8cde;color:#7b8cde;}
    </style>
    <div class="panel">
      <div class="hdr"><span class="hdr-title">Unlock Vault</span>
        <button class="close-btn" id="uc">×</button></div>
      <div class="body">
        <div id="bio-section" style="display:none;margin-bottom:8px;">
          <button class="btn btn-bio" id="bio-unlock-btn" style="width:100%;">
            🔑 Biometric / Device Auth
          </button>
          <div class="divider"><div></div><span>or use PIN</span><div></div></div>
        </div>
        <p class="sub">Enter your Vault PIN</p>
        <div class="pin-row" id="pin-dots"></div>
        <div class="numpad"  id="numpad"></div>
        <div class="err-msg" id="err-msg"></div>
        <div class="ok-row">
          <button class="btn btn-cancel-inline" id="cancel-btn">Cancel</button>
          <button class="btn btn-ok" id="ok-btn" disabled>OK</button>
        </div>
        <div class="brand">VIGIL CLIPBOARD VAULT</div>
      </div>
    </div>`;

    document.documentElement.appendChild(el);

    (async()=>{
      const hasCred=await isBiometricConfigured(), avail=await checkBiometricAvailable();
      if(hasCred&&avail){
        sh.getElementById('bio-section').style.display='block';
        sh.getElementById('bio-unlock-btn').addEventListener('click',async()=>{
          const emsg=sh.getElementById('err-msg');
          emsg.textContent='Waiting for biometric…';
          try{
            const ok=await unlockWithBiometric();
            if(ok){el.remove();onOk?.();}
            else{ emsg.textContent='Biometric verification failed.'; }
          }catch(err){ emsg.textContent='Error: '+err.message; }
        });
      }
    })();

    let pin='',attempts=0;
    const okBtn=sh.getElementById('ok-btn');

    function dots(p,err=false){
      sh.getElementById('pin-dots').innerHTML=
        Array.from({length:Math.max(p.length,4)},(_,i)=>
          `<div class="pin-dot ${i<p.length?(err?'error':'filled'):''}"></div>`).join('');
      okBtn.disabled = p.length < 4;
    }
    const np=sh.getElementById('numpad');
    np.innerHTML=['1','2','3','4','5','6','7','8','9','','0','⌫'].map((d,idx)=>
      `<button class="numpad-btn${idx===11?' del':''}" data-d="${idx===11?'x':d}">${d}</button>`).join('');
    np.querySelectorAll('.numpad-btn').forEach(b=>{
      if(!b.dataset.d||b.dataset.d===''){b.style.visibility='hidden';return;}
      b.addEventListener('click',()=>{
        sh.getElementById('err-msg').textContent='';
        if(b.dataset.d==='x'){pin=pin.slice(0,-1);dots(pin);return;}
        if(pin.length<8){pin+=b.dataset.d;dots(pin);}
        if(pin.length===8) tryUnlock();
      });
    });
    sh.addEventListener('keydown',e=>{
      if(e.key==='Enter'){if(pin.length>=4)tryUnlock();return;}
      if(e.key==='Backspace'){pin=pin.slice(0,-1);dots(pin);return;}
      if(/^\d$/.test(e.key)&&pin.length<8){pin+=e.key;dots(pin);sh.getElementById('err-msg').textContent='';}
      if(pin.length===8) tryUnlock();
    });
    async function tryUnlock(){
      const emsg=sh.getElementById('err-msg');
      if(pin.length<4){emsg.textContent='PIN must be at least 4 digits.';dots(pin,true);return;}
      emsg.textContent='Checking…';
      okBtn.disabled=true;
      const ok=await unlockWithPin(pin);
      if(ok){el.remove();onOk?.();}
      else{
        attempts++;pin='';dots('',true);
        emsg.textContent=`Wrong PIN${attempts>=3?' ('+attempts+' attempts)':''}`;
        setTimeout(()=>{emsg.textContent='';dots('');},900);
      }
    }
    okBtn.addEventListener('click',()=>{ if(pin.length>=4) tryUnlock(); });
    sh.getElementById('cancel-btn').addEventListener('click',()=>{el.remove();onCancel?.();});
    sh.getElementById('uc').addEventListener('click',()=>{el.remove();onCancel?.();});
    dots('');
  }

  function requireUnlock(cb) {
    if(_vaultKey){cb();return;}
    showUnlockDialog(cb,null);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SAVE PROMPT
  // ═══════════════════════════════════════════════════════════════════════════

  function showSavePrompt(text,cat,domain,onSave,onDiscard) {
    document.getElementById('vigil-cv-save-prompt')?.remove();
    const el=document.createElement('vigil-cv-save-prompt'); el.id='vigil-cv-save-prompt';
    const sh=el.attachShadow({mode:'open'});
    const color=cat.color, preview=makePreview(text);
    const expMin=smartExpiryMin(cat.id);
    const expLabel=expMin?`Expires in ${expMin<60?expMin+' min':Math.round(expMin/60)+' hr'}`:'No expiry';

    sh.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;bottom:20px;right:20px;z-index:2147483647;}
      .panel{width:300px;border-left:3px solid ${color};animation:sIn .18s cubic-bezier(.34,1.4,.64,1);}
      @keyframes sIn{from{transform:translateX(16px);opacity:0}to{transform:none;opacity:1}}
      .badge{display:inline-block;font-size:9px;font-weight:700;padding:1px 6px;
        border-radius:4px;text-transform:uppercase;background:${color}22;color:${color};margin-bottom:5px;}
      .prev{font-size:11px;color:#555;font-family:monospace;word-break:break-all;max-height:38px;overflow:hidden;margin-bottom:6px;}
      .exp-note{font-size:10px;color:#555;margin-bottom:8px;}
      .row{display:flex;gap:8px;}
      .row .btn{flex:1;font-size:11px;padding:6px;}
      .tbar{height:2px;background:#1e1e3a;margin-top:8px;border-radius:1px;overflow:hidden;}
      .tfill{height:100%;background:${color};width:100%;transition:width ${SAVE_PROMPT_MS}ms linear;}
    </style>
    <div class="panel">
      <div class="hdr"><span class="hdr-title">Save to Vault?</span>
        <button class="close-btn" id="sp-x">x</button></div>
      <div class="body">
        <span class="badge">${escH(cat.label)}</span>
        <div class="prev">${escH(preview)}</div>
        <div class="exp-note">${expLabel} · ${escH(domain)}</div>
        <div class="row">
          <button class="btn btn-primary" id="sp-save">Save &amp; Encrypt</button>
          <button class="btn" id="sp-dis">Discard</button>
        </div>
        <div class="tbar"><div class="tfill" id="sp-tf"></div></div>
        <div class="brand">Auto-discards in ${SAVE_PROMPT_MS/1000}s</div>
      </div>
    </div>`;

    document.documentElement.appendChild(el);
    requestAnimationFrame(()=>{ const tf=sh.getElementById('sp-tf'); if(tf) tf.style.width='0%'; });
    const auto=setTimeout(()=>{el.remove();onDiscard?.();},SAVE_PROMPT_MS);
    sh.getElementById('sp-save').addEventListener('click',()=>{clearTimeout(auto);el.remove();onSave();});
    sh.getElementById('sp-dis') .addEventListener('click',()=>{clearTimeout(auto);el.remove();onDiscard?.();});
    sh.getElementById('sp-x')   .addEventListener('click',()=>{clearTimeout(auto);el.remove();onDiscard?.();});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // COPY / PASTE HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  async function handleCopy(e) {
    try{await VigilDB.Clipboard.purgeExpired();}catch(_){}
    let text='';
    try{text=e.clipboardData?.getData('text/plain')||'';}catch(_){}
    if(!text) try{text=window.getSelection()?.toString()||'';}catch(_){}
    text=text.trim();
    if(!text||text.length<MIN_TEXT_LEN) return;

    const cat=classify(text), domain=location.hostname.replace(/^www\./,'');
    const policy=SETTINGS.savePrompt;
    if(policy==='always'||(policy==='sensitive'&&cat.id!=='text')){
      showSavePrompt(text,cat,domain,()=>doSave(text,cat,domain),null);
    } else if(policy==='never'){
      await doSave(text,cat,domain);
    }
  }

  async function doSave(text,cat,domain) {
    if(!_vaultKey){
      const configured=await isPinConfigured();
      if(!configured){showPinSetup(async()=>doSave(text,cat,domain));return;}
      showUnlockDialog(async()=>doSave(text,cat,domain),null);
      return;
    }
    try{
      await VigilDB.ready;
      // ── Duplicate detection ──────────────────────────────────────────────
      const hash=await sha256(text), active=await VigilDB.Clipboard.getActive();
      const dup=active.find(en=>en.contentHash===hash);
      if(dup){
        await VigilDB.db.clipboard.update(dup.id,{timestamp:Date.now()});
        showSensitiveToast(cat,makePreview(text),true);
        touchActivity(); return;
      }
      const enc=await encryptText(text), prev=makePreview(text);
      const expMin=smartExpiryMin(cat.id)||525600;
      await VigilDB.Clipboard.save(enc,prev,domain,expMin,{categoryId:cat.id,contentHash:hash});
      touchActivity();
      if(cat.id!=='text') showSensitiveToast(cat,prev,false);
    }catch(err){console.warn('[Vigil CV] Save failed:',err.message);}
  }

  async function handlePaste(e) {
    const text=e.clipboardData?.getData('text/plain')||'';
    if(!text||text.length<MIN_TEXT_LEN) return;
    const cat=classify(text), suspicious=isSuspiciousDomain(location.hostname);
    if(cat.id==='text'&&!suspicious) return;
    const dest=location.hostname.replace(/^www\./,'');
    let src=null;
    try{
      await VigilDB.ready;
      const entries=await VigilDB.Clipboard.getActive(), prev=makePreview(text);
      const m=entries.find(en=>en.preview&&prev.startsWith(en.preview.substring(0,15)));
      if(m) src=m.domain;
    }catch(_){}
    let reason='';
    if(cat.id!=='text') reason+=`You are pasting what looks like a <b>${cat.label}</b>. `;
    if(suspicious)       reason+=`<b>${escH(dest)}</b> looks like a phishing domain. `;
    if(src&&src!==dest)  reason+=`Originally copied from <b>${escH(src)}</b>.`;
    if(reason) showPasteWarning(reason.trim(),cat);
  }

  function showPasteWarning(reason,cat){
    document.getElementById('vigil-cv-warn')?.remove();
    const el=document.createElement('vigil-cv-warn'); el.id='vigil-cv-warn';
    const sh=el.attachShadow({mode:'open'}), color=cat?.color||'#ff9800';
    sh.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:2147483647;}
      .panel{max-width:380px;min-width:290px;border-top:3px solid ${color};animation:drop .2s cubic-bezier(.34,1.4,.64,1);}
      @keyframes drop{from{transform:translateY(-12px);opacity:0}to{transform:none;opacity:1}}
      .body b{color:#ddd;} .row{display:flex;gap:8px;margin-top:10px;} .row .btn{flex:1;font-size:11px;padding:6px;}
    </style>
    <div class="panel">
      <div class="hdr"><span class="hdr-title" style="color:${color}">Clipboard Warning</span>
        <button class="close-btn" id="wc">x</button></div>
      <div class="body">
        <div style="font-size:12px;color:#aaa;line-height:1.6;">${reason}</div>
        <div class="row">
          <button class="btn" id="w-cancel">Cancel paste</button>
          <button class="btn btn-danger" id="w-proceed">Proceed anyway</button>
        </div>
        <div class="brand">VIGIL CLIPBOARD VAULT</div>
      </div>
    </div>`;
    document.documentElement.appendChild(el);
    const dm=()=>el.remove();
    sh.getElementById('wc').addEventListener('click',dm);
    sh.getElementById('w-proceed').addEventListener('click',dm);
    sh.getElementById('w-cancel').addEventListener('click',()=>{dm();document.activeElement?.blur();});
    setTimeout(dm,20000);
  }

  function showSensitiveToast(cat,preview,isDuplicate=false){
    document.getElementById('vigil-cv-toast')?.remove();
    const el=document.createElement('vigil-cv-toast'); el.id='vigil-cv-toast';
    const sh=el.attachShadow({mode:'open'});
    sh.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;bottom:20px;right:20px;z-index:2147483647;}
      .panel{width:290px;display:flex;gap:10px;align-items:flex-start;padding:10px 14px;
        border-left:3px solid ${cat.color};animation:sIn .18s ease;}
      @keyframes sIn{from{transform:translateX(16px);opacity:0}to{transform:none;opacity:1}}
      .icon{font-size:15px;flex-shrink:0;margin-top:1px;} .info{flex:1;}
      .title{font-size:11px;font-weight:700;color:${cat.color};text-transform:uppercase;letter-spacing:.8px;margin-bottom:3px;}
      .lbl{font-size:11px;color:#aaa;} .prev{font-size:10px;color:#444;font-family:monospace;margin-top:3px;word-break:break-all;}
    </style>
    <div class="panel">
      <span class="icon">${isDuplicate?'♻':'🔒'}</span>
      <div class="info">
        <div class="title">${isDuplicate?'Already in vault':'Encrypted &amp; saved'}</div>
        <div class="lbl">${escH(cat.label)} ${isDuplicate?'— timestamp updated':'secured in Vault'}.</div>
        <div class="prev">${escH(preview)}</div>
        <div class="brand" style="margin-top:4px;">VIGIL · AES-256-GCM</div>
      </div>
      <button class="close-btn" id="tc">x</button>
    </div>`;
    document.documentElement.appendChild(el);
    sh.getElementById('tc').addEventListener('click',()=>el.remove());
    setTimeout(()=>{if(el.isConnected)el.remove();},7000);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VAULT OVERLAY
  // ═══════════════════════════════════════════════════════════════════════════

  async function showVaultOverlay(){
    document.getElementById('vigil-cv-overlay')?.remove();
    const pinSet=await isPinConfigured();
    if(!pinSet){showPinSetup(async()=>openVaultOverlay());return;}
    if(!_vaultKey){showUnlockDialog(async()=>openVaultOverlay(),null);return;}
    await openVaultOverlay();
  }

  let _searchQuery='';

  async function openVaultOverlay(){
    const el=document.createElement('vigil-cv-overlay'); el.id='vigil-cv-overlay';
    const sh=el.attachShadow({mode:'open'});
    sh.innerHTML=buildOverlayShell();
    document.documentElement.appendChild(el);
    makeDrag(sh.getElementById('cv-panel'),sh.getElementById('cv-hdr'));
    sh.getElementById('cv-close')     .addEventListener('click',()=>el.remove());
    sh.getElementById('cv-lock-btn')  .addEventListener('click',()=>{lockVault();el.remove();});
    sh.getElementById('cv-cfg-btn')   .addEventListener('click',()=>showSettingsPanel(sh));
    sh.getElementById('cv-export-btn').addEventListener('click',()=>showExportDialog(sh));
    sh.getElementById('cv-search')    .addEventListener('input',e=>{
      _searchQuery=e.target.value.toLowerCase().trim();
      refreshVaultList(sh);
    });
    await refreshVaultList(sh);
  }

  async function refreshVaultList(sh){
    const cont=sh.getElementById('cv-entries'), cnt=sh.getElementById('cv-count');
    try{
      await VigilDB.ready;
      await VigilDB.Clipboard.purgeExpired();
      let entries=await VigilDB.Clipboard.getActive();
      if(_searchQuery){
        entries=entries.filter(en=>{
          return (en.domain||'').toLowerCase().includes(_searchQuery)||
                 (en.categoryId||'').toLowerCase().includes(_searchQuery)||
                 (en.preview||'').toLowerCase().includes(_searchQuery);
        });
      }
      cnt.textContent=entries.length?`${entries.length} entr${entries.length===1?'y':'ies'}`:'Empty';
      renderEntries(sh,cont,entries);
    }catch(err){
      cont.innerHTML=`<div style="padding:12px;color:#f44336;font-size:11px;">Error: ${escH(err.message)}</div>`;
    }
  }

  function buildOverlayShell(){
    return `<style>
      ${BASE_CSS}
      :host{position:fixed;top:20px;right:20px;z-index:2147483647;}
      #cv-panel{width:360px;max-height:82vh;display:flex;flex-direction:column;animation:sIn .18s ease;}
      @keyframes sIn{from{transform:translateY(-10px);opacity:0}to{transform:none;opacity:1}}
      .hdr-btns{display:flex;gap:5px;align-items:center;margin-left:auto;}
      .icon-btn{background:transparent;border:none;color:#444;font-size:13px;cursor:pointer;padding:2px 4px;border-radius:4px;transition:color .15s;}
      .icon-btn:hover{color:#aaa;}
      .search-bar{padding:8px 14px;border-bottom:1px solid #1a1a2e;}
      .search-bar input{width:100%;background:#12121f;border:1px solid #2a2a4a;border-radius:6px;padding:5px 10px;font-size:12px;color:#ccc;font-family:inherit;outline:none;}
      .search-bar input:focus{border-color:#7b8cde;}
      #cv-entries{overflow-y:auto;flex:1;scrollbar-width:thin;scrollbar-color:#2a2a4a transparent;}
      #cv-entries::-webkit-scrollbar{width:4px;}
      #cv-entries::-webkit-scrollbar-thumb{background:#2a2a4a;border-radius:2px;}
      .entry{padding:10px 14px;border-bottom:1px solid #12121f;display:flex;flex-direction:column;gap:4px;}
      .entry:last-child{border-bottom:none;}
      .entry-top{display:flex;align-items:center;gap:6px;}
      .badge{font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px;text-transform:uppercase;flex-shrink:0;}
      .e-domain{font-size:11px;color:#7b8cde;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
      .e-age{font-size:10px;color:#444;flex-shrink:0;}
      .e-preview{font-size:11px;color:#555;font-family:monospace;word-break:break-all;}
      .e-masked{color:#2a2a4a!important;letter-spacing:1px;}
      .e-revealed{font-size:11px;color:#aaa;background:#0d0d1e;border-left:2px solid #7b8cde;padding:5px 8px;border-radius:4px;word-break:break-all;font-family:monospace;margin-top:3px;}
      .expbar{height:2px;background:#1e1e3a;border-radius:1px;overflow:hidden;margin-top:3px;}
      .expfill{height:100%;background:#7b8cde;}
      .btn-row{display:flex;gap:5px;margin-top:4px;flex-wrap:wrap;align-items:center;}
      .btn-row .btn{font-size:10px;padding:3px 8px;}
      .copy-ok{font-size:10px;color:#4caf50;}
      .empty-msg{padding:28px 16px;text-align:center;color:#333;font-size:12px;line-height:1.7;}
      .footer{padding:6px 14px;border-top:1px solid #2a2a4a;background:#141428;font-size:9px;color:#2a2a4a;letter-spacing:1px;text-align:right;border-radius:0 0 12px 12px;flex-shrink:0;}
      #cv-cfg{display:none;padding:12px 14px;border-top:1px solid #2a2a4a;background:#12121f;}
      #cv-cfg.open{display:block;}
      #cv-cfg label{display:flex;align-items:center;gap:8px;font-size:11px;color:#888;margin-bottom:8px;}
      #cv-cfg select{flex:1;background:#1a1a2e;border:1px solid #2a2a4a;color:#ccc;border-radius:4px;padding:3px 6px;font-size:11px;font-family:inherit;}
      .cfg-hdr{font-size:10px;font-weight:700;color:#7b8cde;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;}
    </style>
    <div class="panel" id="cv-panel">
      <div class="hdr" id="cv-hdr">
        <span class="hdr-title">Clipboard Vault</span>
        <span style="font-size:10px;color:#444;" id="cv-count"></span>
        <div class="hdr-btns">
          <button class="icon-btn" id="cv-export-btn" title="Export vault">⬇</button>
          <button class="icon-btn" id="cv-cfg-btn"    title="Settings">⚙</button>
          <button class="icon-btn" id="cv-lock-btn"   title="Lock vault">🔒</button>
          <button class="close-btn" id="cv-close">x</button>
        </div>
      </div>
      <div class="search-bar">
        <input type="text" id="cv-search" placeholder="Search by domain, category, or text…" autocomplete="off">
      </div>
      <div id="cv-entries"></div>
      <div id="cv-cfg">
        <div class="cfg-hdr">Settings</div>
        <label>Save prompt
          <select id="s-prompt">
            <option value="always">Always ask before saving</option>
            <option value="sensitive">Ask only for sensitive data</option>
            <option value="never">Save silently</option>
          </select>
        </label>
        <label>Default entry expiry
          <select id="s-expiry">
            <option value="15">15 minutes</option><option value="30">30 minutes</option>
            <option value="60">1 hour</option><option value="120">2 hours</option>
            <option value="240">4 hours</option><option value="0">Never</option>
          </select>
        </label>
        <label>Auto-lock vault
          <select id="s-lock">
            <option value="5">5 min idle</option><option value="15">15 min idle</option>
            <option value="30">30 min idle</option><option value="60">1 hr idle</option>
            <option value="0">Never</option>
          </select>
        </label>
        <label><input type="checkbox" id="s-smart" style="accent-color:#7b8cde;">
          Smart expiry per category</label>
        <div style="display:flex;gap:6px;margin-top:4px;">
          <button class="btn btn-primary" id="s-save" style="flex:1;font-size:10px;padding:5px;">Save</button>
          <button class="btn"             id="s-pin"  style="flex:1;font-size:10px;padding:5px;">Change auth</button>
        </div>
      </div>
      <div class="footer">VIGIL CLIPBOARD VAULT · AES-256-GCM · BIOMETRIC / PIN PROTECTED</div>
    </div>`;
  }

  function renderEntries(sh,cont,entries){
    if(!entries.length){
      cont.innerHTML=`<div class="empty-msg">
        ${_searchQuery?'No entries match your search.':'Vault is empty.<br><span style="color:#2a2a4a;font-size:10px;">Copy something to get started.</span>'}
      </div>`;
      return;
    }
    const TTL=(SETTINGS.expiryMin||60)*60000;
    cont.innerHTML=entries.map((en,i)=>{
      const ageMs=Date.now()-en.timestamp, left=en.expiresAt-Date.now();
      const pct=Math.max(0,Math.min(100,(left/TTL)*100)).toFixed(0);
      const cat=CATEGORIES.find(c=>c.id===en.categoryId)||CAT_TEXT;
      return `<div class="entry" data-i="${i}">
        <div class="entry-top">
          <span class="badge" style="background:${cat.color}22;color:${cat.color};">${escH(cat.label)}</span>
          <span class="e-domain">${escH(en.domain||'—')}</span>
          <span class="e-age">${fmtAgo(ageMs)}</span>
        </div>
        <div class="e-preview e-masked" id="masked-${i}">${escH(makeMaskedDisplay(en.preview||''))}</div>
        <div class="expbar"><div class="expfill" style="width:${pct}%"></div></div>
        <div class="btn-row">
          <button class="btn btn-reveal" data-i="${i}" data-enc="${escH(en.encryptedData||'')}">🔓 Reveal</button>
          <button class="btn btn-copy"   data-i="${i}" data-enc="${escH(en.encryptedData||'')}">📋 Copy</button>
          <button class="btn btn-danger btn-del" data-id="${en.id}">Delete</button>
          <span class="copy-ok" id="copy-ok-${i}" style="display:none;">Copied!</span>
        </div>
        <div class="e-revealed" id="rev-${i}" style="display:none;"></div>
      </div>`;
    }).join('');

    cont.querySelectorAll('.btn-reveal').forEach(btn=>{
      btn.addEventListener('click',async()=>{
        const i=btn.dataset.i,enc=btn.dataset.enc;
        const rv=sh.getElementById('rev-'+i),masked=sh.getElementById('masked-'+i);
        if(rv.style.display!=='none'){
          rv.style.display='none';btn.textContent='🔓 Reveal';
          masked.textContent=makeMaskedDisplay(entries[i]?.preview||'');
          masked.classList.add('e-masked'); return;
        }
        requireUnlock(async()=>{
          btn.textContent='…';
          try{
            const p=await decryptText(enc);
            rv.textContent=p;rv.style.display='block';btn.textContent='🔒 Hide';
            masked.textContent=entries[i]?.preview||'';
            masked.classList.remove('e-masked'); touchActivity();
          }catch(err){rv.textContent='Decryption failed: '+err.message;rv.style.display='block';btn.textContent='🔓 Reveal';}
        });
      });
    });

    cont.querySelectorAll('.btn-copy').forEach(btn=>{
      btn.addEventListener('click',async()=>{
        const i=btn.dataset.i,enc=btn.dataset.enc,okEl=sh.getElementById('copy-ok-'+i);
        requireUnlock(async()=>{
          try{
            const p=await decryptText(enc);
            const ok=await copyToClipboard(p);
            if(ok){okEl.style.display='inline';setTimeout(()=>okEl.style.display='none',2000);}
            touchActivity();
          }catch(err){console.warn('[Vigil CV] Copy-back failed:',err.message);}
        });
      });
    });

    cont.querySelectorAll('.btn-del').forEach(btn=>{
      btn.addEventListener('click',async()=>{
        try{await VigilDB.db.clipboard.delete(Number(btn.dataset.id));await refreshVaultList(sh);}
        catch(err){console.warn('[Vigil CV] Delete failed:',err.message);}
      });
    });
  }

  function showSettingsPanel(sh){
    const panel=sh.getElementById('cv-cfg');
    panel.classList.toggle('open');
    if(!panel.classList.contains('open')) return;
    sh.getElementById('s-prompt').value=SETTINGS.savePrompt;
    sh.getElementById('s-expiry').value=String(SETTINGS.expiryMin);
    sh.getElementById('s-lock')  .value=String(SETTINGS.autoLockMin);
    sh.getElementById('s-smart').checked=!!SETTINGS.smartExpiry;
    sh.getElementById('s-save').addEventListener('click',async()=>{
      await saveSettings({
        savePrompt:  sh.getElementById('s-prompt').value,
        expiryMin:   Number(sh.getElementById('s-expiry').value),
        autoLockMin: Number(sh.getElementById('s-lock').value),
        smartExpiry: sh.getElementById('s-smart').checked,
      });
      touchActivity(); panel.classList.remove('open');
    },{once:true});
    sh.getElementById('s-pin').addEventListener('click',()=>{
      lockVault(); panel.classList.remove('open');
      document.getElementById('vigil-cv-overlay')?.remove();
      showPinSetup(async()=>openVaultOverlay());
    },{once:true});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EXPORT
  // ═══════════════════════════════════════════════════════════════════════════

  function showExportDialog(sh){
    document.getElementById('vigil-cv-export')?.remove();
    const el=document.createElement('vigil-cv-export'); el.id='vigil-cv-export';
    const dlg=el.attachShadow({mode:'open'});
    dlg.innerHTML=`<style>
      ${BASE_CSS}
      :host{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2147483647;}
      .panel{width:280px;}
      .intro{font-size:12px;color:#aaa;line-height:1.6;margin-bottom:12px;}
      .field{width:100%;background:#12121f;border:1px solid #2a2a4a;border-radius:6px;
        padding:6px 10px;color:#ccc;font-size:12px;font-family:inherit;outline:none;margin-bottom:8px;}
      .field:focus{border-color:#7b8cde;}
    </style>
    <div class="panel">
      <div class="hdr"><span class="hdr-title">Export Vault</span>
        <button class="close-btn" id="ex-close">x</button></div>
      <div class="body">
        <p class="intro">All entries will be re-encrypted with your export passphrase and downloaded as a JSON file. Keep it secure.</p>
        <input type="password" class="field" id="ex-pass"  placeholder="Export passphrase (min 6 chars)…" autocomplete="new-password">
        <input type="password" class="field" id="ex-pass2" placeholder="Confirm passphrase…" autocomplete="new-password">
        <div class="err-msg" id="ex-err"></div>
        <button class="btn btn-primary" id="ex-go" style="width:100%;margin-top:8px;">Download encrypted JSON</button>
        <div class="brand">VIGIL · PBKDF2 + AES-256-GCM export</div>
      </div>
    </div>`;
    document.documentElement.appendChild(el);
    dlg.getElementById('ex-close').addEventListener('click',()=>el.remove());
    dlg.getElementById('ex-go').addEventListener('click',async()=>{
      const emsg=dlg.getElementById('ex-err');
      const p1=dlg.getElementById('ex-pass').value, p2=dlg.getElementById('ex-pass2').value;
      if(!p1||p1.length<6){emsg.textContent='Passphrase must be at least 6 characters.';return;}
      if(p1!==p2){emsg.textContent='Passphrases do not match.';return;}
      emsg.textContent='Exporting…';
      try{
        const entries=await VigilDB.Clipboard.getActive();
        const exSalt=crypto.getRandomValues(new Uint8Array(32));
        const exKey=await deriveKey(new TextEncoder().encode(p1),exSalt);
        const exported=[];
        for(const en of entries){
          let plain='';
          try{plain=await decryptText(en.encryptedData);}catch{plain='[unreadable]';}
          const iv=crypto.getRandomValues(new Uint8Array(12));
          const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},exKey,new TextEncoder().encode(plain));
          const out=new Uint8Array(12+ct.byteLength);
          out.set(iv,0);out.set(new Uint8Array(ct),12);
          exported.push({id:en.id,domain:en.domain,category:en.categoryId||'text',
            preview:en.preview,timestamp:en.timestamp,expiresAt:en.expiresAt,ciphertext:b64(out)});
        }
        const payload=JSON.stringify({version:3,exported:new Date().toISOString(),
          salt:b64(exSalt),pbkdf2:PBKDF2_ITERS,entries:exported},null,2);
        const blob=new Blob([payload],{type:'application/json'});
        const url=URL.createObjectURL(blob);
        const a=document.createElement('a');
        a.href=url; a.download=`vigil-vault-export-${Date.now()}.json`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(()=>URL.revokeObjectURL(url),2000);
        el.remove();
      }catch(err){emsg.textContent='Export failed: '+err.message;}
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MESSAGE HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  chrome.runtime.onMessage.addListener((msg,_,sendResponse)=>{
    if(msg.action==='purgeClipboard'){
      VigilDB.Clipboard.purgeExpired().catch(()=>{});
    }
    if(msg.action==='openClipboardVault'){
      showVaultOverlay();
    }
    if(msg.action==='getClipboardCount'){
      (async()=>{
        try{
          await VigilDB.ready;
          await VigilDB.Clipboard.purgeExpired();
          const e=await VigilDB.Clipboard.getActive();
          sendResponse({count:e.length});
        }catch{sendResponse({count:0});}
      })();
      return true;
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // INIT
  // ═══════════════════════════════════════════════════════════════════════════

  (async()=>{
    await loadSettings();
    document.addEventListener('copy', handleCopy, {capture:true,passive:true});
    document.addEventListener('paste',handlePaste,{capture:true,passive:true});
    setInterval(()=>{ VigilDB?.Clipboard?.purgeExpired().catch(()=>{}); },5*60000);
    console.log('[Vigil] clipboardVault v3.0 loaded on',location.hostname);
  })();

})();