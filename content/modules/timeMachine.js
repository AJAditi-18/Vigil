// Vigil — Module 1: Time Machine (v0.4)
//
// WHAT'S NEW vs v0.3:
// ───────────────────
// 1. PAYWALL / ANTI-SCRAPE BYPASS
//    Many publishers (NYT, WaPo, Medium, Wordpress sites, substack) hide
//    article text from scrapers using these techniques:
//      a) CSS visibility:hidden / opacity:0 / height:0 / overflow:hidden
//      b) Placing text in <template> or detached DOM fragments
//      c) JavaScript-rendered text behind a class like `.paywall-hide`
//      d) Blurred/clipped text that is still present in the DOM
//      e) content: attr(data-content) CSS tricks (text in data attributes)
//    We now handle all of these in the extraction pipeline.
//
// 2. SHADOW DOM TRAVERSAL
//    Some SPAs (Angular, Lit) render article content inside Shadow DOM roots.
//    extractBlocks() now recurses into open shadow roots.
//
// 3. READER-MODE HEURISTICS
//    We prioritise elements inside containers that Readability would pick:
//    article, [role="main"], main, .post-content, .entry-content, etc.
//    If we find a strong content container we extract from it first.
//
// 4. INVISIBLE TEXT RECOVERY
//    Elements that are invisible via CSS (not display:none, which removes from
//    layout entirely, but visibility:hidden or opacity:0) still have their
//    text in the DOM. We now collect that text explicitly.
//
// 5. DATA-ATTRIBUTE TEXT
//    Some sites put the real text in data-content, data-text, or aria-label
//    attributes and show it only via CSS `content:`. We harvest those.

;(function () {
  'use strict';

  const SKIP_PREFIXES = [
    'chrome://', 'chrome-extension://', 'moz-extension://',
    'about:', 'file://', 'data:', 'blob:'
  ];
  if (SKIP_PREFIXES.some(p => location.href.startsWith(p))) return;

  // ─── Config ───────────────────────────────────────────────────────────────
  const CFG = {
    snapshotDelay:     4000,   // ms after page load before snapshotting
    cooldownMs:        5 * 60 * 1000,
    minContentBlocks:  3,      // raised: require at least 3 solid content blocks
    minBlockScore:     0.28,   // raised: stricter scoring to filter nav/widget noise
    minSentenceLen:    30,     // raised: short strings are usually UI labels, not content
    maxSentences:      900,
    severity: { minor: 3, moderate: 15 },
    // Extra delay for SPAs / lazy loaders (WordPress jQuery can defer rendering)
    spaExtraDelay:     3000,
    // Stability check: re-extract after this delay and compare hashes.
    // If they differ the page is still mutating (ads, timers, live feeds) —
    // skip the snapshot to avoid recording noise as a "change".
    stabilityCheckMs:  2500,
  };

  // ─── Selectors ────────────────────────────────────────────────────────────
  const CONTENT_TAGS = new Set([
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'li', 'td', 'th', 'blockquote', 'figcaption',
    'dt', 'dd', 'caption'
  ]);

  // Strong article containers — we prefer text from inside these
  const ARTICLE_SELECTORS = [
    'article',
    '[role="main"]',
    'main',
    '.post-content', '.entry-content', '.article-content',
    '.article-body', '.story-body', '.article__body',
    '.post-body', '.entry-body', '.content-body',
    '.article-text', '.story-text', '.post-text',
    '[itemprop="articleBody"]',
    '#article-body', '#story-body', '#post-content',
    '.paywall-article', '.subscriber-content',
    '[data-testid="article-body"]',
    '[data-module="ArticleBody"]',
    '.StandardArticleBody', '.ArticleBodyWrapper',
    // Substack
    '.available-content', '.post-content-cta-free',
    // Medium
    '.section-inner', '.section-content',
    // WordPress — specific enough to not match <body> or sidebars
    '.entry', '.hentry', '.single-post-content',
    '.wp-block-post-content', '.site-main article',
    // NOTE: '.body' and '.post' deliberately excluded — they are too broad
    // and match <body class="..."> on WordPress themes, causing articleRoot
    // to be set to the entire page body (bypassing skip-ancestor filtering).
  ];

  const SKIP_ANCESTOR_SELECTORS = [
    'nav', 'header', 'footer', 'aside',
    '[role="navigation"]', '[role="banner"]', '[role="contentinfo"]',
    '[role="complementary"]', '[aria-hidden="true"]',
    '[class*="cookie"]', '[id*="cookie"]',
    '[class*="consent"]', '[class*="gdpr"]',
    '[class*="modal"]',
    '[class*="sidebar"]', '[class*="widget"]',
    '[class*="advert"]', '[class*="sponsor"]',
    '[class*="promo"]', '[class*="banner"]',
    '[class*="comment"]', '[id*="comment"]',
    '[class*="related"]', '[class*="recommend"]',
    '[class*="share"]', '[class*="social-btn"]',
    '[class*="breadcrumb"]', '[class*="pagination"]',
    '[class*="newsletter"]', '[class*="subscribe-prompt"]',
    '[class*="paywall-gate"]', '[class*="reg-gate"]',
    'script', 'style', 'noscript', 'svg', 'canvas', 'iframe'
  ];

  const NOISE_PATTERNS = [
    /\b\d+\s+(second|minute|hour|day|week|month|year)s?\s+ago\b/gi,
    /\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}/gi,
    /\b\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?\b/g,
    /\b\d[\d,]*\s*[KkMmBb]?\s+views?\b/gi,
    /updated\s+\d+\s+(minute|hour|day)s?\s+ago/gi,
    /^\s*(share|tweet|like|follow|subscribe|sign\s*up|log\s*in|register)\s*$/gi,
    // Additional: ad slots, live counters, timestamps, reaction counts
    /\b\d+\s+(likes?|comments?|shares?|reactions?|retweets?)\b/gi,
    /\b(just now|moments? ago|recently|live|breaking)\b/gi,
    /\b\d+:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?\b/g,
    // Cookie/GDPR banners that sometimes leak into content containers
    /\b(accept all cookies?|manage preferences|cookie settings|privacy choices)\b/gi,
  ];

  // ─── Paywall/anti-scrape bypass helpers ───────────────────────────────────

  /**
   * Temporarily reveal CSS-hidden elements to read their text.
   * Handles visibility:hidden, opacity:0, max-height:0, clip/clip-path tricks.
   * We read the computed style and, if text is hidden via CSS (not display:none),
   * collect the text directly from the DOM node's textContent.
   *
   * We do NOT modify any styles. We just read .textContent which is always
   * present in the DOM regardless of CSS visibility.
   */
  function getEffectiveText(el) {
    // el.textContent always works even for CSS-invisible elements.
    // The only thing that hides text from textContent is display:none on the
    // element itself (not parents). We explicitly include those too.
    return el.textContent || '';
  }

  /**
   * Check if an element is truly display:none (removed from layout).
   * CSS visibility:hidden / opacity:0 elements are NOT display:none —
   * their text is still readable and we want it.
   */
  function isDisplayNone(el) {
    // Check inline style first (cheap)
    if (el.style && el.style.display === 'none') return true;
    // Avoid getComputedStyle in a tight loop — only check if element is
    // in the DOM and large enough to matter.
    try {
      const cs = window.getComputedStyle(el);
      return cs.display === 'none';
    } catch {
      return false;
    }
  }

  /**
   * Harvest text from data-content / data-text / aria-label attributes.
   * Some sites (e.g. NYT) put the real sentence in a data attribute and
   * render it via CSS content: attr(data-content).
   */
  function harvestDataAttrs(root) {
    const texts = [];
    const candidates = (root || document).querySelectorAll(
      '[data-content],[data-text],[data-body],[data-paragraph]'
    );
    candidates.forEach(el => {
      const val = el.getAttribute('data-content')
               || el.getAttribute('data-text')
               || el.getAttribute('data-body')
               || el.getAttribute('data-paragraph')
               || '';
      if (val && val.length > 30) texts.push(val.trim());
    });
    return texts;
  }

  /**
   * Extract text nodes from a shadow root (open only — closed roots are
   * intentionally inaccessible, which is fine).
   */
  function extractFromShadowRoot(shadowRoot, skipEls, seen) {
    const blocks = [];
    shadowRoot.querySelectorAll(
      'p, h1, h2, h3, h4, h5, h6, li, td, th, blockquote, figcaption, dt, dd'
    ).forEach(el => {
      if (isInsideSkip(el, skipEls)) return;
      let text = getEffectiveText(el).replace(/\s+/g, ' ').trim();
      if (!text || text.length < 15) return;
      NOISE_PATTERNS.forEach(rx => { text = text.replace(rx, ''); });
      text = text.replace(/\s+/g, ' ').trim();
      if (!text || text.length < 15) return;
      const key = text.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      blocks.push(text);
    });
    return blocks;
  }

  // ─── Stage 1: Block-level extraction ─────────────────────────────────────
  function isInsideSkip(el, skipEls) {
    let cur = el.parentElement;
    while (cur) {
      if (skipEls.has(cur)) return true;
      cur = cur.parentElement;
    }
    return false;
  }

  function extractBlocks() {
    const skipEls = new Set();
    SKIP_ANCESTOR_SELECTORS.forEach(sel => {
      try { document.querySelectorAll(sel).forEach(el => skipEls.add(el)); } catch (_) {}
    });

    const blocks = [];
    const seen   = new Set();

    // ── Pass 1: Try article containers first ──────────────────────────────
    let articleRoot = null;
    for (const sel of ARTICLE_SELECTORS) {
      try {
        const el = document.querySelector(sel);
        if (el && !isDisplayNone(el)) {
          // Reject if this is the <body> or <html> element itself
          const tag = el.tagName.toLowerCase();
          if (tag === 'body' || tag === 'html') continue;
          // Reject if the matched container has very little text — likely a
          // sidebar, widget, or theme wrapper rather than main article content.
          const textLen = (el.textContent || '').replace(/\s+/g,' ').trim().length;
          if (textLen < 200) continue;
          articleRoot = el;
          break;
        }
      } catch (_) {}
    }

    const queryRoot = articleRoot || document;

    // ── Pass 2: Standard content elements ────────────────────────────────
    queryRoot.querySelectorAll(
      'p, h1, h2, h3, h4, h5, h6, li, td, th, blockquote, figcaption, dt, dd, caption'
    ).forEach(el => {
      // Always filter skip ancestors — even inside an articleRoot,
      // themes can embed nav, sidebar, or comments within the container.
      if (isInsideSkip(el, skipEls)) return;
      // Include CSS-invisible elements (paywall trick)
      // But skip display:none (truly absent from layout)
      if (!articleRoot && isDisplayNone(el)) return;

      let text = '';
      el.childNodes.forEach(node => {
        if (node.nodeType === Node.TEXT_NODE) {
          text += node.textContent;
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          const tag = node.tagName.toLowerCase();
          if (!CONTENT_TAGS.has(tag)) text += node.textContent;
        }
      });

      text = text.replace(/\s+/g, ' ').trim();
      if (!text || text.length < 15) return;
      NOISE_PATTERNS.forEach(rx => { text = text.replace(rx, ''); });
      text = text.replace(/\s+/g, ' ').trim();
      if (!text || text.length < 15) return;
      const key = text.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      blocks.push(text);
    });

    // ── Pass 3: If we found very little, grab ALL paragraphs ignoring
    //    skip ancestors (catches paywalled sites that hide text in odd places).
    //    Minimum length raised to 40 to exclude nav labels, button text, etc.
    if (blocks.length < 5) {
      document.querySelectorAll('p, li, blockquote').forEach(el => {
        if (isDisplayNone(el)) return;
        let text = el.textContent.replace(/\s+/g, ' ').trim();
        if (!text || text.length < 40) return;
        NOISE_PATTERNS.forEach(rx => { text = text.replace(rx, ''); });
        text = text.replace(/\s+/g, ' ').trim();
        if (!text || text.length < 40) return;
        const key = text.toLowerCase();
        if (seen.has(key)) return;
        seen.add(key);
        blocks.push(text);
      });
    }

    // ── Pass 4: CSS-invisible elements (visibility:hidden paywall trick) ──
    // Only run this if we really have almost nothing — broad class selectors
    // like [class*="content"] match sidebars, footers, and widgets on many
    // sites, injecting dynamic text that changes every page load.
    if (blocks.length < 4) {
      document.querySelectorAll(
        '[class*="article"],[class*="story"],[class*="post"],[class*="content"],[class*="body"],' +
        '[class*="entry"],[class*="hentry"],[class*="wp-block"]'
      ).forEach(container => {
        if (isDisplayNone(container)) return;
        // Reject containers that are likely sidebars/widgets by checking
        // that they have meaningful text density (> 300 chars raw text).
        const rawLen = (container.textContent || '').replace(/\s+/g,' ').trim().length;
        if (rawLen < 300) return;
        container.querySelectorAll('p, li').forEach(el => {
          const text = el.textContent.replace(/\s+/g, ' ').trim();
          if (!text || text.length < 40) return;
          const key = text.toLowerCase();
          if (seen.has(key)) return;
          seen.add(key);
          blocks.push(text);
        });
      });
    }

    // ── Pass 5: data-attribute text harvest ───────────────────────────────
    harvestDataAttrs(queryRoot).forEach(text => {
      const key = text.toLowerCase();
      if (!seen.has(key)) { seen.add(key); blocks.push(text); }
    });

    // ── Pass 6: Shadow DOM ────────────────────────────────────────────────
    document.querySelectorAll('*').forEach(el => {
      if (el.shadowRoot) {
        extractFromShadowRoot(el.shadowRoot, skipEls, seen).forEach(t => blocks.push(t));
      }
    });

    return blocks;
  }

  // ─── Stage 2: Block scoring ───────────────────────────────────────────────
  function scoreBlock(text) {
    let score = 0;
    const len = text.length;
    if (len < 20)  return 0;
    if (len > 30)  score += 0.2;
    if (len > 80)  score += 0.2;
    if (len > 200) score += 0.1;
    if (/[.!?:]\s*$/.test(text)) score += 0.2;
    const words = text.split(/\s+/).filter(Boolean);
    if (words.length >= 5)  score += 0.15;
    if (words.length >= 15) score += 0.1;
    if (/\b(the|a|an|is|are|was|were|in|on|at|to|of|and|or|but|for|with)\b/i.test(text))
      score += 0.15;
    if (text === text.toUpperCase() && text.length < 60) score -= 0.3;
    if (words.length <= 3 && !/[.!?]/.test(text)) score -= 0.3;
    return Math.max(0, Math.min(1, score));
  }

  // ─── Stage 3: Sentence splitting ─────────────────────────────────────────
  function splitSentences(text) {
    const marked = text
      .replace(/([.!?])\s+(?=[A-Z])/g, '$1\x00')
      .replace(/\s{3,}/g, '\x00');
    return marked.split('\x00')
      .map(s => s.trim())
      .filter(s => s.length >= CFG.minSentenceLen);
  }

  // ─── Full extraction pipeline ─────────────────────────────────────────────
  function extractSentences() {
    const blocks    = extractBlocks();
    const scored    = blocks.filter(b => scoreBlock(b) >= CFG.minBlockScore);
    const sentences = [];
    const seenSents = new Set();
    for (const block of scored) {
      for (const sent of splitSentences(block)) {
        const key = sent.toLowerCase().replace(/\s+/g, ' ');
        if (!seenSents.has(key)) {
          seenSents.add(key);
          sentences.push(sent);
        }
        if (sentences.length >= CFG.maxSentences) break;
      }
      if (sentences.length >= CFG.maxSentences) break;
    }
    return sentences;
  }

  // ─── Hash ─────────────────────────────────────────────────────────────────
  function hashArr(arr) {
    const str = arr.join('|');
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return h.toString(16);
  }

  // ─── Diff library resolver ────────────────────────────────────────────────
  function getDiffLib() {
    if (typeof Diff   !== 'undefined' && typeof Diff.diffArrays   === 'function') return Diff;
    if (typeof JsDiff !== 'undefined' && typeof JsDiff.diffArrays === 'function') return JsDiff;
    return null;
  }

  // ─── Sentence-array diff ──────────────────────────────────────────────────
  function runDiff(oldSents, newSents) {
    const lib = getDiffLib();
    if (!lib) {
      if (oldSents.join() === newSents.join()) return [{ type:'unchanged', text: oldSents.join(' ') }];
      return [{ type:'removed', text: oldSents.join(' ') }, { type:'added', text: newSents.join(' ') }];
    }
    const raw    = lib.diffArrays(oldSents, newSents);
    const blocks = [];
    for (const part of raw) {
      const type = part.added ? 'added' : part.removed ? 'removed' : 'unchanged';
      const text = part.value.join(' ');
      if (type === 'unchanged' && text.trim().length < 60) continue;
      blocks.push({ type, text });
    }
    return blocks;
  }

  // ─── Importance scorer ────────────────────────────────────────────────────
  const IMP = [
    { re: /\b(terms\s+of\s+service|privacy\s+policy|user\s+agreement)\b/i,   w: 1.0 },
    { re: /\b(shall\s+not|must\s+not|prohibited|forbidden|unlawful)\b/i,      w: 0.9 },
    { re: /\b(liable|liability|indemnif|damages|arbitration|dispute)\b/i,     w: 0.9 },
    { re: /\b(data\s+collect|personal\s+information|third[\s-]party)\b/i,     w: 0.9 },
    { re: /\b(opt[\s-]out|opt[\s-]in|consent|rights?\s+reserved)\b/i,        w: 0.85 },
    { re: /[$€£¥₹]\s*[\d,]+\.?\d*/,                                           w: 0.8 },
    { re: /\b(price|fee|charge|subscription|billing|payment)\b/i,            w: 0.8 },
    { re: /\b(free|discount|refund|cancel|upgrade|downgrade)\b/i,            w: 0.75 },
    { re: /\b(breaking|correction|retracted|updated|exclusive)\b/i,          w: 0.6 },
    { re: /\b\d+(\.\d+)?\s*(%|percent|million|billion)\b/i,                  w: 0.5 },
    { re: /.+/, w: 0.2 }
  ];
  function scoreImportance(text) {
    for (const { re, w } of IMP) { if (re.test(text)) return w; }
    return 0.1;
  }

  // ─── Severity ─────────────────────────────────────────────────────────────
  function calcSeverity(blocks, oldCount, newCount) {
    const total = Math.max(oldCount, newCount, 1);
    let changed = 0, impW = 0, impT = 0;
    blocks.forEach(b => {
      if (b.type === 'unchanged') return;
      const wc = b.text.split(/\s+/).filter(Boolean).length;
      changed += wc;
      const s  = scoreImportance(b.text);
      impW    += s * wc;
      impT    += wc;
    });
    const rawPct  = Math.min(100, (changed / total) * 100);
    const avgImp  = impT > 0 ? impW / impT : 0;
    const effPct  = Math.min(100, rawPct * (1 + avgImp * 3));
    let label, color, bg;
    if (effPct < CFG.severity.minor)      { label='Minor';    color='#f5c542'; bg='rgba(245,197,66,0.15)'; }
    else if (effPct < CFG.severity.moderate) { label='Moderate'; color='#ff9800'; bg='rgba(255,152,0,0.15)'; }
    else                                  { label='Major';    color='#f44336'; bg='rgba(244,67,54,0.15)'; }
    const stats = { added:0, removed:0 };
    blocks.forEach(b => {
      const wc = b.text.split(/\s+/).filter(Boolean).length;
      if (b.type === 'added')   stats.added   += wc;
      if (b.type === 'removed') stats.removed += wc;
    });
    return { rawPct:Math.round(rawPct), effectivePct:Math.round(effPct), label, color, bg, ...stats };
  }

  // ─── Module state ─────────────────────────────────────────────────────────
  let cachedDiff = null;

  // ─── Message listener ─────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'getSnapshotSummary') {
      if (typeof VigilDB === 'undefined') { sendResponse(null); return; }
      VigilDB.ready
        .then(() => VigilDB.Snapshots.getAll(location.href))
        .then(snaps => {
          if (!snaps || snaps.length === 0) { sendResponse({ count:0 }); return; }
          const withChange = snaps.find(s => s.changeSize > 0);
          sendResponse({
            count:      snaps.length,
            latestTs:   snaps[0].timestamp,
            hasChange:  !!withChange,
            changeSize: withChange ? withChange.changeSize : 0
          });
        })
        .catch(() => sendResponse(null));
      return true;
    }

    if (msg.action !== 'openTimeMachineOverlay') return;

    if (document.getElementById('vigil-tm-overlay')) {
      document.getElementById('vigil-tm-overlay').remove(); return;
    }
    if (cachedDiff) { buildOverlay(cachedDiff.blocks, cachedDiff.sev, cachedDiff.oldSnap); return; }
    if (typeof VigilDB === 'undefined') {
      showInfoOverlay('Time Machine not ready', 'VigilDB failed to load — check extension setup.'); return;
    }

    VigilDB.ready.then(() => VigilDB.Snapshots.getAll(location.href))
      .then(snaps => {
        if (!snaps || snaps.length === 0) {
          showInfoOverlay('No snapshots yet',
            'Vigil hasn\'t saved a baseline for this page yet.<br>' +
            'The first snapshot saves automatically after 3–4 seconds.<br>' +
            'Visit the page a second time to compare versions.');
          return;
        }
        if (snaps.length === 1) {
          showInfoOverlay('Baseline saved',
            `First snapshot recorded <b>${fmtAgo(Date.now() - snaps[0].timestamp)}</b>.<br>` +
            'Visit the page again later to track changes.');
          return;
        }
        const newest   = snaps[0];
        const prev     = snaps[1];
        const oldSents = deserializeSents(prev.content);
        const newSents = deserializeSents(newest.content);
        const blocks   = runDiff(oldSents, newSents);
        const hasChange = blocks.some(b => b.type !== 'unchanged');
        if (!hasChange) {
          showInfoOverlay('No changes detected',
            `Content matches the previous snapshot from <b>${fmtAgo(Date.now() - prev.timestamp)}</b>.`);
          return;
        }
        const sev = calcSeverity(blocks, oldSents.length, newSents.length);
        cachedDiff = { blocks, sev, oldSnap: prev };
        buildOverlay(blocks, sev, prev);
      })
      .catch(err => showInfoOverlay('Error', 'Could not load snapshot: ' + err.message));
  });

  // ─── Serialization helpers ────────────────────────────────────────────────
  function serializeSents(sents)   { return JSON.stringify(sents); }
  function deserializeSents(stored) {
    try {
      const parsed = JSON.parse(stored);
      if (Array.isArray(parsed)) return parsed;
    } catch (_) {}
    return (stored || '').split(/(?<=[.!?])\s+/).filter(s => s.length >= CFG.minSentenceLen);
  }

  // ─── Info overlay ─────────────────────────────────────────────────────────
  function showInfoOverlay(title, bodyHtml) {
    document.getElementById('vigil-tm-overlay')?.remove();
    const o = document.createElement('div');
    o.id = 'vigil-tm-overlay';
    o.innerHTML = `
      <style>
        #vigil-tm-overlay{
          position:fixed;top:18px;right:18px;width:380px;
          background:#0e0e1a;border:1px solid #22224a;
          border-top:3px solid #7b8cde;border-radius:12px;
          z-index:2147483647;font-family:system-ui,sans-serif;
          font-size:13px;color:#dde0f0;
          box-shadow:0 12px 48px rgba(0,0,0,0.75);overflow:hidden;
          animation:vtm-in 0.22s cubic-bezier(0.22,1,0.36,1);
        }
        @keyframes vtm-in{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}
        .vtm-ih{display:flex;justify-content:space-between;align-items:center;
          padding:11px 14px;background:#141428;border-bottom:1px solid #22224a;
          cursor:move;user-select:none;}
        .vtm-ib{padding:18px 16px;font-size:12px;color:#888;line-height:1.7;}
        .vtm-if{display:flex;justify-content:space-between;align-items:center;
          padding:9px 14px;border-top:1px solid #1a1a38;background:#141428;}
        .vtm-xb{background:transparent;border:none;color:#3a3a5a;font-size:22px;
          cursor:pointer;line-height:1;padding:0 2px;font-family:inherit;}
        .vtm-xb:hover{color:#aaa;}
        .vtm-hb{background:transparent;border:1px solid #2a2a4a;color:#7b8cde;
          border-radius:5px;padding:3px 9px;font-size:11px;cursor:pointer;font-family:inherit;}
        .vtm-hb:hover{background:#1a1a30;}
        .vtm-db{background:transparent;border:1px solid #2a2a4a;color:#555;
          border-radius:5px;padding:3px 10px;font-size:11px;cursor:pointer;font-family:inherit;}
        .vtm-db:hover{border-color:#555;color:#aaa;}
      </style>
      <div class="vtm-ih">
        <div style="display:flex;align-items:center;gap:9px;">
          <span style="font-weight:800;font-size:11px;letter-spacing:2.5px;color:#7b8cde;">VIGIL</span>
          <span style="font-size:11px;color:#888;">Time Machine</span>
        </div>
        <button class="vtm-xb" id="vtm-ix">×</button>
      </div>
      <div class="vtm-ib">
        <div style="font-size:13px;color:#ccc;font-weight:600;margin-bottom:8px;">${escH(title)}</div>
        <div>${bodyHtml}</div>
      </div>
      <div class="vtm-if">
        <button class="vtm-hb" id="vtm-ih">History ↗</button>
        <button class="vtm-db" id="vtm-id">Dismiss</button>
      </div>`;
    document.documentElement.appendChild(o);
    makeDrag(o, o.querySelector('.vtm-ih'));
    o.querySelector('#vtm-ix').onclick = () => o.remove();
    o.querySelector('#vtm-id').onclick = () => o.remove();
    o.querySelector('#vtm-ih').onclick = () => chrome.runtime.sendMessage({ action:'openHistory', url: location.href });
  }

  // ─── Main diff overlay ────────────────────────────────────────────────────
  function buildOverlay(blocks, sev, oldSnap) {
    document.getElementById('vigil-tm-overlay')?.remove();
    const ago       = fmtAgo(Date.now() - oldSnap.timestamp);
    const pageTitle = escH(oldSnap.title || getDomain(location.href));
    const diffHtml  = blocks.map(b => {
      if (b.type === 'unchanged') {
        const p = b.text.length > 200 ? b.text.substring(0, 200) + '…' : b.text;
        return p.trim() ? `<span class="vtm-ctx">${escH(p.trim())} </span>` : '';
      }
      const cls   = b.type === 'added' ? 'vtm-add' : 'vtm-del';
      const label = b.type === 'added' ? '+ ' : '− ';
      return `<div class="${cls}">${label}${escH(b.text.trim())}</div>`;
    }).join('');
    const ap = sev.added   ? `<span class="vtm-pill vtm-pa">+${sev.added} words</span>` : '';
    const rp = sev.removed ? `<span class="vtm-pill vtm-pr">−${sev.removed} words</span>` : '';
    const o = document.createElement('div');
    o.id = 'vigil-tm-overlay';
    o.innerHTML = `
      <style>
        #vigil-tm-overlay{
          position:fixed;top:18px;right:18px;width:440px;max-height:78vh;
          background:#0e0e1a;border:1px solid #22224a;
          border-top:3px solid ${sev.color};border-radius:12px;
          z-index:2147483647;
          font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
          font-size:13px;color:#dde0f0;
          box-shadow:0 12px 48px rgba(0,0,0,0.75),0 0 0 1px rgba(255,255,255,0.04);
          display:flex;flex-direction:column;overflow:hidden;
          animation:vtm-in 0.25s cubic-bezier(0.22,1,0.36,1);
        }
        @keyframes vtm-in{from{opacity:0;transform:translateY(-12px) scale(0.97);}to{opacity:1;transform:translateY(0) scale(1);}}
        #vtm-hdr{display:flex;justify-content:space-between;align-items:center;
          padding:11px 14px;background:#141428;border-bottom:1px solid #22224a;
          cursor:move;flex-shrink:0;user-select:none;}
        #vtm-hl{display:flex;align-items:center;gap:9px;}
        .vtm-wm{font-weight:800;font-size:11px;letter-spacing:2.5px;color:#7b8cde;}
        .vtm-sb{background:${sev.bg};color:${sev.color};border:1px solid ${sev.color}55;
          border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700;}
        #vtm-hr{display:flex;gap:7px;align-items:center;}
        .vtm-btn{background:transparent;border:1px solid #2a2a4a;color:#7b8cde;
          border-radius:5px;padding:3px 9px;font-size:11px;cursor:pointer;
          transition:background 0.15s;font-family:inherit;}
        .vtm-btn:hover{background:#1a1a30;border-color:#7b8cde;}
        .vtm-x{background:transparent;border:none;color:#3a3a5a;font-size:22px;
          cursor:pointer;line-height:1;padding:0 2px;font-family:inherit;transition:color 0.15s;}
        .vtm-x:hover{color:#aaa;}
        #vtm-meta{display:flex;align-items:center;flex-wrap:wrap;gap:6px;
          padding:7px 14px;background:#111122;border-bottom:1px solid #1a1a38;
          flex-shrink:0;font-size:11px;color:#555;}
        .vtm-mv{color:#888;}.vtm-ms{color:#2a2a4a;}
        .vtm-pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600;}
        .vtm-pa{background:rgba(76,175,80,0.2);color:#81c784;}
        .vtm-pr{background:rgba(244,67,54,0.2);color:#e57373;}
        #vtm-body{padding:12px 14px;overflow-y:auto;flex:1;line-height:1.75;
          scrollbar-width:thin;scrollbar-color:#2a2a4a transparent;}
        #vtm-body::-webkit-scrollbar{width:4px;}
        #vtm-body::-webkit-scrollbar-thumb{background:#2a2a4a;border-radius:2px;}
        .vtm-add{background:rgba(76,175,80,0.1);border-left:3px solid #4caf50;
          color:#a5d6a7;padding:5px 10px;margin:4px 0;border-radius:3px;
          font-size:12.5px;word-break:break-word;}
        .vtm-del{background:rgba(244,67,54,0.1);border-left:3px solid #f44336;
          color:#ef9a9a;padding:5px 10px;margin:4px 0;border-radius:3px;
          font-size:12.5px;word-break:break-word;text-decoration:line-through;}
        .vtm-ctx{color:#2e2e54;font-size:11.5px;}
        #vtm-foot{display:flex;align-items:center;gap:10px;padding:9px 14px;
          border-top:1px solid #1a1a38;background:#141428;flex-shrink:0;font-size:11px;}
        .vtm-leg{display:flex;gap:12px;color:#3a3a5a;}
        .vtm-leg span{display:flex;align-items:center;gap:4px;}
        .da,.dr{width:8px;height:8px;border-radius:2px;display:inline-block;}
        .da{background:#4caf50;}.dr{background:#f44336;}
        #vtm-dis{margin-left:auto;background:transparent;border:1px solid #2a2a4a;
          color:#555;border-radius:5px;padding:3px 10px;font-size:11px;
          cursor:pointer;transition:border-color 0.15s,color 0.15s;font-family:inherit;}
        #vtm-dis:hover{border-color:#555;color:#aaa;}
      </style>
      <div id="vtm-hdr">
        <div id="vtm-hl">
          <span class="vtm-wm">VIGIL</span>
          <span class="vtm-sb">${sev.label} Change</span>
          <span style="font-size:11px;color:#444;">${sev.rawPct}% content</span>
        </div>
        <div id="vtm-hr">
          <button class="vtm-btn" id="vtm-hist">History ↗</button>
          <button class="vtm-x"  id="vtm-close">×</button>
        </div>
      </div>
      <div id="vtm-meta">
        <span class="vtm-mv">${pageTitle}</span>
        <span class="vtm-ms">·</span>
        <span>last seen <span class="vtm-mv">${ago}</span></span>
        <span class="vtm-ms">·</span>
        ${ap}${rp}
      </div>
      <div id="vtm-body">
        ${diffHtml || '<span style="color:#3a3a5a;font-size:12px;">No textual diff to display.</span>'}
      </div>
      <div id="vtm-foot">
        <div class="vtm-leg">
          <span><span class="da"></span> Added</span>
          <span><span class="dr"></span> Removed</span>
        </div>
        <button id="vtm-dis">Dismiss</button>
      </div>`;
    document.documentElement.appendChild(o);
    makeDrag(o, o.querySelector('#vtm-hdr'));
    o.querySelector('#vtm-close').onclick = () => o.remove();
    o.querySelector('#vtm-dis').onclick   = () => o.remove();
    o.querySelector('#vtm-hist').onclick  = () => chrome.runtime.sendMessage({ action:'openHistory', url: location.href });
  }

  // ─── Drag ─────────────────────────────────────────────────────────────────
  function makeDrag(el, handle) {
    let drag = false, sx, sy, ox, oy;
    handle.addEventListener('mousedown', e => {
      if (e.target.tagName === 'BUTTON') return;
      drag = true; sx = e.clientX; sy = e.clientY;
      const r = el.getBoundingClientRect();
      ox = r.left; oy = r.top;
      el.style.right = 'auto'; el.style.left = ox + 'px'; el.style.top = oy + 'px';
      e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
      if (!drag) return;
      el.style.left = (ox + e.clientX - sx) + 'px';
      el.style.top  = (oy + e.clientY - sy) + 'px';
    });
    document.addEventListener('mouseup', () => { drag = false; });
  }

  // ─── Notification ─────────────────────────────────────────────────────────
  function sendNotif(sev, title) {
    try {
      chrome.runtime.sendMessage({
        action: 'showNotification',
        payload: { title, domain:getDomain(location.href), severity:sev.label, added:sev.added, removed:sev.removed }
      });
    } catch (_) {}
  }

  // ─── Main auto-run ────────────────────────────────────────────────────────
  async function runTimeMachine() {
    const url = location.href;
    if (!url.startsWith('http')) return;
    if (typeof VigilDB === 'undefined') {
      console.error('[Vigil TM] VigilDB not loaded — check manifest.json'); return;
    }

    await sleep(CFG.snapshotDelay);

    // Extra wait for SPAs / lazy-loaded content
    let sents = extractSentences();
    if (sents.length < CFG.minContentBlocks) {
      await sleep(CFG.spaExtraDelay);
      sents = extractSentences();
    }

    if (sents.length < CFG.minContentBlocks) {
      console.log(`[Vigil TM] Only ${sents.length} content sentences found — skipping snapshot`);
      return;
    }

    // ── Stability check ────────────────────────────────────────────────────
    // Re-extract after a short pause. If the page content is still mutating
    // (live feeds, ad rotations, animated counters, social share counts) the
    // two hashes will differ and we skip this cycle entirely rather than
    // recording noise as a meaningful change.
    const hash1 = hashArr(sents);
    await sleep(CFG.stabilityCheckMs);
    const sents2 = extractSentences();
    const hash2  = hashArr(sents2);
    if (hash1 !== hash2) {
      console.log('[Vigil TM] Content unstable (page still mutating) — skipping snapshot');
      return;
    }
    // Use the second extraction as authoritative (slightly later = more settled)
    sents = sents2;

    const hash    = hashArr(sents);
    const content = serializeSents(sents);

    try {
      await VigilDB.ready;
      const latest = await VigilDB.Snapshots.getLast(url);

      if (!latest) {
        await VigilDB.Snapshots.save(url, content, document.title, 0);
        console.log('[Vigil TM] First snapshot:', getDomain(url), `(${sents.length} sentences)`);
        return;
      }

      if (Date.now() - latest.timestamp < CFG.cooldownMs) {
        console.log('[Vigil TM] Cooldown active — skipping'); return;
      }

      const prevSents = deserializeSents(latest.content);
      if (hashArr(prevSents) === hash) {
        await VigilDB.Snapshots.save(url, content, document.title, 0); return;
      }

      const blocks    = runDiff(prevSents, sents);
      const hasChange = blocks.some(b => b.type !== 'unchanged');
      if (!hasChange) {
        await VigilDB.Snapshots.save(url, content, document.title, 0); return;
      }

      const sev = calcSeverity(blocks, prevSents.length, sents.length);
      console.log(`[Vigil TM] ${sev.label} change on ${getDomain(url)}`);
      await VigilDB.Snapshots.save(url, content, document.title, sev.effectivePct);
      cachedDiff = { blocks, sev, oldSnap: latest };
      buildOverlay(blocks, sev, latest);
      sendNotif(sev, document.title);
    } catch (err) {
      console.error('[Vigil TM] Error:', err);
    }
  }

  // ─── SPA detection ────────────────────────────────────────────────────────
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      cachedDiff = null;
      setTimeout(runTimeMachine, CFG.snapshotDelay + 500);
    }
  }).observe(document.documentElement, { childList:true, subtree:true });

  // ─── Utils ────────────────────────────────────────────────────────────────
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function escH(s) {
    return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function getDomain(url) {
    try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return url; }
  }
  function fmtAgo(ms) {
    const s = Math.floor(ms/1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s/60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m/60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h/24);
    return d < 30 ? `${d}d ago` : `${Math.floor(d/30)}mo ago`;
  }

  // ─── Boot ─────────────────────────────────────────────────────────────────
  runTimeMachine();
  console.log('[Vigil] timeMachine v1.4 loaded on', location.hostname);
})();