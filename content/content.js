// Vigil content script — master loader

// ─── Dependency diagnostics ───────────────────────────────────────
// These logs appear in the DevTools console of every page Vigil runs on.
// If any value shows "undefined", the corresponding lib failed to load —
// check the file path in manifest.json and reload the extension.

console.log('Vigil active on:', window.location.href);

// Dexie.js — required by vigilDB.js
console.log('Vigil Dexie status:', typeof Dexie !== 'undefined' ? '✓ loaded' : '✗ MISSING');

// VigilDB — required by timeMachine.js, networkMap.js, formShadow.js
console.log('Vigil VigilDB status:', typeof VigilDB !== 'undefined' ? '✓ loaded' : '✗ MISSING');

// jsdiff — required by timeMachine.js
// The jsdiff library may expose itself as either `Diff` or `JsDiff`
// depending on the build. We check both so the diagnostic is accurate.
const diffGlobal =
  (typeof Diff !== 'undefined' && typeof Diff.diffArrays === 'function')
    ? 'Diff'
    : (typeof JsDiff !== 'undefined' && typeof JsDiff.diffArrays === 'function')
      ? 'JsDiff'
      : null;

if (diffGlobal) {
  console.log('Vigil Diff status: ✓ loaded — global name is:', diffGlobal);
} else {
  console.warn(
    'Vigil Diff status: ✗ MISSING — diff.min.js did not expose a usable global. ' +
    'Make sure you are using the browser UMD build from ' +
    'https://cdnjs.cloudflare.com/ajax/libs/jsdiff/5.2.0/diff.min.js'
  );
}

// ── Message router ────────────────────────────────────────────────────────────
// Relays messages that require content-script context (VigilDB access, DOM access)
// back to background.js which cannot directly query Dexie or the live DOM.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {

  // ── Clipboard Vault: count query ──────────────────────────────────────────
  if (msg.action === 'getClipboardCount') {
    (async () => {
      try {
        await VigilDB.ready;
        await VigilDB.Clipboard.purgeExpired();
        const entries = await VigilDB.Clipboard.getActive();
        sendResponse({ count: entries.length });
      } catch {
        sendResponse({ count: 0 });
      }
    })();
    return true;
  }

  // ── Link Scorer: rescan relay ─────────────────────────────────────────────
  // background.js relays 'rescanLinks' and 'getLinkReport' here.
  // LinkScorer listens for these itself; no relay needed — it registers its
  // own chrome.runtime.onMessage listener. This block is intentionally empty
  // so background.js can forward without error.

  // ── Form Shadow: receipt count query ─────────────────────────────────────
  if (msg.action === 'getFormCount') {
    (async () => {
      try {
        await VigilDB.ready;
        const forms = await VigilDB.Forms.getAll();
        sendResponse({ count: forms.length });
      } catch {
        sendResponse({ count: 0 });
      }
    })();
    return true;
  }

});