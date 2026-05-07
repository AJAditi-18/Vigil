// Vigil — central database manager
// FIX: Added `ready` promise export. Previous version did not export it,
// so `await VigilDB.ready` in timeMachine.js threw "Cannot read properties
// of undefined (reading 'then')", silently killing the entire snapshot flow.

const VigilDB = (() => {

  if (typeof Dexie === 'undefined') {
    console.error(
      'Vigil VigilDB: Dexie is not defined. ' +
      'Make sure lib/dexie.min.js is listed FIRST in manifest.json js array. ' +
      'Download: https://unpkg.com/dexie@latest/dist/dexie.min.js'
    );
    const notReady = () => Promise.reject(new Error('VigilDB not ready: Dexie missing'));
    const stub = {
      getLast: notReady, getAll: notReady, save: notReady,
      deleteAll: notReady, getAllUrls: notReady, getTotalSize: notReady
    };
    return {
      Snapshots: stub, Tabs: stub, Clipboard: stub,
      Forms: stub, Links: stub, Stats: stub, db: null,
      ready: Promise.reject(new Error('Dexie missing'))
    };
  }

  const db = new Dexie('vigil_master');

  db.version(1).stores({
    snapshots:  '++id, url, timestamp, wordCount',
    network:    '++id, tabId, url, domain, timestamp, trusted',
    clipboard:  '++id, timestamp, expiresAt, domain',
    tabs:       'tabId, url, openedAt, lastVisited, read',
    tabHistory: '++id, url, openedAt, closedAt, read',
    forms:      '++id, url, timestamp, fieldCount, hasHidden',
    linkCache:  'url, score, checkedAt, safe'
  });

  // ── KEY FIX: export `ready` so callers can await DB open ─────────────────
  // Dexie opens lazily on first query in content-script context but in the
  // options page and popup contexts this races with queries. Awaiting `ready`
  // before any query is the correct fix.
  const ready = db.open().catch(err => {
    console.error('[Vigil] DB open failed:', err);
    throw err;
  });

  // ── Module 1: Snapshots ───────────────────────────────────────────────────
  const Snapshots = {
    async getLast(url) {
      return db.snapshots
        .where('url').equals(url)
        .reverse().sortBy('timestamp')
        .then(r => r[0] || null);
    },

    async getAll(url) {
      return db.snapshots
        .where('url').equals(url)
        .reverse().sortBy('timestamp');
    },

    async save(url, content, title, changeSize = 0) {
      await db.snapshots.add({
        url, content, title,
        wordCount: content.split(/\s+/).length,
        changeSize,
        timestamp: Date.now()
      });
      const all = await this.getAll(url);
      if (all.length > 20) {
        await db.snapshots.bulkDelete(all.slice(20).map(s => s.id));
      }
    },

    async deleteAll(url) {
      const ids = (await this.getAll(url)).map(s => s.id);
      await db.snapshots.bulkDelete(ids);
    },

    async getAllUrls() {
      const all = await db.snapshots.orderBy('timestamp').reverse().toArray();
      const seen = {};
      return all.filter(s => {
        if (seen[s.url]) return false;
        seen[s.url] = true;
        return true;
      });
    },

    async getTotalSize() {
      const all   = await db.snapshots.toArray();
      const bytes = all.reduce((acc, s) =>
        acc + (s.content ? s.content.length * 2 : 0), 0
      );
      return (bytes / 1024 / 1024).toFixed(2);
    }
  };

  // ── Module 4: Tabs ────────────────────────────────────────────────────────
  const Tabs = {
    async upsert(tabData) { await db.tabs.put(tabData); },
    async get(tabId)      { return db.tabs.get(tabId); },
    async getAll()        { return db.tabs.toArray(); },

    async remove(tabId) {
      const tab = await this.get(tabId);
      if (tab) {
        await db.tabHistory.add({ ...tab, closedAt: Date.now() });
        const count = await db.tabHistory.count();
        if (count > 100) {
          const oldest = await db.tabHistory.orderBy('closedAt').first();
          if (oldest) await db.tabHistory.delete(oldest.id);
        }
        await db.tabs.delete(tabId);
      }
    },

    async getHistory() {
      return db.tabHistory.orderBy('closedAt').reverse().toArray();
    }
  };

  // ── Module 3: Clipboard ───────────────────────────────────────────────────
  const Clipboard = {
    async save(encryptedData, preview, domain, expiryMinutes = 60) {
      await db.clipboard.add({
        encryptedData, preview, domain,
        timestamp: Date.now(),
        expiresAt: Date.now() + expiryMinutes * 60 * 1000
      });
    },
    async getActive() {
      return db.clipboard.where('expiresAt').above(Date.now())
        .reverse().sortBy('timestamp');
    },
    async purgeExpired() {
      await db.clipboard.where('expiresAt').below(Date.now()).delete();
    },
    async deleteAll() { await db.clipboard.clear(); }
  };

  // ── Module 5: Forms ───────────────────────────────────────────────────────
  const Forms = {
    async save(url, fields, hiddenFields, encryptedData) {
      await db.forms.add({
        url, fields, hiddenFields,
        fieldCount: fields.length,
        hasHidden:  hiddenFields.length > 0,
        encryptedData,
        timestamp: Date.now()
      });
    },
    async getForUrl(url) {
      return db.forms.where('url').equals(url).reverse().sortBy('timestamp');
    },
    async getAll() {
      return db.forms.orderBy('timestamp').reverse().toArray();
    }
  };

  // ── Module 6: Links ───────────────────────────────────────────────────────
  const Links = {
    async getCached(url) {
      const entry = await db.linkCache.get(url);
      if (!entry) return null;
      if (Date.now() - entry.checkedAt > 86400000) {
        await db.linkCache.delete(url);
        return null;
      }
      return entry;
    },
    async saveResult(url, score, safe) {
      await db.linkCache.put({ url, score, safe, checkedAt: Date.now() });
    },
    async clearOld() {
      await db.linkCache.where('checkedAt').below(Date.now() - 86400000).delete();
    }
  };

  // ── Stats ─────────────────────────────────────────────────────────────────
  const Stats = {
    async getSummary() {
      return {
        snapshots:  await db.snapshots.count(),
        tabs:       await db.tabs.count(),
        tabHistory: await db.tabHistory.count(),
        clipboard:  await db.clipboard.count(),
        forms:      await db.forms.count(),
        linkCache:  await db.linkCache.count(),
        sizeMB:     await Snapshots.getTotalSize()
      };
    },
    async nukeAll() {
      await Promise.all([
        db.snapshots.clear(), db.network.clear(), db.clipboard.clear(),
        db.tabs.clear(), db.tabHistory.clear(), db.forms.clear(), db.linkCache.clear()
      ]);
    }
  };

  return { Snapshots, Tabs, Clipboard, Forms, Links, Stats, db, ready };

})();