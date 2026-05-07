// Vigil — Tracker List Helper
// Parses disconnect.json into a fast lookup map

const TrackerList = (() => {

  let domainMap = {};
  let loaded    = false;

  const CATEGORY_INFO = {
    'Advertising': {
      label: 'Ad network',
      color: '#f44336',
      bg:    'rgba(244,67,54,0.15)',
      trust: 0
    },
    'Analytics': {
      label: 'Analytics',
      color: '#ff9800',
      bg:    'rgba(255,152,0,0.15)',
      trust: 2
    },
    'Social': {
      label: 'Social tracker',
      color: '#9c27b0',
      bg:    'rgba(156,39,176,0.15)',
      trust: 1
    },
    'Fingerprinting': {
      label: 'Fingerprinter',
      color: '#e91e63',
      bg:    'rgba(233,30,99,0.15)',
      trust: 0
    },
    'Cryptomining': {
      label: 'Cryptominer',
      color: '#ff5722',
      bg:    'rgba(255,87,34,0.15)',
      trust: 0
    },
    'Content': {
      label: 'Content delivery',
      color: '#607d8b',
      bg:    'rgba(96,125,139,0.15)',
      trust: 3
    },
    'Disconnect': {
      label: 'Tracked by Disconnect',
      color: '#ff9800',
      bg:    'rgba(255,152,0,0.15)',
      trust: 1
    }
  };

  const DEFAULT_INFO = {
    label: 'Unknown',
    color: '#555',
    bg:    'rgba(100,100,100,0.1)',
    trust: 5
  };

  async function load() {
    if (loaded) return;
    try {
      const url  = chrome.runtime.getURL('data/disconnect.json');
      const res  = await fetch(url);
      const json = await res.json();

      // Disconnect format:
      // { categories: { Advertising: { CompanyName: { domains: [...] } } } }
      const categories = json.categories || {};
      Object.entries(categories).forEach(([category, companies]) => {
        Object.values(companies).forEach(company => {
          Object.values(company).forEach(entry => {
            if (Array.isArray(entry)) {
              entry.forEach(domain => {
                domainMap[domain.toLowerCase()] = category;
              });
            }
          });
        });
      });

      loaded = true;
      console.log(
        `Vigil TrackerList: loaded ${Object.keys(domainMap).length} domains`
      );
    } catch (err) {
      console.error('Vigil TrackerList: failed to load', err);
    }
  }

  function lookup(hostname) {
    if (!hostname) return null;
    const host = hostname.toLowerCase().replace(/^www\./, '');

    // Exact match
    if (domainMap[host]) {
      const cat = domainMap[host];
      return {
        category: cat,
        ...(CATEGORY_INFO[cat] || DEFAULT_INFO)
      };
    }

    // Parent domain match
    // e.g. sub.doubleclick.net → doubleclick.net
    const parts = host.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (domainMap[parent]) {
        const cat = domainMap[parent];
        return {
          category: cat,
          ...(CATEGORY_INFO[cat] || DEFAULT_INFO)
        };
      }
    }

    return null; // not a known tracker
  }

  function getCategoryInfo(category) {
    return CATEGORY_INFO[category] || DEFAULT_INFO;
  }

  return { load, lookup, getCategoryInfo, CATEGORY_INFO, DEFAULT_INFO };

})();