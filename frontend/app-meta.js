(function () {
  const fallback = {
    author: 'PiBroadGuard · Markus Gerber · markus.gerber@npn.ch',
    standards: 'IEC 62443-3-2/-4-2 | NIST SP 800-82r3/-115/-30r1',
    version: 'v1.8 | March 2026',
    logo_path: '/app/assets/pibg-logo.svg',
    logo_alt: 'PiBroadGuard Logo',
  };

  async function loadMeta() {
    try {
      const resp = await fetch('/api/v1/system/ui-meta');
      if (!resp.ok) return fallback;
      const data = await resp.json();
      return { ...fallback, ...data };
    } catch {
      return fallback;
    }
  }

  function applyMeta(meta) {
    document.querySelectorAll('[data-pibg-meta]').forEach((el) => {
      const key = el.getAttribute('data-pibg-meta');
      if (meta[key] !== undefined) el.textContent = meta[key];
    });
    document.querySelectorAll('[data-pibg-logo]').forEach((img) => {
      if (meta.logo_path) img.setAttribute('src', meta.logo_path);
      if (meta.logo_alt) img.setAttribute('alt', meta.logo_alt);
    });
  }

  window.PiBGMeta = {
    fallback,
    async init() {
      const meta = await loadMeta();
      applyMeta(meta);
      return meta;
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { window.PiBGMeta.init(); });
  } else {
    window.PiBGMeta.init();
  }
})();
