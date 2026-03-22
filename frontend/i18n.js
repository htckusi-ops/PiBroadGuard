// PiBroadGuard i18n helper
// Loads translations from /api/v1/i18n/{lang}, default: 'en'
(function () {
  window.PiBGi18n = {
    _cache: {},
    _lang: localStorage.getItem('pibg_lang') || 'en',

    async load(lang) {
      lang = lang || this._lang;
      if (!this._cache[lang]) {
        try {
          const resp = await fetch('/api/v1/i18n/' + lang);
          this._cache[lang] = resp.ok ? await resp.json() : {};
        } catch (e) {
          this._cache[lang] = {};
        }
      }
      this._lang = lang;
      localStorage.setItem('pibg_lang', lang);
      document.documentElement.lang = lang;
      return this._cache[lang];
    },

    t(key, fallback) {
      const tr = this._cache[this._lang] || {};
      return tr[key] !== undefined ? tr[key] : (fallback !== undefined ? fallback : key);
    },

    currentLang() {
      return this._lang;
    }
  };
})();
