
(async () => {
  // Set up CMP state
  window.__CMP_STATE__ = window.__CMP_STATE__ || {
    loading: false,
    loaded: false,
    initialized: false
  }; 

  // Hide all banners initially
  function hideBannerclient(banner) {
    if (banner) {
      banner.style.display = "none";
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }
  hideBannerclient(document.getElementById("consent-banner"));
  hideBannerclient(document.getElementById("initial-consent-banner"));
  hideBannerclient(document.getElementById("main-banner"));
  hideBannerclient(document.getElementById("main-consent-banner"));

  // Config
  const CONFIG = {
    maxRetries: 5,
    baseUrl: 'https://cmp-consentv2-worker.web-8fb.workers.dev',
    retryDelay: 2000,
    scriptTimeout: 5000
  };

  class ScriptLoader {
    static async fetchWithTimeout(url, options = {}, timeout = 5000) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
          headers: { 'Content-Type': 'application/json' }
        });
        clearTimeout(timeoutId);
        return response;
      } catch (error) {
        clearTimeout(timeoutId);
        throw error;
      }
    }

    static async getToken() {
      try {
        const response = await this.fetchWithTimeout(
          `${CONFIG.baseUrl}/request-token`,
          { method: 'GET', mode: 'cors', credentials: 'omit' }
        );
        if (!response.ok) return null;
        const data = await response.json();
        return data.token || null;
      } catch (error) {
        console.error("Token fetch error:", error);
        return null;
      }
    }

    static loadScript(token) {
      return new Promise((resolve, reject) => {
        if (window.__CMP_STATE__.loaded) return resolve(true);
        const script = document.createElement('script');
        const timestamp = Date.now();
        script.src = `${CONFIG.baseUrl}/cmp-script?token=${encodeURIComponent(token)}&_=${timestamp}`;
        script.async = true;
        const timeoutId = setTimeout(() => {
          script.remove();
          window.__CMP_STATE__.loading = false;
          reject(new Error('Script load timeout'));
        }, CONFIG.scriptTimeout);
        script.onload = () => {
          clearTimeout(timeoutId);
          window.__CMP_STATE__.loaded = true;
          window.__CMP_STATE__.loading = false;
          resolve(true);
        };
        script.onerror = (error) => {
          clearTimeout(timeoutId);
          script.remove();
          window.__CMP_STATE__.loading = false;
          reject(new Error('Script load failed'));
        };
        window.__CMP_STATE__.loading = true;
        document.head.appendChild(script);
      });
    }

    static async initialize() {
      let attempt = 0;
      let delay = CONFIG.retryDelay;
      while (attempt < CONFIG.maxRetries) {
        try {
          attempt++;
          const token = await this.getToken();
          if (!token) throw new Error('Invalid token');
          await this.loadScript(token);
          return true;
        } catch (error) {
          if (attempt === CONFIG.maxRetries) {
            console.error('CMP script loading failed after all retries');
            return false;
          }
          await new Promise(resolve => setTimeout(resolve, delay));
          delay *= 1.5;
        }
      }
      return false;
    }
  }

  try {
    // Initial load attempt
    await ScriptLoader.initialize();
    // Backup initialization check
    window.addEventListener('load', async () => {
      if (!window.__CMP_STATE__.loaded) {
        try { await ScriptLoader.initialize(); } catch (error) {}
      }
    });
  } catch (error) {
    console.error('Fatal error in CMP initialization:', error);
  }
})();

// --- Script Analysis Functionality ---

async function analyzeScripts() {
  const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
    src: s.src || null,
    content: s.src ? null : s.textContent
  }));

  const response = await fetch('https://cmp-consentv2-worker.web-8fb.workers.dev/ai-identify-scripts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scripts })
  });

  let result;
  try {
    result = await response.json();
  } catch (e) {
    result = { error: "Failed to parse response", details: e.message };
  }

  // Display result in your UI
  const div = document.getElementById('script-analysis');
  if (div) {
    div.innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
  } else {
    // fallback: log to console
    console.log(result);
  }
}
