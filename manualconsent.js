
(async () => {
  // Initialize state object
  window.__CMP_STATE__ = window.__CMP_STATE__ || {
    loading: false,
    loaded: false,
    initialized: false
  };

  const CONFIG = {
    maxRetries: 5,
    baseUrl: 'https://app.consentbit.com',
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
          headers: {
            'Content-Type': 'application/json'
          }
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
          `${CONFIG.baseUrl}/cmp/request-token`,
          {
            method: 'GET',
            mode: 'cors',
            credentials: 'omit'
          }
        );
        
        if (!response.ok) {
          console.error(`Token request failed with status: ${response.status}`);
          return null;
        }

        const data = await response.json();
        if (!data || !data.token) {
          console.error('Invalid token response:', data);
          return null;
        }

        return data.token;
      } catch (error) {
        console.error("Token fetch error:", error);
        return null;
      }
    }

    static async getLocation() {
      try {
        const response = await this.fetchWithTimeout(
          `${CONFIG.baseUrl}/cmp/detect-location`,
          {
            method: 'GET',
            mode: 'cors',
            credentials: 'omit'
          }
        );

        if (!response.ok) {
          console.error(`Location request failed with status: ${response.status}`);
          return null;
        }

        const locationData = await response.json();
        return locationData;
      } catch (error) {
        console.error("Location fetch error:", error);
        return null;
      }
    }

    static loadScript(token) {
      return new Promise((resolve, reject) => {
        if (window.__CMP_STATE__.loaded) {
          return resolve(true);
        }

        const script = document.createElement('script');
        const timestamp = Date.now();
        script.src = `${CONFIG.baseUrl}/cmp/cmp-script?token=${encodeURIComponent(token)}&_=${timestamp}`;
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
          console.error('Script load failed:', error);
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
          if (!token) {
            throw new Error('Invalid token');
          }

          // Fetch location data
          const locationData = await this.getLocation();
          console.log('Location Data:', locationData); // Log the location data
          fetchBanner(locationData);
          await this.loadScript(token);
          
          return true;

        } catch (error) {
          if (attempt === CONFIG.maxRetries) {
            console.error('CMP script loading failed after all retries');
            return false;
          }

          await new Promise(resolve => setTimeout(resolve, delay));
          delay *= 1.5; // Exponential backoff
        }
      }
      return false;
    }
  }

  async function fetchBanner(locationData) {
    try {
        // Check if consent has been given
        const consentGiven = localStorage.getItem("consent-given");
        if (consentGiven === "true") {
            console.log("Consent already given, hiding banners.");
            // Hide all banners immediately if consent is given
            hideBannerclient(document.getElementById("consent-banner"));
            hideBannerclient(document.getElementById("initial-consent-banner"));
            hideBannerclient(document.getElementById("main-banner"));
            hideBannerclient(document.getElementById("main-consent-banner"));
            hideBannerclient(document.getElementById("simple-consent-banner"));
            return; // Exit early if consent is already given
        }
      

        // Show the appropriate banner based on the location data
        if (locationData === "GDPR") {
            console.log("Showing GDPR banner");
            hideBannerclient(document.getElementById("initial-consent-banner"));
            hideBannerclient(document.getElementById("main-consent-banner"));
            showBannerclient(document.getElementById("consent-banner"));
        } else if (locationData === "CCPA") {
            console.log("Showing CCPA banner");
            hideBannerclient(document.getElementById("consent-banner"));
            hideBannerclient(document.getElementById("main-banner"));
            showBannerclient(document.getElementById("initial-consent-banner"));
        } else {
            console.log("No specific banner to show, defaulting to GDPR");
            hideBannerclient(document.getElementById("initial-consent-banner"));
            hideBannerclient(document.getElementById("main-consent-banner"));
            showBannerclient(document.getElementById("consent-banner"));
        }
    } catch (error) {
        console.error("Error fetching banner:", error);
    }
  }

  function showBannerclient(banner) {
    if (banner) {
      banner.style.display = "block";
      banner.classList.add("show-banner");
      banner.classList.remove("hidden");
    }
  }

  function hideBannerclient(banner) {
    if (banner) {
      banner.style.display = "none"; // Hide the banner
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }

  try {
    // Initial load attempt
    await ScriptLoader.initialize();

    // Backup initialization check
    window.addEventListener('load', async () => {
      if (!window.__CMP_STATE__.loaded) {
        console.log('Backup CMP initialization...');
        try {
          await ScriptLoader.initialize();
        } catch (error) {
          console.error('Backup CMP initialization failed:', error);
        }
      }
    });
  } catch (error) {
    console.error('Fatal error in CMP initialization:', error);
  }
})();

(function() {
    const DELAY_MS = 3000; // Delay for restoring scripts
    const analyticsPatterns = /hubspot|matomo|plausible.io|gtag|analytics|googletagmanager|google-analytics|fbevents|facebook|mixpanel|segment|amplitude|hotjar|piwik|clicky|kaltura|quantcast|newrelic/i;

    // Block initial script loading
    const originalCreateElement = document.createElement;
    document.createElement = function(tag) {
        const element = originalCreateElement.call(document, tag);
        if (tag.toLowerCase() === 'script') {
            const originalSetAttribute = element.setAttribute;
            element.setAttribute = function(name, value) {
                if (name === 'src' && analyticsPatterns.test(value)) {
                    element.type = 'javascript/blocked';
                    element.dataset.originalSrc = value; // Store the original source
                    return;
                }
                return originalSetAttribute.call(this, name, value);
            };
        }
        return element;
    };

    // Immediately block any existing analytics scripts
    function blockExistingScripts() {
        const scripts = document.querySelectorAll('script[src]');
        scripts.forEach(script => {
            if (analyticsPatterns.test(script.src)) {
                console.log("Blocking script from head:", script.src);
                script.type = 'javascript/blocked';
                script.dataset.originalSrc = script.src; // Store the original source
                script.src = ''; // Prevent the script from loading
            }
        });
    }

    // Block scripts on load
    document.addEventListener('DOMContentLoaded', blockExistingScripts);
    
    // Block scripts immediately if DOM is already loaded
    if (document.readyState !== 'loading') {
        blockExistingScripts();
    }

    // Create a flag to check if CMP is loaded
    window.cmpLoaded = false;

    // Function to restore scripts after delay
    function restoreScripts() {
        if (window.cmpLoaded) {
            console.log("CMP script loaded, restoring blocked scripts.");
            const blockedScripts = document.querySelectorAll('script[type="javascript/blocked"]');
            blockedScripts.forEach(script => {
                if (script.dataset.originalSrc) {
                    const newScript = document.createElement('script');
                    newScript.src = script.dataset.originalSrc;
                    newScript.async = true;
                    script.parentNode.replaceChild(newScript, script);
                }
            });
        }
    }

    // Monitor for CMP script loading
    const originalAddEventListener = window.addEventListener;
    window.addEventListener = function(type, listener, options) {
        if (type === 'load' && listener.toString().includes('cmpLoaded')) {
            // If CMP script is loaded, set cmpLoaded to true
            window.cmpLoaded = true;
            restoreScripts(); // Restore blocked scripts
        }
        return originalAddEventListener.call(this, type, listener, options);
    };

    // Set timeout for script restoration
    setTimeout(restoreScripts, DELAY_MS);
})();


