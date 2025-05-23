
(async () => {
  // Initialize state object
  window.__CMP_STATE__ = window.__CMP_STATE__ || {
    loading: false,
    loaded: false,
    initialized: false
  };
   hideBannerclient(document.getElementById("consent-banner"));
   hideBannerclient(document.getElementById("initial-consent-banner"));
   hideBannerclient(document.getElementById("main-banner"));
   hideBannerclient(document.getElementById("main-consent-banner "));

  
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
          `${CONFIG.baseUrl}/request-token`,
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
          `${CONFIG.baseUrl}/detect-location`,
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
          let locationData = await this.getLocation();
           if (
            window.location.hostname === "sungreensystems.com" ||
            window.location.hostname === "www.sungreensystems.com" ||
            window.location.hostname === "sungreen-systems.webflow.io"
          ) {
            bannerType = "GDPR";
          } else if (locationData && typeof locationData === "object") {
            if (locationData.isEU) {
              bannerType = "GDPR";
            } else if (locationData.country === "US") {
              bannerType = "CCPA";
            } else {
              bannerType = "GDPR";
            }
          } else {
            bannerType = locationData;
          }

          fetchBanner(locationData);
          await this.loadScript(token);
          
          // Call fetchBanner to show the appropriate banner
          
          
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
            
            // Hide all banners immediately if consent is given
            hideBannerclient(document.getElementById("consent-banner"));
            hideBannerclient(document.getElementById("initial-consent-banner"));
            hideBannerclient(document.getElementById("main-banner"));
            hideBannerclient(document.getElementById("main-consent-banner"));
            return; // Exit early if consent is already given
        }

        // Log the location data for debugging
        

        // Show the appropriate banner based on the location data
        if (locationData === "GDPR") {
            
            hideBannerclient(document.getElementById("initial-consent-banner"));
            hideBannerclient(document.getElementById("main-consent-banner"));
            showBannerclient(document.getElementById("consent-banner"));
        } else if (locationData === "CCPA") {
            
            hideBannerclient(document.getElementById("consent-banner"));
            hideBannerclient(document.getElementById("main-banner"));
            showBannerclient(document.getElementById("initial-consent-banner"));
        } else {
            
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
    const DELAY_MS = 3000;
    const analyticsPatterns = /gtag|analytics|googletagmanager|google-analytics|fbevents|facebook/i;
    
    // Block initial script loading
    const originalCreateElement = document.createElement;
    document.createElement = function(tag) {
        const element = originalCreateElement.call(document, tag);
        if (tag.toLowerCase() === 'script') {
            const originalSetAttribute = element.setAttribute;
            element.setAttribute = function(name, value) {
                if (name === 'src' && analyticsPatterns.test(value)) {
                    
                    element.type = 'javascript/blocked';
                    element.dataset.originalSrc = value;
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
                
                script.type = 'javascript/blocked';
                script.dataset.originalSrc = script.src;
                script.src = '';
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
            
            return;
        }

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

    // Set timeout for script restoration
    setTimeout(restoreScripts, DELAY_MS);
})();
