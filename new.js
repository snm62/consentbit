
(async function () {
    let isLoadingState = false;
    let consentState = {};
    let observer;
    let isInitialized = false;
    const blockedScripts = [];
    let currentBannerType = null;
    let country =null;
    const categorizedScripts=null;      
    

    function blockAllScripts() {
      console.log("----inside Block ALL SCRIPTS STARTED-----")
      console.log("INVOKE: BLOCK META FUNCTIONS")

    blockMetaFunctions();
    console.log("INVOKE: BLOCK blockAnalyticsRequests")

    blockAnalyticsRequests();
    console.log("INVOKE: BLOCK scanAndBlockScripts")

    scanAndBlockScripts();
    console.log("INVOKE: BLOCK blockDynamicScripts")

    blockDynamicScripts();
    console.log("INVOKE: BLOCK createPlaceholderScripts")

    createPlaceholderScripts();

    if (!consentState.marketing) {
      console.log("----inside Block ALL SCRIPTS :INVOKE blockMarketingScripts-----")

      blockMarketingScripts();
  }
  if (!consentState.personalization) {
    console.log("----inside Block ALL SCRIPTS :INVOKE blockPersonalizationScripts-----")

      blockPersonalizationScripts();
  }
  if (!consentState.analytics) {
    console.log("----inside Block ALL SCRIPTS :INVOKE blockAnalyticsScripts-----")

    
      blockAnalyticsScripts();
  }

  console.log("----inside Block ALL SCRIPTS FINISHED-----")

  }


 // Function to get visitor session token
    async function getVisitorSessionToken() {
        try {
            // Get or create visitor ID
            const visitorId = await getOrCreateVisitorId();
            
            // Get cleaned site name
            const siteName = await  cleanHostname(window.location.hostname);
            
            // Check if we have a valid token in localStorage
            let token = localStorage.getItem('visitorSessionToken');
            
            // If we have a token and it's not expired, return it
            if (token && !isTokenExpired(token)) {
                console.log("Token is in localstorage")
                return token;
            }

            // Request new token from server
            const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    visitorId: visitorId,
                    userAgent: navigator.userAgent,
                    siteName: siteName
                })
            });

            if (!response.ok) {
                throw new Error('Failed to get visitor session token');
            }

            const data = await response.json();
            
            // Store the new token
            localStorage.setItem('visitorSessionToken', data.token);
            
            return data.token;
        } catch (error) {
            console.error('Error getting visitor session token:', error);
            return null;
        }
    }
 // Function to check if token is expired
 function isTokenExpired(token) {
    try {
        const [payloadBase64] = token.split('.');
        const payload = JSON.parse(atob(payloadBase64));
        
        if (!payload.exp) return true;
        
        return payload.exp < Math.floor(Date.now() / 1000);
    } catch (error) {
        console.error('Error checking token expiration:', error);
        return true;
    }
}

// Function to clean hostname
async function cleanHostname(hostname) {
    let cleaned = hostname.replace(/^www\./, '');
    cleaned = cleaned.split('.')[0];
    return cleaned;
}

// Function to generate or get visitor ID
async function getOrCreateVisitorId() {
    let visitorId = localStorage.getItem('visitorId');
    if (!visitorId) {
        visitorId = crypto.randomUUID();
        localStorage.setItem('visitorId', visitorId);
    }
    return visitorId;
}
async function detectLocationAndGetBannerType() {
  try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
          console.log("No visitor session token found in detect location");
          return null;
      }

      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      const response = await fetch(`https://cb-server.web-8fb.workers.dev/api/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`, {
          method: 'GET',
          headers: {
              'Authorization': `Bearer ${sessionToken}`,
              'Content-Type': 'application/json',
              'Accept': 'application/json'
          },
          // credentials: 'include'
      });

      if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('Failed to load banner type:', errorData);
          return null;
      }

      const data = await response.json();
      // Changed to check for bannerType instead of scripts
      if (!data.bannerType) {
          console.error('Invalid banner type data format');
          return null;
      }

      return data;
  } catch (error) {
      console.error('Error detecting location:', error);
      return null;
  }
}
/**
 * Encryption Utilities for Consent Management Platform
 * Provides secure encryption and decryption functions using the Web Crypto API
 */
const EncryptionUtils = {
  /**
   * Generates a new encryption key and IV
   * @returns {Promise<{key: CryptoKey, iv: Uint8Array}>}
   */
  async generateKey() {
      const key = await crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      return { key, iv };
  },

  /**
   * Imports a raw key for encryption/decryption
   * @param {Uint8Array} rawKey - The raw key bytes
   * @param {string[]} usages - Array of key usages ['encrypt', 'decrypt']
   * @returns {Promise<CryptoKey>}
   */
  async importKey(rawKey, usages = ['encrypt', 'decrypt']) {
      return await crypto.subtle.importKey(
          'raw',
          rawKey,
          { name: 'AES-GCM' },
          false,
          usages
      );
  },

  /**
   * Encrypts data using AES-GCM
   * @param {string} data - The data to encrypt
   * @param {CryptoKey} key - The encryption key
   * @param {Uint8Array} iv - The initialization vector
   * @returns {Promise<string>} - Base64 encoded encrypted data
   */
  async encrypt(data, key, iv) {
      const encoder = new TextEncoder();
      const encodedData = encoder.encode(data);
      const encrypted = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          encodedData
      );
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  },

  /**
   * Decrypts data using AES-GCM
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @param {CryptoKey} key - The decryption key
   * @param {Uint8Array} iv - The initialization vector
   * @returns {Promise<string>} - Decrypted data
   */
  async decrypt(encryptedData, key, iv) {
      const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
      const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          key,
          encryptedBytes
      );
      return new TextDecoder().decode(decrypted);
  }
};

/**
* Loads categorized scripts from the server with encryption
* @returns {Promise<Array>} Array of categorized scripts
*/
async function loadCategorizedScripts() {
  try {
      // Get session token from localStorage
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
          console.error('No session token found');
          return [];
      }

      // Get or generate visitorId
      let visitorId = localStorage.getItem('visitorId');
      if (!visitorId) {
          visitorId = crypto.randomUUID();
          localStorage.setItem('visitorId', visitorId);
      }

      // Get site name from hostname
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      
      // Generate encryption key and IV
      const { key, iv } = await EncryptionUtils.generateKey();
      
      // Prepare request data
      const requestData = {
          siteName: siteName,
          visitorId: visitorId,
          userAgent: navigator.userAgent
      };
      
      // Encrypt the request data
      const encryptedRequest = await EncryptionUtils.encrypt(
          JSON.stringify(requestData),
          key,
          iv
      );
      
      // Send the encrypted request
      const response = await fetch('https://cb-server.web-8fb.workers.dev/api/cmp/script-category', {
          method: 'POST',
          headers: {
              'Authorization': `Bearer ${sessionToken}`,
              'X-Request-ID': crypto.randomUUID(),
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'Origin': window.location.origin
          },
          body: JSON.stringify({
              encryptedData: encryptedRequest,
              key: Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', key))),
              iv: Array.from(iv)
          })
      });

      if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('Failed to load categorized scripts:', errorData);
          return [];
      }

      const data = await response.json();
      
      // Decrypt the response data
      if (data.encryptedData) {
          const responseKey = await EncryptionUtils.importKey(
              new Uint8Array(data.key),
              ['decrypt']
          );
          
          const decryptedData = await EncryptionUtils.decrypt(
              data.encryptedData,
              responseKey,
              new Uint8Array(data.iv)
          );
          
          const responseObj = JSON.parse(decryptedData);
          console.log("decrypted Script category",responseObj.scripts)
          categorizedScripts =responseObj.scripts || [];
          console.log("initial categorized script",categorizedScripts);
          return responseObj.scripts || [];
      } else {
          console.error('Response does not contain encrypted data');
          return [];
      }
  } catch (error) {
      console.error('Error loading categorized scripts:', error);
      return [];
  }
} 
    async function loadConsentState() {
      if (isLoadingState) {
        
        return;
     }
        isLoadingState = true;
    
        blockAllInitialRequests();
        blockAllScripts();
        
        const consentGiven = localStorage.getItem("consent-given");
        
        if (consentGiven === "true") {
          try {
              const savedPreferences = JSON.parse(localStorage.getItem("consent-preferences"));
              if (savedPreferences?.encryptedData) {
                  const decryptedData = await decryptData(
                      savedPreferences.encryptedData,
                      await importKey(Uint8Array.from(savedPreferences.key)),
                      Uint8Array.from(savedPreferences.iv)
                  );
                  consentState = JSON.parse(decryptedData);
                  consentState = {
                    necessary: consentState.necessary || true,
                    marketing: consentState.marketing || false,
                    personalization: consentState.personalization || false,
                    analytics: consentState.analytics || false,
                    ccpa: {
                        doNotShare: consentState.ccpa?.doNotShare || false // Safely access doNotShare
                    }
                };
  
                  
                  // Update checkbox states if they exist
           const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]')
           const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]')
           const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]')
           const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]')
           const doNotShareCheckbox = document.getElementById("do-not-share-checkbox");



  
                  if (necessaryCheckbox) {
                    necessaryCheckbox.checked = true; // Always true
                    necessaryCheckbox.disabled = true; // Disable the necessary checkbox
                  }

          
  
    
                  if (necessaryCheckbox) necessaryCheckbox.checked = true; // Always true
                  if (marketingCheckbox) marketingCheckbox.checked = consentState.marketing || false;
                  if (personalizationCheckbox) personalizationCheckbox.checked = consentState.personalization || false;
                  if (analyticsCheckbox) analyticsCheckbox.checked = consentState.analytics || false;
                  if (doNotShareCheckbox) doNotShareCheckbox.checked = consentState.ccpa.doNotShare || false;
              }
          } catch (error) {
              console.error("Error loading consent state:", error);
              consentState = { 
                  necessary: true,
                  marketing: false,
                  personalization: false,
                  analytics: false ,
                  ccpa: { doNotShare: false } 
              };
          }
      } else {
            consentState = { 
               necessary: true,
               marketing: false,
               personalization: false,
               analytics: false ,
               ccpa: { doNotShare: false } 
      };
    }
    
        initialBlockingEnabled = !consentState.analytics;
        
        // Always scan and block on initial load
        blockAllScripts();
        
        // If analytics are accepted, unblock after initial scan
        if (!initialBlockingEnabled) {
          unblockScripts({ analytics: true });
        }
        isLoadingState = false;
    }
    
    async function initializeBannerVisibility() {
      //const request = new Request(window.location.href);
      const locationData = await detectLocationAndGetBannerType();  
      console.log("Location Data",locationData);
      currentBannerType = locationData?.bannerType;
      country = locationData?.country;  
      const consentGiven = localStorage.getItem("consent-given");
      const consentBanner = document.getElementById("consent-banner"); // GDPR banner
      const ccpaBanner = document.getElementById("initial-consent-banner"); // CCPA banner
      const mainBanner = document.getElementById("main-banner"); // Main banner
      const mainConsentBanner = document.getElementById("main-consent-banner"); 
  
      if (consentGiven === "true") {
        //console.log("Consent already given, skipping banner display.");
        hideBanner(consentBanner);
        hideBanner(ccpaBanner);
        return; 
      }
      // Show the appropriate banner based on location
      if (currentBannerType === "GDPR") {
        showBanner(consentBanner); // Show GDPR banner
        hideBanner(ccpaBanner); // Hide CCPA banner
      } else if (currentBannerType === "CCPA") {
        showBanner(ccpaBanner); // Show CCPA banner
        hideBanner(consentBanner); // Hide GDPR banner
      } else {
        showBanner(consentBanner); // Default to showing GDPR banner
        hideBanner(ccpaBanner);
      }
    }
  
    async function initialize() {
         // Get visitor session token first
         await hardenScriptBlocking();
       await loadConsentState();
       await getVisitorSessionToken();
       loadConsentStyles();
       await loadCategorizedScripts();

      scanExistingCookies();
      hideBanner(document.getElementById("consent-banner"));
      hideBanner(document.getElementById("initial-consent-banner"));
      hideBanner(document.getElementById("main-banner"));
      hideBanner(document.getElementById("main-consent-banner"));
      hideBanner(document.getElementById("simple-consent-banner"));
     
      await initializeBannerVisibility();
      const hasMainBanners = document.getElementById("consent-banner") ||document.getElementById("initial-consent-banner");
  
    // if (!hasMainBanners) {
    //   // If no main banners exist, initialize simple banner
    //   initializeSimpleBanner();
    // } else {
    //   // Otherwise initialize main banners
    //   await initializeBannerVisibility();
    // }
    
      attachBannerHandlers();
   //   monitorCookieChanges();
      
    }
      document.addEventListener('DOMContentLoaded',  initialize);
      document.addEventListener("DOMContentLoaded", function () {
        const scrollControl = document.querySelector('[scroll-control="true"]');
        function toggleScrolling() {
          const banner = document.querySelector('[data-cookie-banner="true"]');
          if (!banner) return;
          const observer = new MutationObserver(() => {
            const isVisible = window.getComputedStyle(banner).display !== "none";
            document.body.style.overflow = isVisible ? "hidden" : "";
          });
          // Initial check on load
          const isVisible = window.getComputedStyle(banner).display !== "none";
          document.body.style.overflow = isVisible ? "hidden" : "";
          observer.observe(banner, { attributes: true, attributeFilter: ["style", "class"] });
        }
        if (scrollControl) {
          toggleScrolling();
        }
      });

  
    async function initializeBlocking() {
        blockAllScripts();
        const consentGiven = localStorage.getItem("consent-given");
        const consentBanner = document.getElementById("consent-banner");
        const ccpaBanner = document.getElementById("initial-consent-banner");
        
      
        if (consentGiven === "true") {
          return; 
        }   
      
        if (consentGiven === "true") {
          try {
            const savedPreferences = JSON.parse(localStorage.getItem("consent-preferences"));
            if (savedPreferences?.encryptedData) {
              const decryptedData = await decryptData(
                savedPreferences.encryptedData,
                await importKey(Uint8Array.from(savedPreferences.key)),
                Uint8Array.from(savedPreferences.iv)
              );
              const preferences = JSON.parse(decryptedData);
              initialBlockingEnabled = !preferences.analytics;
      
              // Show the appropriate banner based on preferences
              if (initialBlockingEnabled) {
                blockAllScripts();
                showBanner(consentBanner); // Show GDPR banner if blocking is enabled
              } else {
                unblockScripts();
                hideBanner(consentBanner); // Hide GDPR banner if blocking is disabled
              }
            }
          } catch (error) {
            console.error("Error loading consent state:", error);
            initialBlockingEnabled = true;
            showBanner(consentBanner); // Show GDPR banner if there's an error
          }
        } else {
          // No consent given, show GDPR banner and enable blocking
          initialBlockingEnabled = true;
          showBanner(consentBanner);
          blockAllScripts();
        }
      }
  
  
    // Move createPlaceholder function outside of scanAndBlockScripts
    function createPlaceholder(script, category) {
      console.log("INSIDE CREATE PLACEHOLDER AND CATEGORY IS :",category)
        const placeholder = document.createElement('script');
        placeholder.type = 'text/placeholder';
        placeholder.dataset.src = script.src;
        placeholder.dataset.async = script.async || false;
        placeholder.dataset.defer = script.defer || false;
        placeholder.dataset.type = script.type || 'text/javascript';
        placeholder.dataset.crossorigin = script.crossOrigin || '';
    
        if (category) {
            placeholder.dataset.category = category; // Store the script category
        }
    
        return placeholder;
    }
    
    function scanAndBlockScripts() {
        const scripts = document.querySelectorAll("script[src]");
        const inlineScripts = document.querySelectorAll("script:not([src])");
      
        console.log("INSIDE SCAN AND BLOCK")
        // Handle external scripts
        scripts.forEach(script => {
            if (isSuspiciousResource(script.src)) {
              console.log("SCAN AND BLOCK:Blocking script:", script.src);
              const placeholder = createPlaceholder(script,category="all");
              if (placeholder) {
                        script.parentNode.replaceChild(placeholder, script);
                         blockedScripts.push(placeholder);
                      } else {
                      console.error('Failed to create placeholder for script:', script.src);
                    }
                }
        });



  
    // Handle inline scripts
    inlineScripts.forEach(script => {
        const content = script.textContent;
        if (content.match(/gtag|ga|fbq|twq|pintrk|snaptr|_qevents|dataLayer|plausible/)) {
            
            script.remove();
        } else {
           
        }
    });
  }
  
  function isSuspiciousResource(url) {
    const suspiciousPatterns = /gtag|analytics|zoho|matomo|plausible|track|collect|googletagmanager|googleanalytics|metrics|pageview|stat|trackpageview|pixel|doubleclick|adservice|adwords|adsense|connect\.facebook\.net|fbevents\.js|facebook|meta|graph\.facebook\.com|business\.facebook\.com|pixel|quantserve|scorecardresearch|clarity\.ms|hotjar|mouseflow|fullstory|logrocket|mixpanel|segment|amplitude|heap|kissmetrics|matomo|piwik|woopra|crazyegg|clicktale|optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat|olark|purechat|snapengage|liveperson|boldchat|clickdesk|userlike|zopim|crisp|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|moat|integral-marketing|comscore|nielsen|quantcast|adobe|marketo|hubspot|salesforce|pardot|eloqua|act-on|mailchimp|constantcontact|sendgrid|klaviyo|braze|iterable|appsflyer|adjust|branch|kochava|singular|tune|attribution|chartbeat|parse\.ly|newrelic|datadog|sentry|rollbar|bugsnag|raygun|loggly|splunk|elastic|dynatrace|appoptics|pingdom|uptimerobot|statuscake|newrelic|datadoghq|sentry\.io|rollbar\.com|bugsnag\.com|raygun\.io|loggly\.com|splunk\.com|elastic\.co|dynatrace\.com|appoptics\.com|pingdom\.com|uptimerobot\.com|statuscake\.com|clarity|clickagy|yandex|baidu/;
    const isSuspicious = suspiciousPatterns.test(url);
     if (isSuspicious) {
     console.log("Suspicious script detected:", url);
     }
     return isSuspicious;
  }
  
  async function blockAnalyticsScripts() {
    console.log("INSIDE BLOCK ANALYTICS SCRIPT");
  
    const analyticsPatterns = /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview/i;
    const categoryOfPreference = "Analytics";
  const categorizedScripts = await loadCategorizedScripts();
    const scripts = document.querySelectorAll('script');
  
    scripts.forEach(script => {
      const src = script.src || null;
      const content = script.innerText || script.textContent;
  
      const matchingEntry = categorizedScripts.find(entry => {
        const srcMatch = entry.src && src && entry.src === src;
        const contentMatch = !entry.src &&
          entry.content &&
          content &&
          content.replace(/\s/g, '').includes(entry.content.replace(/\s/g, ''));
        return srcMatch || contentMatch;
      });
  
      const isCategorizedAnalytics =
        matchingEntry &&
        matchingEntry.selectedCategories.includes(categoryOfPreference) &&
        !(src && analyticsPatterns.test(src));
  
      const isDefaultAnalyticsScript =
        !matchingEntry &&
        ((src && analyticsPatterns.test(src)) || (content && analyticsPatterns.test(content)));
  
      if (isCategorizedAnalytics || isDefaultAnalyticsScript) {
        console.log("Blocking Analytics Script:", src || "[inline]");
        const placeholder = createPlaceholder(script, categoryOfPreference);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  
  async function hardenScriptBlocking() {
    try {
      window.__BLOCK_ALL_SCRIPTS__ = true;
  
      const blockedScriptTypes = new Set(["text/javascript", "application/javascript", "module"]);
  
      const originalCreateElement = document.createElement;
      const originalAppendChild = Node.prototype.appendChild;
      const originalInsertBefore = Node.prototype.insertBefore;
  
      // Override createElement to trap <script>
      document.createElement = function(tagName, ...args) {
        const element = originalCreateElement.call(this, tagName, ...args);
  
        if (tagName.toLowerCase() === "script") {
          setTimeout(() => {
            element.type = "blocked/javascript";
          }, 0);
  
          Object.defineProperty(element, 'src', {
            set(value) {
              element.setAttribute("data-blocked-src", value);
            },
            get() {
              return element.getAttribute("data-blocked-src");
            }
          });
        }
  
        return element;
      };
  
      // Block appendChild of <script>
      Node.prototype.appendChild = function(child, ...args) {
        if (child?.tagName === "SCRIPT") {
          console.warn("[BLOCKED SCRIPT: appendChild]", child.src || "[inline]");
          return child;
        }
        return originalAppendChild.call(this, child, ...args);
      };
  
      // Block insertBefore of <script>
      Node.prototype.insertBefore = function(newNode, referenceNode, ...args) {
        if (newNode?.tagName === "SCRIPT") {
          console.warn("[BLOCKED SCRIPT: insertBefore]", newNode.src || "[inline]");
          return newNode;
        }
        return originalInsertBefore.call(this, newNode, referenceNode, ...args);
      };
  
      // MutationObserver: catch dynamic script tags
      const observer = new MutationObserver(mutations => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === 1 && node.tagName === "SCRIPT") {
              node.type = "blocked/javascript";
              node.remove();
              console.warn("[BLOCKED SCRIPT: MutationObserver]", node.src || "[inline]");
            }
          }
        }
      });
  
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
  
      // Remove any existing scripts
      const initialScripts = document.querySelectorAll("script");
      initialScripts.forEach(script => {
        const type = script.type || "text/javascript";
        if (blockedScriptTypes.has(type)) {
          script.type = "blocked/javascript";
          script.remove();
          console.warn("[BLOCKED SCRIPT: Initial]", script.src || "[inline]");
        }
      });
  
    } catch (err) {
      console.error("Error hardening script blocking:", err);
    }
  }
  async function blockMarketingScripts() {
    const marketingPatterns = /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough/i;
    const categoryOfPreference = "Marketing";
    const scripts = document.querySelectorAll('script');
    const categorizedScripts = await loadCategorizedScripts();

    scripts.forEach(script => {
      const src = script.src || null;
      const content = script.innerText || script.textContent;
  
      const matchingEntry = categorizedScripts.find(entry => {
        const entrySrcMatch = entry.src && src && entry.src === src;
        const entryContentMatch = !entry.src &&
          entry.content &&
          content &&
          content.replace(/\s/g, '').includes(entry.content.replace(/\s/g, ''));
        return entrySrcMatch || entryContentMatch;
      });
  
      const isCategorizedMarketing =
        matchingEntry &&
        matchingEntry.selectedCategories.includes(categoryOfPreference) &&
        !(src && marketingPatterns.test(src));
  
      const isDefaultMarketingScript =
        !matchingEntry &&
        ((src && marketingPatterns.test(src)) || (content && marketingPatterns.test(content)));
  
      if (isCategorizedMarketing || isDefaultMarketingScript) {
        const placeholder = createPlaceholder(script, categoryOfPreference);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  
  async function blockPersonalizationScripts() {
    console.log("INSIDE BLOCK PERSONALIZATION SCRIPT");
  
    const personalizationPatterns = /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i;
    const categoryOfPreference = "Personalization";
    const categorizedScripts = await loadCategorizedScripts();
  
    const scripts = document.querySelectorAll('script');
  
    scripts.forEach(script => {
      const src = script.src || null;
      const content = script.innerText || script.textContent;
  
      const matchingEntry = categorizedScripts.find(entry => {
        const srcMatch = entry.src && src && entry.src === src;
        const contentMatch = !entry.src &&
          entry.content &&
          content &&
          content.replace(/\s/g, '').includes(entry.content.replace(/\s/g, ''));
        return srcMatch || contentMatch;
      });
  
      const isCategorizedPersonalization =
        matchingEntry &&
        matchingEntry.selectedCategories.includes(categoryOfPreference) &&
        !(src && personalizationPatterns.test(src));
  
      const isDefaultPersonalizationScript =
        !matchingEntry &&
        ((src && personalizationPatterns.test(src)) || (content && personalizationPatterns.test(content)));
  
      if (isCategorizedPersonalization || isDefaultPersonalizationScript) {
        console.log("Blocking Personalization Script:", src || "[inline]");
        const placeholder = createPlaceholder(script, categoryOfPreference);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  
async function unblockScripts(categoryOfPreference = "all") {
  console.log(`Starting unblockScripts with categoryOfPreference:`, categoryOfPreference);
  console.log(`Total blocked scripts: ${blockedScripts.length}`);

  const scriptsToProcess = [...blockedScripts];

  console.log("Script to process",scriptsToProcess)

  scriptsToProcess.forEach((placeholder, index) => {
    const category = placeholder.dataset.category;
    const src = placeholder.dataset.src;

    const shouldUnblock =
      categoryOfPreference === "all" ||
      (typeof categoryOfPreference === "object" && categoryOfPreference[category]);

    console.log(`Checking script ${index}:`, { category, src, shouldUnblock });

    if (shouldUnblock && src) {
      console.log(`Unblocking script: ${src}`);

      const script = document.createElement("script");
      script.src = src;
      script.async = placeholder.dataset.async === "true";
      script.defer = placeholder.dataset.defer === "true";
      script.type = placeholder.dataset.type;

      if (placeholder.dataset.crossorigin) {
        script.crossOrigin = placeholder.dataset.crossorigin;
      }

      script.onload = () => {
        console.log(`Successfully loaded script: ${script.src}`);
        if (script.src.includes("fbevents.js")) {
          console.log("Reinitializing Facebook Pixel");
          initializeFbq();
        }
      };

      script.onerror = (error) => {
        console.error(`Error loading script ${script.src}:`, error);
      };

      try {
        placeholder.parentNode.replaceChild(script, placeholder);
        console.log(`Replaced placeholder with script: ${src}`);
        const originalIndex = blockedScripts.indexOf(placeholder);
        if (originalIndex !== -1) {
          blockedScripts.splice(originalIndex, 1);
        }
      } catch (error) {
        console.error("Error replacing script:", error);
      }
    }
  });

  console.log(`Remaining blocked scripts: ${blockedScripts.length}`);

  if (blockedScripts.length === 0) {
    console.log("No more blocked scripts, cleaning up observers");
    if (observer) observer.disconnect();
    if (headObserver) headObserver.disconnect();
  }

  if (
    (categoryOfPreference === "all" ||
      (typeof categoryOfPreference === "object" && categoryOfPreference.marketing)) &&
    window.fbqBlocked
  ) {
    console.log("Restoring Facebook Pixel functionality");
    delete window.fbqBlocked;
    loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
  }
}
  // Add this new function to restore original functions
  function restoreOriginalFunctions() {
      if (window.originalFetch) window.fetch = window.originalFetch;
      if (window.originalXHR) window.XMLHttpRequest = window.originalXHR;
      if (window.originalImage) window.Image = window.originalImage;
      
      if (window.fbqBlocked) {
          delete window.fbqBlocked;
          loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
      }
  }
  
function blockAnalyticsRequests() {
    // Fetch Blocking (Improved)
    const originalFetch = window.fetch;
    window.fetch = function (...args) {
        const url = args[0];
        if (typeof url === "string" && !consentState.analytics && isSuspiciousResource(url)) {
            
            return Promise.resolve(new Response(null, { status: 204, statusText: 'No Content' })); // More robust empty response
        }
        return originalFetch.apply(this, args);
    };
  
   
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      
      xhr.open = function(method, url) {
        if (typeof url === "string" && !consentState.analytics && isSuspiciousResource(url)) {
          
          return;
        }
        return originalOpen.apply(xhr, arguments); // Use xhr instead of this
      };
      return xhr;
    };
  } 
  
  function blockMetaFunctions() {
    if (!consentState.analytics) {
      if (!window.fbqBlocked) {
        window.fbqBlocked = window.fbq || function () {
          
          window.fbq.queue.push(arguments);
        };
        window.fbqBlocked.queue = [];
        window.fbq = window.fbqBlocked;
        
      }
    } else {
      if (window.fbq === window.fbqBlocked) {
        delete window.fbqBlocked;
        delete window.fbq;
        
        // Direct load without delay
        loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
        
      }
    }
  }
  function initializeFbq() {
    if (window.fbq && window.fbq.queue) {
      window.fbq.queue.forEach(args => window.fbq.apply(null, args));
    }
    
  }
  let initialBlockingEnabled = true;  // Flag to control initial blocking
  
  function blockAllInitialRequests() {
  const originalFetch = window.fetch;
  window.fetch = function (...args) {
      const url = args[0];
      if (initialBlockingEnabled && isSuspiciousResource(url)) {
          
          return Promise.resolve(new Response(null, { status: 204 }));
      }
      return originalFetch.apply(this, args);
  };
  
  const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      
      xhr.open = function(method, url) {
        if (initialBlockingEnabled && isSuspiciousResource(url)) {
          
          return;
        }
        return originalOpen.apply(xhr, arguments);
      };
      return xhr;
    };
  
  const originalImage = window.Image;
  const originalSetAttribute = Element.prototype.setAttribute;
  window.Image = function(...args) {
      const img = new originalImage(...args);
      img.setAttribute = function(name, value) {
          if (name === 'src' && initialBlockingEnabled && isSuspiciousResource(value)) {
              
              return;
          }
          return originalSetAttribute.apply(this, arguments);
      };
      return img;
  };
  }   
  
  function getClientIdentifier() {
  return window.location.hostname; // Use hostname as the unique client identifier
  }
  
    async function generateKey() {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const exportedKey = await crypto.subtle.exportKey("raw", key);
      return { secretKey: exportedKey, iv };
    } 
  
    // Add these two functions here
  async function importKey(rawKey) {
      return await crypto.subtle.importKey(
          "raw",
          rawKey,
          { name: "AES-GCM" },
          false,
          ["decrypt"]
      );
  }
  
  async function decryptData(encrypted, key, iv) {
      const encryptedBuffer = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
      const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          encryptedBuffer
      );
      return new TextDecoder().decode(decrypted);
  }
  
    async function encryptData(data, key, iv) {
      const encoder = new TextEncoder();
      const encodedData = encoder.encode(data);
      const importedKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        importedKey,
        encodedData
      );
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }
  
 
  async function saveConsentState(preferences, country) {
    console.log("inside saveConsentstate function");
    
   
    const clientId = getClientIdentifier();
    const visitorId = localStorage.getItem("visitorId");
    console.log("Visitor id in saveConsentState",visitorId)
    const policyVersion = "1.2";
    const timestamp = new Date().toISOString();
  
    const consentPreferences = buildConsentPreferences(preferences, country, timestamp);
    console.log("called function generateKey ");

  
    const encryptionKey = await generateKey();
    const encryptedVisitorId = await encryptData(visitorId, encryptionKey.secretKey, encryptionKey.iv);
    const encryptedPreferences = await encryptData(JSON.stringify(consentPreferences), encryptionKey.secretKey, encryptionKey.iv);
    console.log("called function storeEncryptedConsent ");
  
    storeEncryptedConsent(encryptedPreferences, encryptionKey, timestamp);
  
    const sessionToken = localStorage.getItem('visitorSessionToken');
    if (!sessionToken) {
      console.error("Failed to retrieve authentication token.");
      return;
    }
    console.log("called function buildPayload ");

  
    const payload = buildPayload({
      clientId,
      encryptedVisitorId,
      encryptedPreferences,
      encryptionKey,
      policyVersion,
      timestamp,
      country
    });
    console.log("called https://cb-server.web-8fb.workers.dev/api/cmp/consent ");
  
    try {
      const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(payload),
      });
  
      const text = await response.text();
      console.log("Consent section response:", text);
    } catch (error) {
      console.error("Error sending consent data:", error);
    }
  }  
  // ---------------- Helper Functions ----------------
  
  function buildConsentPreferences(preferences, country, timestamp) {
    return {
      necessary: true,
      marketing: preferences.marketing || false,
      personalization: preferences.personalization || false,
      analytics: preferences.analytics || false,
      doNotShare: preferences.doNotShare || false,
      country,
      timestamp,      
      cookies: cookieData,
      gdpr: {
        necessary: true,
        marketing: preferences.marketing || false,
        personalization: preferences.personalization || false,
        analytics: preferences.analytics || false,
        lastUpdated: timestamp,
        country
      },
      ccpa: {
        necessary: true,
        doNotShare: preferences.doNotShare || false,
        lastUpdated: timestamp,
        country
      }
    };
  }
  
  function storeEncryptedConsent(encryptedPreferences, encryptionKey, timestamp) {
    localStorage.setItem("consent-given", "true");
    localStorage.setItem("consent-preferences", JSON.stringify({
      encryptedData: encryptedPreferences,
      iv: Array.from(encryptionKey.iv),
      key: Array.from(new Uint8Array(encryptionKey.secretKey))
    }));
    localStorage.setItem("consent-timestamp", timestamp);
    localStorage.setItem("consent-policy-version", "1.2");
  }
  
  function buildPayload({ clientId, encryptedVisitorId, encryptedPreferences, encryptionKey, policyVersion, timestamp, country }) {
    return {
      clientId,
      visitorId: {
        encryptedData: encryptedVisitorId,
        iv: Array.from(encryptionKey.iv),
        key: Array.from(new Uint8Array(encryptionKey.secretKey))
      },
      preferences: {
        encryptedData: encryptedPreferences,
        iv: Array.from(encryptionKey.iv),
        key: Array.from(new Uint8Array(encryptionKey.secretKey))
      },
      metadata: {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      policyVersion,
      timestamp,
      cookies: cookieData,
      country,
      bannerType: currentBannerType
    };
  }
  
  const headObserver = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          
            if (node.tagName === 'SCRIPT' && isSuspiciousResource(node.src)) {
                
                node.remove(); // Remove the script before it runs
            }
        });
    });
  });
  
  headObserver.observe(document.head, { childList: true, subtree: true });
  
  function blockDynamicScripts() {
    if (observer) observer.disconnect(); // Disconnect previous observer if it exists
    observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.tagName === "SCRIPT" && isSuspiciousResource(node.src)) {
                    console.log("Blocking dynamically added script:", node.src); // Log blocked script
                    node.remove();
                }
                if (node.tagName === "IFRAME" && isSuspiciousResource(node.src)) {
                    //console.log("Blocking dynamically added iframe:", node.src); // Log blocked iframe
                    node.remove();
                }
                // Block dynamically added images (for tracking pixels)
                if (node.tagName === "IMG" && isSuspiciousResource(node.src)) {
                    //console.log("Blocking dynamically added image:", node.src); // Log blocked image
                    node.remove();
                }
            });
        });
    });
  
    observer.observe(document.body, { childList: true, subtree: true });
  }
  
   function createPlaceholderScripts() {
      const allScripts = document.querySelectorAll('script');
      allScripts.forEach(script => {
          if (isSuspiciousResource(script.src)) {
              const placeholder = document.createElement('script');
              placeholder.type = 'text/placeholder'; // Mark as placeholder
              placeholder.dataset.src = script.src; // Store original source
              placeholder.dataset.async = script.async; // Store original async
              script.parentNode.replaceChild(placeholder, script); // Replace with placeholder
              blockedScripts.push(placeholder);
              
          }
      });
  }
  
  function revalidateBlockedScripts() {
    if (!consentState.analytics) {
      loadConsentStyles();        
        scanAndBlockScripts();
        blockDynamicScripts();
    }
  }
  
  async function updateConsentState(preferences) {
    
    consentState = preferences;
    initialBlockingEnabled = !preferences.analytics;  
  
    if (preferences.doNotShare) {
      blockAllScripts(); // Just block everything
    } else {
      await unblockScripts(preferences); // Let the updated unblockScripts handle categories
    }
  
    await saveConsentState(preferences, country); 
 
    
    await saveConsentState(preferences, country);
  }
  function loadConsentStyles() {
    try {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css";
        link.type = "text/css";
        const link2 = document.createElement("link");
        link2.rel = "stylesheet";
        link2.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css";
        document.head.appendChild(link2);

        
        // Add error handling
        link.onerror = function() {
            console.error('Failed to load consent styles');
        };
        
        // Add load confirmation
        link.onload = function() {
            console.log('Consent styles loaded successfully');
        };
        
        document.head.appendChild(link);
    } catch (error) {
        console.error('Error loading consent styles:', error);
    }
}
  function loadScript(src, callback) {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.onload = callback;
    document.head.appendChild(script);
    
  }
  
  function initializeBanner() {
    
    
    // Wait for DOM to be fully loaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachBannerHandlers);
    } else {
        attachBannerHandlers();
    }
  }  
  
  function showBanner(banner) {
    if (banner) {
      banner.style.display = "block";
      banner.classList.add("show-banner");
      banner.classList.remove("hidden");
    }
  }
  
  function hideBanner(banner) {
    if (banner) {
      banner.style.display = "none";
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }
  
  function attachBannerHandlers() {
    const consentBanner = document.getElementById("consent-banner");
    const ccpaBanner = document.getElementById("initial-consent-banner");
    const mainBanner = document.getElementById("main-banner");
    const mainConsentBanner = document.getElementById("main-consent-banner");
    const simpleBanner = document.getElementById("simple-consent-banner");
    const simpleAcceptButton = document.getElementById("simple-accept");
    const simpleRejectButton = document.getElementById("simple-reject");
  
    // Button elements
    const toggleConsentButton = document.getElementById("toggle-consent-btn");
    const newToggleConsentButton = document.getElementById("new-toggle-consent-btn");
    const acceptButton = document.getElementById("accept-btn");
    const declineButton = document.getElementById("decline-btn");
    const preferencesButton = document.getElementById("preferences-btn");
    const savePreferencesButton = document.getElementById("save-preferences-btn");
    const saveCCPAPreferencesButton = document.getElementById("save-btn");
    const cancelButton = document.getElementById("cancel-btn");
    const closeConsentButton = document.getElementById("close-consent-banner");
    const doNotShareLink = document.getElementById("do-not-share-link");
    doNotShareLink? "true":"false";
  
    // Checkbox elements
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]')
    const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]')
    const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]')
    const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]')
    const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
      
    // Initialize banner visibility based on user location
    initializeBannerVisibility();
  
    if (simpleBanner) {
      console.log('Simple banner found, initializing handlers'); // Debug log
      showBanner(simpleBanner);
  
      if (simpleAcceptButton) {
        simpleAcceptButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Accept button clicked');
          const preferences = {
            necessary: true,
            marketing: true,
            personalization: true,
            analytics: true,
            doNotShare: false
          };
          
            await updateConsentState(preferences);
            unblockScripts();
            hideBanner(simpleBanner);
            localStorage.setItem("consent-given", "true");
          
          });
        }
      
  
      if (simpleRejectButton) {
        simpleRejectButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Reject button clicked');
          const preferences = {
            necessary: true,
            marketing: false,
            personalization: false,
            analytics: false,
            doNotShare: true
          };
          await updateConsentState(preferences);
          blockAllScripts();
          hideBanner(simpleBanner);
          localStorage.setItem("consent-given", "true");
        });
      }
    }
    
  
    if (toggleConsentButton) {
      toggleConsentButton.addEventListener("click", async function(e) {
          e.preventDefault();
  
          
          const consentBanner = document.getElementById("consent-banner");
          const ccpaBanner = document.getElementById("initial-consent-banner");
          const simpleBanner = document.getElementById("simple-consent-banner");
          //console.log('Location Data:', window.currentLocation); // Log the location data for debugging
          //console.log('Banner Type:', window.currentBannerType);
  
          // Show the appropriate banner based on bannerType
          if (currentBannerType === 'GDPR') {
              showBanner(consentBanner); // Show GDPR banner
              hideBanner(ccpaBanner); // Hide CCPA banner
          } else if (currentBannerType === 'CCPA') {
              showBanner(ccpaBanner); // Show CCPA banner
              hideBanner(consentBanner); // Hide GDPR banner
          } else {
              showBanner(consentBanner); // Default to showing GDPR banner
              hideBanner(ccpaBanner);
          }
      });
  }
  
  if (newToggleConsentButton) {
    newToggleConsentButton.addEventListener("click", async function(e) {
      e.preventDefault();
      //console.log('New Toggle Button Clicked'); // Log for debugging
  
      const consentBanner = document.getElementById("consent-banner");
      const ccpaBanner = document.getElementById("initial-consent-banner");
  
      // Show the appropriate banner based on bannerType
      if (currentBannerType === 'GDPR') {
        showBanner(consentBanner); // Show GDPR banner
        hideBanner(ccpaBanner); // Hide CCPA banner
      } else if (currentBannerType === 'CCPA') {
        showBanner(ccpaBanner); // Show CCPA banner
        hideBanner(consentBanner); // Hide GDPR banner
      } else {
        showBanner(consentBanner); // Default to showing GDPR banner
        hideBanner(ccpaBanner);
      }
    });
  }
  
    if (doNotShareLink) {
      
      doNotShareLink.addEventListener("click", function(e) {
        
        e.preventDefault();
        hideBanner(ccpaBanner); // Hide CCPA banner if it's open
        showBanner(mainConsentBanner); // Show main consent banner
      });
    }
  
  
    if (closeConsentButton) {
      closeConsentButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(document.getElementById("main-consent-banner")); // Hide the main consent banner
      });
    }
    // Accept button handler
    if (acceptButton) {
      acceptButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          necessary: true,
          marketing: true,
          personalization: true,
          analytics: true
        };
        await updateConsentState(preferences);
        await unblockScripts(preferences);
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    // Decline button handler
    if (declineButton) {
      declineButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          necessary: true,
          marketing: false,
          personalization: false,
          analytics: false
        };
        await updateConsentState(preferences);
        blockAllScripts();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    // Preferences button handler
    if (preferencesButton) {
      preferencesButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(consentBanner);
        showBanner(mainBanner);
      });
    }
  
    if (savePreferencesButton) {
      savePreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          necessary: true, // Always true
          marketing: marketingCheckbox?.checked || false,
          personalization: personalizationCheckbox?.checked || false,
          analytics: analyticsCheckbox?.checked || false
          
        };
        await updateConsentState(preferences);
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    if (saveCCPAPreferencesButton) {
      saveCCPAPreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const doNotShare = doNotShareCheckbox.checked;
        const preferences = {
          necessary: true, // Always true
          doNotShare: doNotShare // Set doNotShare based on checkbox
        };
        await updateConsentState(preferences);
        
        // Block or unblock scripts based on the checkbox state
        if (doNotShare) {
          blockAllScripts(); // Block all scripts if checkbox is checked
        } else {
          unblockScripts(); // Unblock scripts if checkbox is unchecked
        }
    
        hideBanner(ccpaBanner);
        hideBanner(mainConsentBanner);
      });
    }
  
    // Cancel button handler
    if (cancelButton) {
      cancelButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
    
  }
  








  // Window attachments

  window.loadConsentState = loadConsentState;
  window.blockMetaFunctions = blockMetaFunctions;
  window.blockAllInitialRequests = blockAllInitialRequests;
  window.blockAnalyticsRequests = blockAnalyticsRequests;
  window.scanAndBlockScripts = scanAndBlockScripts;
  window.blockDynamicScripts = blockDynamicScripts;
  window.updateConsentState = updateConsentState;
  window.initializeBanner= initializeBanner;
  window.initializeBlocking = initializeBlocking;
  window.attachBannerHandlers = attachBannerHandlers;
  window.initializeAll = initializeAll;
  window.showBanner = showBanner;
  window.hideBanner = hideBanner;
  window.importKey = importKey;         
  window.decryptData = decryptData;   
  window.unblockScripts = unblockScripts;
  window.createPlaceholderScripts = createPlaceholderScripts;
  window.restoreOriginalFunctions = restoreOriginalFunctions;
  window.loadCategorizedScripts =loadCategorizedScripts;
  window.detectLocationAndGetBannerType = detectLocationAndGetBannerType;
  window.getVisitorSessionToken = getVisitorSessionToken;
  window.isTokenExpired = isTokenExpired;
    window.cleanHostname = cleanHostname;
    window.getOrCreateVisitorId = getOrCreateVisitorId;
    window.buildConsentPreferences= buildConsentPreferences;
    window.storeEncryptedConsent=storeEncryptedConsent;
    window.buildPayload = buildPayload;
    
  window.loadConsentStyles = loadConsentStyles;
  window.hardenScriptBlocking= hardenScriptBlocking;
  
  function initializeAll() {
    if (isInitialized) {
      
      return;
    }
    
    
    // Block everything first
    blockAllInitialRequests();
    blockAllScripts();
    
    // Then load state and initialize banner
    loadConsentState().then(() => {
      initializeBanner();
      
      isInitialized = true;
    });
   }
      
      // Set up periodic script checking
      setInterval(revalidateBlockedScripts, 5000);
  })();
  


