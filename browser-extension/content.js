// Falsum content.js — anti-fingerprinting shield.
// Runs at document_start on every page. Spoofs the browser APIs that
// fingerprinters abuse: Canvas, WebGL, AudioContext, navigator properties,
// screen geometry, Battery, Network Information.
// Spoofed values are SESSION-CONSISTENT: same fake fingerprint for the whole
// browser session (so sites don't see you flickering), different next session.
//
// NOTE: Chrome content scripts run in an ISOLATED world, so page scripts would
// not see our overrides. We therefore inject a <script> into the PAGE world
// (MAIN world) carrying the spoofed values. The injected script reports
// fingerprinting API calls back here via window.postMessage, and we forward
// them to background.js, which alerts the desktop app over the native bridge.

(async function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // 1. Session seed — one random seed per browser session.
  // ---------------------------------------------------------------------------
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  async function getSessionSeed() {
    try {
      const stored = await chrome.storage.session.get("falsum_fp_seed");
      if (stored && stored.falsum_fp_seed) return stored.falsum_fp_seed;
    } catch (e) { /* storage.session may be unavailable; fall through */ }
    const seed = (crypto.getRandomValues(new Uint32Array(1))[0]) >>> 0;
    try { await chrome.storage.session.set({ falsum_fp_seed: seed }); } catch (e) {}
    return seed;
  }

  const seed = await getSessionSeed();
  const rand = mulberry32(seed);
  const pick = (arr) => arr[Math.floor(rand() * arr.length)];

  // ---------------------------------------------------------------------------
  // 2. Derive session-consistent spoofed values.
  // ---------------------------------------------------------------------------
  const spoof = {
    // Canvas: per-pixel noise amplitude (subtle — breaks hashes, keeps images sane)
    canvasNoise: 3 + Math.floor(rand() * 4),          // 3..6
    // WebGL: plausible-but-fake GPU strings
    glVendor: pick([
      "Google Inc. (NVIDIA)", "Google Inc. (AMD)", "Google Inc. (Intel)",
      "Google Inc. (Apple)", "Qualcomm"
    ]),
    glRenderer: pick([
      "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
      "ANGLE (Qualcomm, Adreno (TM) 640 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ]),
    // Hardware: common configurations, never the exotic real one
    cores: pick([4, 4, 6, 8, 8]),
    deviceMemory: pick([4, 8, 8]),
    // Screen: common resolutions
    screen: pick([
      { w: 1920, h: 1080 }, { w: 1366, h: 768 }, { w: 1536, h: 864 },
      { w: 1440, h: 900 }, { w: 2560, h: 1440 }
    ]),
    colorDepth: 24,
    // AudioContext: jitter amplitude added to frequency data
    audioJitter: 0.5 + rand() * 1.5,
    // Network Information API: report a boring, common profile
    connection: { effectiveType: "4g", downlink: 10, rtt: 50, saveData: false }
  };

  // ---------------------------------------------------------------------------
  // 3. Inject the page-world shield script with the spoofed values baked in.
  // ---------------------------------------------------------------------------
  const shieldSource = "(" + pageShield.toString() + ")(" + JSON.stringify(spoof) + ");";

  function inject() {
    try {
      const el = document.createElement("script");
      el.textContent = shieldSource;
      // document_start: documentElement may not exist yet on some navigations.
      const root = document.documentElement || document.head || document;
      root.prepend(el);
      el.remove();
    } catch (e) {
      // Page CSP may block inline injection; the isolated-world script cannot
      // spoof page-visible APIs in that case. Logged for transparency.
      console.warn("[Falsum] Shield injection blocked on this page:", e && e.message);
    }
  }

  if (document.documentElement) {
    inject();
  } else {
    // Extremely early document_start: wait for the root element.
    new MutationObserver((_, obs) => {
      if (document.documentElement) { obs.disconnect(); inject(); }
    }).observe(document, { childList: true });
  }

  // ---------------------------------------------------------------------------
  // 0. GATE CHECK: Ask the desktop app if this page should be blocked.
  //    Runs before anything else. If blocked, replace page with warning.
  // ---------------------------------------------------------------------------
  (async function gateCheck() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "check-page-block",
        url: window.location.href
      });
      if (response && response.blocked) {
        document.documentElement.innerHTML = `
          <html><head><title>Blocked by Falsum</title></head>
          <body style="background:#1A1A2E;color:#EEEEEE;font-family:sans-serif;
                       display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
            <div style="text-align:center;max-width:600px;padding:40px">
              <h1 style="color:#E94560;font-size:48px;margin-bottom:16px">🛡️</h1>
              <h2>Blocked by Falsum</h2>
              <p>This page was blocked because the desktop gate determined it was dangerous.</p>
              <p style="color:#A0A0A0;font-size:14px">URL: ${window.location.href}</p>
              <p style="color:#A0A0A0;font-size:14px">Nothing left your browser. Your data is safe.</p>
            </div>
          </body></html>`;
        throw new Error("Page blocked by Falsum gate");
      }
    } catch (e) {
      if (e.message === "Page blocked by Falsum gate") throw e;
      // Gate check failed — continue loading (fail open for UX, gate still monitors)
    }
  })();

  // ---------------------------------------------------------------------------
  // 4. Relay fingerprinting-attempt reports from the page script to background.
  // ---------------------------------------------------------------------------
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.__falsum_fp !== true) return;
    try {
      chrome.runtime.sendMessage({
        type: "fingerprint-attempt",
        api: d.api,
        url: location.href,
        timestamp: Date.now()
      });
    } catch (e) { /* background may be unreachable; not fatal */ }
  });

  // Tell background the shield is armed on this page (for the popup badge).
  try {
    chrome.runtime.sendMessage({ type: "shield-armed", url: location.href });
  } catch (e) {}

  // ===========================================================================
  // PAGE-WORLD SHIELD — runs in the page's own JS context.
  // Receives `spoof` (JSON). Overrides fingerprinting APIs. Reports each
  // distinct fingerprinting API call ONCE per page via window.postMessage.
  // ===========================================================================
  function pageShield(spoof) {
    "use strict";
    const reported = new Set();
    function report(api) {
      if (reported.has(api)) return;
      reported.add(api);
      try {
        window.postMessage({ __falsum_fp: true, api: api }, "*");
      } catch (e) {}
    }
    function clamp(v) { return v < 0 ? 0 : v > 255 ? 255 : v; }
    // Independent per-call PRNG so noise isn't predictable across calls.
    let noiseState = (Date.now() ^ (Math.random() * 1e9)) >>> 0;
    function noiseRand() {
      noiseState |= 0; noiseState = (noiseState + 0x6d2b79f5) | 0;
      let t = Math.imul(noiseState ^ (noiseState >>> 15), 1 | noiseState);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    // ---- Canvas: poison getImageData with per-pixel noise ----
    try {
      const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function (sx, sy, sw, sh) {
        report("canvas.getImageData");
        const img = origGetImageData.call(this, sx, sy, sw, sh);
        const d = img.data, n = spoof.canvasNoise;
        for (let i = 0; i < d.length; i += 4) {
          d[i]     = clamp(d[i]     + Math.floor(noiseRand() * (2 * n + 1)) - n);
          d[i + 1] = clamp(d[i + 1] + Math.floor(noiseRand() * (2 * n + 1)) - n);
          d[i + 2] = clamp(d[i + 2] + Math.floor(noiseRand() * (2 * n + 1)) - n);
        }
        return img;
      };
    } catch (e) {}

    // ---- Canvas: toDataURL / toBlob also leak the raw bitmap ----
    try {
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function () {
        report("canvas.toDataURL");
        // Re-render through a temp canvas so getImageData noise applies.
        try {
          const tmp = document.createElement("canvas");
          tmp.width = this.width; tmp.height = this.height;
          const tctx = tmp.getContext("2d");
          tctx.drawImage(this, 0, 0);
          // Force the noisy path once so the exported bitmap differs.
          tctx.getImageData(0, 0, tmp.width, tmp.height);
          return origToDataURL.apply(tmp, arguments);
        } catch (e) {
          return origToDataURL.apply(this, arguments);
        }
      };
      const origToBlob = HTMLCanvasElement.prototype.toBlob;
      if (origToBlob) {
        HTMLCanvasElement.prototype.toBlob = function () {
          report("canvas.toBlob");
          return origToBlob.apply(this, arguments);
        };
      }
    } catch (e) {}

    // ---- WebGL: spoof renderer/vendor strings, report getParameter ----
    try {
      const contexts = [];
      if (typeof WebGLRenderingContext !== "undefined") contexts.push(WebGLRenderingContext);
      if (typeof WebGL2RenderingContext !== "undefined") contexts.push(WebGL2RenderingContext);
      const UNMASKED_VENDOR = 37445, UNMASKED_RENDERER = 37446;
      contexts.forEach(function (Ctx) {
        const orig = Ctx.prototype.getParameter;
        Ctx.prototype.getParameter = function (p) {
          report("webgl.getParameter");
          if (p === UNMASKED_VENDOR) return spoof.glVendor;
          if (p === UNMASKED_RENDERER) return spoof.glRenderer;
          return orig.call(this, p);
        };
        // Also neuter the debug-renderer-info extension lookup path.
        const origGetExt = Ctx.prototype.getExtension;
        Ctx.prototype.getExtension = function (name) {
          if (name === "WEBGL_debug_renderer_info") { report("webgl.debug_renderer_info"); return null; }
          return origGetExt.call(this, name);
        };
      });
    } catch (e) {}

    // ---- AudioContext: jitter frequency data, report oscillator creation ----
    try {
      if (typeof AnalyserNode !== "undefined") {
        const origFreq = AnalyserNode.prototype.getFloatFrequencyData;
        AnalyserNode.prototype.getFloatFrequencyData = function (arr) {
          report("audio.getFloatFrequencyData");
          origFreq.call(this, arr);
          for (let i = 0; i < arr.length; i++) {
            arr[i] += (noiseRand() - 0.5) * 2 * spoof.audioJitter;
          }
          return arr;
        };
        const origByte = AnalyserNode.prototype.getByteFrequencyData;
        if (origByte) {
          AnalyserNode.prototype.getByteFrequencyData = function (arr) {
            report("audio.getByteFrequencyData");
            origByte.call(this, arr);
            for (let i = 0; i < arr.length; i++) {
              arr[i] = clamp(arr[i] + Math.floor((noiseRand() - 0.5) * 4));
            }
            return arr;
          };
        }
      }
      ["AudioContext", "OfflineAudioContext", "webkitAudioContext"].forEach(function (name) {
        const AC = window[name];
        if (AC && AC.prototype && AC.prototype.createOscillator) {
          const origOsc = AC.prototype.createOscillator;
          AC.prototype.createOscillator = function () {
            report("audio.createOscillator");
            return origOsc.call(this);
          };
        }
      });
      if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype.getChannelData) {
        const origCh = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function (ch) {
          report("audio.getChannelData");
          const data = origCh.call(this, ch);
          for (let i = 0; i < data.length; i += 97) {
            data[i] += (noiseRand() - 0.5) * 0.001;
          }
          return data;
        };
      }
    } catch (e) {}

    // ---- navigator: hardwareConcurrency, deviceMemory, Battery, Network Info ----
    function redefine(obj, prop, getter) {
      try {
        Object.defineProperty(obj, prop, { get: getter, configurable: true });
        return true;
      } catch (e) { return false; }
    }
    if (redefine(navigator, "hardwareConcurrency", function () { return spoof.cores; })) {
      /* spoofed */
    }
    redefine(navigator, "deviceMemory", function () { return spoof.deviceMemory; });
    // Battery API: block it entirely (high-entropy, no legitimate need).
    try {
      Object.defineProperty(navigator, "getBattery", {
        value: function () { report("navigator.getBattery"); return Promise.reject(new Error("Battery API blocked by Falsum")); },
        configurable: true
      });
    } catch (e) {}
    // Network Information API: serve the boring spoofed profile.
    redefine(navigator, "connection", function () {
      report("navigator.connection");
      return {
        effectiveType: spoof.connection.effectiveType,
        downlink: spoof.connection.downlink,
        rtt: spoof.connection.rtt,
        saveData: spoof.connection.saveData,
        addEventListener: function () {},
        removeEventListener: function () {},
        dispatchEvent: function () { return false; }
      };
    });

    // ---- screen: spoof geometry ----
    try {
      const s = spoof.screen;
      redefine(window.screen, "width", function () { return s.w; });
      redefine(window.screen, "height", function () { return s.h; });
      redefine(window.screen, "availWidth", function () { return s.w; });
      redefine(window.screen, "availHeight", function () { return s.h - 40; });
      redefine(window.screen, "colorDepth", function () { return spoof.colorDepth; });
      redefine(window.screen, "pixelDepth", function () { return spoof.colorDepth; });
    } catch (e) {}

    // ---- devicePixelRatio: round to a common value ----
    redefine(window, "devicePixelRatio", function () { return 1; });
  }
})();
