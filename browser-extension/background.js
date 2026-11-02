// Falsum Browser Bubble — background service worker
//
// THE BUBBLE: This extension is the inner eye. The Falsum desktop app is the outer gate.
// The browser runs INSIDE Falsum's bubble. Everything the browser does — every download,
// every navigation, every network request, every fingerprinting attempt — passes through
// this extension to the desktop app, which decides: ALLOW or BLOCK.
//
// The extension does not decide. It sees, it reports, it enforces what the app says.
// The app is the brain. This is the nervous system.

const NATIVE_HOST = "com.falsum.native";
let nativePort = null;
let desktopConnected = false;
let reconnectAttempts = 0;
let messageQueue = []; // Queue messages when desktop is disconnected

// ============================================================================
// NATIVE MESSAGING: the umbilical cord to the desktop app
// ============================================================================

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
    desktopConnected = true;
    reconnectAttempts = 0;
    console.log("[Falsum Bubble] Connected to desktop gate");

    // Flush queued messages
    while (messageQueue.length > 0) {
      const msg = messageQueue.shift();
      try { nativePort.postMessage(msg); } catch (e) { break; }
    }

    nativePort.onMessage.addListener(handleDesktopMessage);
    nativePort.onDisconnect.addListener(() => {
      desktopConnected = false;
      console.log("[Falsum Bubble] Desktop gate disconnected");
      const delay = Math.min(5000 * Math.pow(2, reconnectAttempts), 60000);
      reconnectAttempts++;
      setTimeout(connectNative, delay);
    });

    sendToDesktop({ type: "bubble-online", from: "browser-extension", version: "2.0.0", capabilities: [
      "downloads", "navigation", "requests", "fingerprinting", "cookies", "storage"
    ]});
  } catch (e) {
    console.error("[Falsum Bubble] Native connect failed:", e);
    desktopConnected = false;
    setTimeout(connectNative, 10000);
  }
}

function sendToDesktop(msg) {
  msg._ts = Date.now();
  if (!desktopConnected || !nativePort) {
    messageQueue.push(msg);
    if (messageQueue.length > 500) messageQueue.shift(); // Don't grow forever
    return false;
  }
  try {
    nativePort.postMessage(msg);
    return true;
  } catch (e) {
    messageQueue.push(msg);
    return false;
  }
}

// Pending gate decisions: requestId -> { resolve, timeout }
const pendingGates = new Map();
let gateIdCounter = 0;

/// <summary>
/// Ask the desktop gate: should this action be allowed?
/// Returns a Promise that resolves to true (allow) or false (block).
///
/// IRON RULE: Nothing passes without user consent.
/// If desktop is disconnected or times out → BLOCK, don't allow.
/// Fail closed. The user is notified. Nothing goes silently.
/// </summary>
function askGate(actionType, details, timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (!desktopConnected) {
      console.warn(`[Falsum Bubble] Gate offline, BLOCKING ${actionType} (user notified)`);
      sendToDesktop({ type: "gate-bypassed-block", action: actionType, details, reason: "desktop-offline" });
      resolve(false); // Fail closed — block when gate is down
      return;
    }

    const gateId = `gate-${++gateIdCounter}-${Date.now()}`;
    const timeout = setTimeout(() => {
      pendingGates.delete(gateId);
      console.warn(`[Falsum Bubble] Gate timeout for ${actionType}, BLOCKING (user notified)`);
      sendToDesktop({ type: "gate-timeout-block", action: actionType, gateId, details });
      resolve(false); // Fail closed on timeout
    }, timeoutMs);

    pendingGates.set(gateId, { resolve, timeout });
    sendToDesktop({ type: "gate-request", gateId, action: actionType, details });
  });
}

function handleDesktopMessage(msg) {
  switch (msg.type) {
    case "gate-decision": {
      const pending = pendingGates.get(msg.gateId);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingGates.delete(msg.gateId);
        pending.resolve(msg.allow === true);
      }
      break;
    }
    case "threat": {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
      chrome.storage.local.set({ lastDesktopThreat: msg });
      break;
    }
    case "block-url": {
      // Desktop says block this URL pattern going forward
      chrome.storage.local.get(["blockedPatterns"], (r) => {
        const patterns = r.blockedPatterns || [];
        patterns.push(msg.pattern);
        chrome.storage.local.set({ blockedPatterns: patterns.slice(-1000) });
      });
      break;
    }
    case "status":
      chrome.storage.local.set({ desktopStatus: msg });
      break;
  }
}

// ============================================================================
// DOWNLOADS: every file, inside and out
// ============================================================================

chrome.downloads.onCreated.addListener(async (item) => {
  const details = {
    filename: item.filename,
    url: item.url,
    referrer: item.referrer,
    mime: item.mime,
    fileSize: item.fileSize,
    danger: item.danger,
    tabId: item.tabId,
  };

  // Report to desktop
  sendToDesktop({ type: "download-created", ...details });

  // Ask gate for dangerous files
  const ext = (item.filename.split(".").pop() || "").toLowerCase();
  const dangerous = ["exe", "msi", "bat", "cmd", "ps1", "vbs", "js", "scr", "lnk", "jar", "com", "pif", "dll"];
  if (dangerous.includes(ext)) {
    const allow = await askGate("download", details);
    if (!allow) {
      chrome.downloads.cancel(item.id, () => {
        sendToDesktop({ type: "download-blocked", ...details, blockedBy: "desktop-gate" });
      });
    }
  }
});

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === "complete") {
    chrome.downloads.search({ id: delta.id }, (items) => {
      if (items.length > 0) {
        sendToDesktop({
          type: "download-complete",
          filename: items[0].filename,
          url: items[0].url,
          fileSize: items[0].fileSize,
          endTime: items[0].endTime,
        });
      }
    });
  }
});

// ============================================================================
// NAVIGATION: every page, every frame
// ============================================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const url = details.url.toLowerCase();

  // Check local blocklist first (fast path)
  const { blockedPatterns = [] } = await chrome.storage.local.get(["blockedPatterns"]);
  for (const pattern of blockedPatterns) {
    if (url.includes(pattern.toLowerCase())) {
      sendToDesktop({ type: "navigation-blocked-local", url: details.url, pattern });
      return; // Don't navigate — but can't cancel here, desktop handles via content script
    }
  }

  // Heuristic threat signals
  const signals = [];
  if (/xn--/.test(url)) signals.push("punycode-idn");
  if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url)) signals.push("ip-url");
  if ((url.match(/-/g) || []).length >= 4) signals.push("excessive-hyphens");
  if (url.length > 200) signals.push("overlong-url");
  if (/login|signin|verify|account|secure|bank/i.test(url) && !/^[a-z]+:\/\/(www\.)?[a-z0-9-]+\.(com|org|net|gov|edu)/.test(url)) {
    signals.push("suspicious-auth-page");
  }

  sendToDesktop({
    type: "navigation",
    url: details.url,
    tabId: details.tabId,
    frameId: details.frameId,
    signals: signals.length > 0 ? signals : undefined,
  });

  // Gate suspicious navigations
  if (signals.length > 0 && details.frameId === 0) {
    const allow = await askGate("navigation", { url: details.url, signals, tabId: details.tabId });
    if (!allow) {
      // Can't cancel onBeforeNavigate directly — tell content script to block
      sendToDesktop({ type: "navigation-gate-block", url: details.url, tabId: details.tabId });
    }
  }
});

// Track completed navigations for the timeline
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  sendToDesktop({
    type: "navigation-complete",
    url: details.url,
    tabId: details.tabId,
  });
});

// ============================================================================
// NETWORK REQUESTS: what the browser sends and where
// ============================================================================

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Report all requests to non-standard destinations
    const url = new URL(details.url);
    const isApi = /api|track|analytics|telemetry|metric|beacon|pixel/i.test(url.hostname + url.pathname);

    if (isApi || details.type === "xmlhttprequest") {
      sendToDesktop({
        type: "network-request",
        url: details.url,
        method: details.method,
        reqType: details.type,
        tabId: details.tabId,
        isApiCall: isApi,
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// Detect data exfiltration: large POST bodies to unknown domains
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (details.method === "POST" && details.requestBody) {
      const bodySize = details.requestBody.raw
        ? details.requestBody.raw.reduce((s, b) => s + b.bytes.byteLength, 0)
        : 0;
      if (bodySize > 102400) { // >100KB POST
        sendToDesktop({
          type: "large-upload",
          url: details.url,
          bodySize,
          tabId: details.tabId,
        });
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// ============================================================================
// FINGERPRINTING: content.js reports → desktop gate
// ============================================================================

const fpAttempts = {};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "fingerprint-attempt") {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (!fpAttempts[tabId]) fpAttempts[tabId] = {};
    fpAttempts[tabId][msg.api] = (fpAttempts[tabId][msg.api] || 0) + 1;

    chrome.action.setBadgeText({ text: "FP", tabId: tabId >= 0 ? tabId : undefined });
    chrome.action.setBadgeBackgroundColor({ color: "#E94560" });

    sendToDesktop({
      type: "fingerprint-attempt",
      api: msg.api,
      url: msg.url,
      tabId,
      count: fpAttempts[tabId][msg.api],
    });

    chrome.storage.local.get(["fpLog"], (r) => {
      const log = r.fpLog || [];
      log.push({ api: msg.api, url: msg.url, at: Date.now() });
      chrome.storage.local.set({ fpLog: log.slice(-200) });
    });
  }

  if (msg.type === "shield-armed") {
    chrome.storage.local.get(["shieldPages"], (r) => {
      const pages = r.shieldPages || {};
      pages[msg.url] = Date.now();
      const keys = Object.keys(pages);
      if (keys.length > 200) delete pages[keys[0]];
      chrome.storage.local.set({ shieldPages: pages });
    });
  }

  // Content script asking: should I block this page?
  if (msg.type === "check-page-block") {
    chrome.storage.local.get(["blockedPatterns"], (r) => {
      const patterns = r.blockedPatterns || [];
      const blocked = patterns.some(p => msg.url.toLowerCase().includes(p.toLowerCase()));
      sendResponse({ blocked });
    });
    return true; // Async response
  }

  // Popup actions: forward to desktop via native messaging
  if (msg.type === "show-desktop" || msg.type === "request-scan") {
    sendToDesktop({ type: msg.type, from: "popup" });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => { delete fpAttempts[tabId]; });

// ============================================================================
// COOKIE & STORAGE MONITORING
// ============================================================================

chrome.cookies.onChanged.addListener((changeInfo) => {
  if (changeInfo.cause === "explicit") return; // User did it
  const cookie = changeInfo.cookie;
  // Flag third-party tracking cookies
  if (cookie.domain.startsWith(".")) {
    sendToDesktop({
      type: "tracking-cookie",
      domain: cookie.domain,
      name: cookie.name,
      removed: changeInfo.removed,
    });
  }
});

// ============================================================================
// HEARTBEAT
// ============================================================================

chrome.alarms.create("heartbeat", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "heartbeat") {
    sendToDesktop({
      type: "bubble-heartbeat",
      tabs: -1, // Filled by tab query if needed
      queueDepth: messageQueue.length,
      pendingGates: pendingGates.size,
    });
  }
});

// ============================================================================
// INIT
// ============================================================================

connectNative();
console.log("[Falsum Bubble] v2.0.0 — browser is inside the bubble. Desktop is the gate.");
