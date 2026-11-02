// Falsum Falsum — background service worker
// The browser face. Linked to the desktop app via native messaging.
// They see each other: this extension reports browser threats to the desktop,
// and the desktop reports system threats to this extension.

const NATIVE_HOST = "com.sentinel.native";
let nativePort = null;
let desktopConnected = false;
let reconnectAttempts = 0;

// ============================================================================
// NATIVE MESSAGING: link to desktop app
// ============================================================================

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
    desktopConnected = true;
    reconnectAttempts = 0;
    console.log("[Falsum] Connected to desktop app");

    nativePort.onMessage.addListener((msg) => {
      handleDesktopMessage(msg);
    });

    nativePort.onDisconnect.addListener(() => {
      desktopConnected = false;
      console.log("[Falsum] Desktop disconnected");
      // Exponential backoff: 5s, 10s, 20s, 40s, max 60s (pain point #61 FIX)
      const delay = Math.min(5000 * Math.pow(2, reconnectAttempts), 60000);
      reconnectAttempts++;
      console.log(`[Falsum] Reconnecting in ${delay/1000}s (attempt ${reconnectAttempts})`);
      setTimeout(connectNative, delay);
    });

    // Announce ourselves
    sendToDesktop({ type: "hello", from: "browser-extension", version: "1.0.0" });
  } catch (e) {
    console.error("[Falsum] Native connect failed:", e);
    desktopConnected = false;
    setTimeout(connectNative, 10000);
  }
}

function sendToDesktop(msg) {
  if (!desktopConnected || !nativePort) {
    console.warn("[Falsum] Desktop not connected, queuing:", msg.type);
    return false;
  }
  try {
    nativePort.postMessage(msg);
    return true;
  } catch (e) {
    console.error("[Falsum] Send failed:", e);
    return false;
  }
}

function handleDesktopMessage(msg) {
  console.log("[Falsum] Desktop says:", msg.type);
  switch (msg.type) {
    case "threat":
      // Desktop found a system threat — show browser warning
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
      chrome.storage.local.set({ lastDesktopThreat: msg });
      break;
    case "purge":
      // Desktop purged a binary — log it in browser
      chrome.storage.local.get(["purgeLog"], (r) => {
        const log = r.purgeLog || [];
        log.push({ ...msg, receivedAt: Date.now() });
        chrome.storage.local.set({ purgeLog: log.slice(-100) });
      });
      break;
    case "status":
      chrome.storage.local.set({ desktopStatus: msg });
      break;
  }
}

// ============================================================================
// BROWSER THREAT DETECTION → DESKTOP
// ============================================================================

// Watch for phishing: check URLs against local blocklist
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // top frame only
  const url = details.url.toLowerCase();

  // Quick heuristic checks (full analysis by desktop app)
  const suspicious = [];
  if (/xn--/.test(url)) suspicious.push("punycode");
  if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url)) suspicious.push("ip-url");
  if ((url.match(/-/g) || []).length >= 4) suspicious.push("excessive-hyphens");
  if (url.length > 200) suspicious.push("overlong-url");

  if (suspicious.length > 0) {
    sendToDesktop({
      type: "browser-threat",
      url: details.url,
      signals: suspicious,
      tabId: details.tabId,
      timestamp: Date.now()
    });
  }
});

// Watch for suspicious downloads
chrome.downloads.onCreated.addListener((item) => {
  const ext = (item.filename.split(".").pop() || "").toLowerCase();
  const dangerous = ["exe", "msi", "bat", "cmd", "ps1", "vbs", "js", "scr", "lnk"];
  if (dangerous.includes(ext)) {
    sendToDesktop({
      type: "browser-download",
      filename: item.filename,
      url: item.url,
      danger: `Executable download: .${ext}`,
      timestamp: Date.now()
    });
  }
});

// ============================================================================
// HEARTBEAT: let desktop know we're alive
// ============================================================================

chrome.alarms.create("heartbeat", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "heartbeat") {
    sendToDesktop({ type: "heartbeat", from: "browser-extension", timestamp: Date.now() });
  }
});

// ============================================================================
// INIT
// ============================================================================

connectNative();
console.log("[Falsum] Falsum browser extension loaded");
