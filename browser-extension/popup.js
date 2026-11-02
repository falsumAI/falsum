// Popup logic — shows desktop link status and recent threats
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(
    ["desktopStatus", "lastDesktopThreat", "purgeLog"],
    (r) => {
      const connEl = document.getElementById("connStatus");
      if (r.desktopStatus) {
        connEl.className = "status connected";
        connEl.textContent = "✓ Linked to desktop app";
        document.getElementById("desktopLink").textContent = "Active";
      } else {
        connEl.className = "status disconnected";
        connEl.textContent = "✗ Desktop app not connected";
        document.getElementById("desktopLink").textContent = "Offline";
      }

      const purges = r.purgeLog || [];
      document.getElementById("purgeCount").textContent = purges.length;

      if (r.lastDesktopThreat) {
        const t = r.lastDesktopThreat;
        document.getElementById("lastThreat").innerHTML =
          `<div class="threat"><strong>Desktop alert:</strong> ${t.detail || t.type}<br>` +
          `<span style="color:#888">${new Date(t.timestamp).toLocaleString()}</span></div>`;
      }
    }
  );

  document.getElementById("openDesktop").addEventListener("click", () => {
    // Tell desktop to show itself (via native message)
    chrome.runtime.sendMessage({ type: "show-desktop" });
    window.close();
  });

  document.getElementById("runScan").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "request-scan" });
    window.close();
  });
});

// Listen for messages from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "show-desktop" || msg.type === "request-scan") {
    // Forward to native host via background
    chrome.runtime.sendMessage(msg);
  }
});
