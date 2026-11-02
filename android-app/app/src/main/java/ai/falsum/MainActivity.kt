package ai.falsum

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * Falsum main screen.
 *
 * Plain, jargon-free controls: protection on/off, permission audit,
 * stalkerware scan. Output is written in sentences a non-technical
 * person can read. (Per project requirement: a worried parent — or
 * their kid — must be able to use this.)
 *
 * UI is built programmatically so the skeleton needs zero XML layouts
 * or drawable resources; the VS Code agent can replace it with a
 * polished Fluent-style design later.
 */
class MainActivity : Activity() {

    private lateinit var output: TextView
    private lateinit var statusView: TextView
    private lateinit var vault: VaultLogger

    companion object {
        private const val REQUEST_VPN = 1001
    }

    @Suppress("DEPRECATION") // startActivityForResult still works on all API levels;
    // the VS Code agent may migrate to ActivityResultLauncher later.
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vault = VaultLogger(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        val title = TextView(this).apply {
            text = "Falsum"
            textSize = 28f
        }
        val subtitle = TextView(this).apply {
            text = "Free protection. Nothing leaves your phone."
            textSize = 14f
        }
        statusView = TextView(this).apply {
            textSize = 14f
            text = "Status: checking…"
        }

        val btnStart = Button(this).apply { text = "Turn protection ON" }
        val btnStop = Button(this).apply { text = "Turn protection OFF" }
        val btnAudit = Button(this).apply { text = "Check app permissions" }
        val btnStalker = Button(this).apply { text = "Scan for stalkerware" }

        output = TextView(this).apply {
            textSize = 13f
            setPadding(0, 24, 0, 0)
        }
        val scroll = ScrollView(this).apply { addView(output) }

        root.addView(title)
        root.addView(subtitle)
        root.addView(statusView)
        root.addView(btnStart)
        root.addView(btnStop)
        root.addView(btnAudit)
        root.addView(btnStalker)
        root.addView(
            scroll,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0, 1f
            )
        )
        setContentView(root)

        btnStart.setOnClickListener { requestVpnStart() }
        btnStop.setOnClickListener { stopVpn() }
        btnAudit.setOnClickListener { runAudit() }
        btnStalker.setOnClickListener { runStalkerScan() }

        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    // ---------------------------------------------------------- VPN control

    private fun requestVpnStart() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepare, REQUEST_VPN)
        } else {
            startVpn()
        }
    }

    @Deprecated("Kept for skeleton simplicity; works on all API levels.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startVpn()
            else appendOutput("VPN permission was denied. Protection stays off.")
        }
    }

    private fun startVpn() {
        val intent = Intent(this, FalsumVpnService::class.java).apply {
            action = FalsumVpnService.ACTION_START
        }
        startService(intent)
        vault.log("ui", "protection turned on")
        appendOutput("Protection is turning on…")
        statusView.postDelayed({ refreshStatus() }, 1500)
    }

    private fun stopVpn() {
        val intent = Intent(this, FalsumVpnService::class.java).apply {
            action = FalsumVpnService.ACTION_STOP
        }
        startService(intent)
        vault.log("ui", "protection turned off")
        appendOutput("Protection is off.")
        refreshStatus()
    }

    // ---------------------------------------------------------- audits

    private fun runAudit() {
        appendOutput("Checking every app's permissions…")
        thread {
            val findings = try {
                PermissionAuditor(this).audit()
            } catch (e: Exception) {
                runOnUiThread { appendOutput("Permission check failed: ${e.message}") }
                return@thread
            }
            vault.log("audit", "permission audit: ${findings.size} risky apps")
            runOnUiThread {
                if (findings.isEmpty()) {
                    appendOutput("Good news: no app has a risky permission mix.")
                } else {
                    appendOutput("Found ${findings.size} app(s) worth a look:")
                    findings.take(20).forEach { f ->
                        val sys = if (f.isSystemApp) " [system app]" else ""
                        appendOutput("• ${f.appName}$sys — risk ${f.riskScore}/100")
                        f.reasons.take(3).forEach { r -> appendOutput("    – $r") }
                    }
                    if (findings.size > 20) appendOutput("…and ${findings.size - 20} more.")
                }
                refreshStatus()
            }
        }
    }

    private fun runStalkerScan() {
        appendOutput("Scanning for stalkerware…")
        thread {
            val scanner = StalkerwareScanner(this)
            val sigHits = try { scanner.scanSignatures() } catch (e: Exception) { emptyList() }
            val heur = try { scanner.scanHeuristic() } catch (e: Exception) { emptyList() }
            vault.log("stalkerware", "scan: ${sigHits.size} signature hits, ${heur.size} heuristic warnings")
            runOnUiThread {
                if (sigHits.isEmpty() && heur.isEmpty()) {
                    appendOutput("No stalkerware found. Your phone looks clean.")
                } else {
                    sigHits.forEach { h ->
                        appendOutput("⚠ FOUND: ${h.appLabel} (${h.family})")
                        appendOutput("    ${h.notes}")
                        appendOutput("    Package: ${h.packageName}")
                    }
                    heur.forEach { w -> appendOutput("⚠ Suspicious: $w") }
                    appendOutput("If you did not install these yourself, remove them and consider this phone compromised.")
                }
                refreshStatus()
            }
        }
    }

    // ---------------------------------------------------------- helpers

    private fun refreshStatus() {
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        statusView.text =
            "Status ($time): blocked trackers=${FalsumVpnService.blockedTrackers} · " +
                    "forwarded=${FalsumVpnService.forwardedPackets} · " +
                    "vault entries=${vault.entryCount()} (chain ${if (vault.verify()) "OK" else "BROKEN"})"
    }

    private fun appendOutput(line: String) {
        output.append(line + "\n")
    }
}
