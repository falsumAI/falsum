package ai.falsum

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Tamper-evident, hash-chained event log — the Android side of the Falsum
 * vault. Same concept as the desktop SHA-384 vault: every entry commits to
 * the hash of the previous entry, so silent deletion or alteration breaks
 * the chain and is detectable via [verify].
 *
 * Stored in app-private storage ([Context.getFilesDir]); no other app can
 * read it, and nothing is ever uploaded.
 */
class VaultLogger(context: Context) {

    private val file = File(context.filesDir, "falsum-vault.jsonl")
    private val lock = Any()

    /** Append an event to the chain. Never throws. */
    fun log(eventType: String, detail: String) {
        synchronized(lock) {
            try {
                val prev = lastHash()
                val ts = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).format(Date())
                val entry = JSONObject()
                    .put("ts", ts)
                    .put("type", eventType)
                    .put("detail", detail)
                    .put("prev", prev)
                    .toString()
                val hash = sha256Hex(prev + entry)
                val record = JSONObject()
                    .put("hash", hash)
                    .put("entry", entry)
                    .toString()
                file.appendText(record + "\n")
            } catch (e: Exception) {
                Log.w(TAG, "vault log failed: ${e.message}")
            }
        }
    }

    /**
     * Verify the full chain. Returns true if every entry's stored hash
     * matches its recomputed hash and every prev-link matches.
     */
    fun verify(): Boolean {
        synchronized(lock) {
            if (!file.exists()) return true
            var expectedPrev = "GENESIS"
            for (line in file.readLines()) {
                if (line.isBlank()) continue
                try {
                    val record = JSONObject(line)
                    val hash = record.getString("hash")
                    val entry = record.getString("entry")
                    val obj = JSONObject(entry)
                    if (obj.getString("prev") != expectedPrev) return false
                    if (sha256Hex(expectedPrev + entry) != hash) return false
                    expectedPrev = hash
                } catch (e: Exception) {
                    Log.w(TAG, "vault verify failed on line: ${e.message}")
                    return false
                }
            }
            return true
        }
    }

    /** Number of entries currently in the vault. */
    fun entryCount(): Int {
        synchronized(lock) {
            if (!file.exists()) return 0
            return file.readLines().count { it.isNotBlank() }
        }
    }

    private fun lastHash(): String {
        if (!file.exists()) return "GENESIS"
        val last = file.readLines().lastOrNull { it.isNotBlank() } ?: return "GENESIS"
        return try {
            JSONObject(last).getString("hash")
        } catch (e: Exception) {
            "GENESIS"
        }
    }

    private fun sha256Hex(s: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val TAG = "FalsumVault"
    }
}
