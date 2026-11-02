package ai.falsum

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager

/**
 * Result of auditing a single installed app.
 *
 * @param riskScore 0-100. Higher = more reason to look closely.
 */
data class PermissionFinding(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
    val dangerousPermissions: List<String>,
    val riskScore: Int,
    val reasons: List<String>
)

/**
 * PermissionAuditor — lists installed apps and flags permission overreach.
 *
 * Scores each app on the permissions it was GRANTED (not merely requested),
 * then adds combo bonuses for the classic exfiltration patterns:
 * sensitive-data permission + INTERNET in the same app.
 *
 * Runs fully on-device via PackageManager. Requires QUERY_ALL_PACKAGES on
 * API 30+ (declared in the manifest).
 */
class PermissionAuditor(private val context: Context) {

    private data class Risk(val weight: Int, val reason: String)

    companion object {
        private const val INTERNET = "android.permission.INTERNET"

        private val RISKY: Map<String, Risk> = mapOf(
            "android.permission.READ_SMS" to Risk(25, "can read your text messages"),
            "android.permission.RECEIVE_SMS" to Risk(20, "can intercept incoming texts"),
            "android.permission.SEND_SMS" to Risk(15, "can send texts (premium-SMS fraud risk)"),
            "android.permission.READ_CALL_LOG" to Risk(20, "can read your call history"),
            "android.permission.READ_CONTACTS" to Risk(20, "can read your contacts"),
            "android.permission.ACCESS_FINE_LOCATION" to Risk(20, "can track your precise location"),
            "android.permission.ACCESS_BACKGROUND_LOCATION" to Risk(25, "can track location in the background"),
            "android.permission.ACCESS_COARSE_LOCATION" to Risk(10, "can track your approximate location"),
            "android.permission.RECORD_AUDIO" to Risk(25, "can record audio / eavesdrop"),
            "android.permission.CAMERA" to Risk(15, "can access the camera"),
            "android.permission.READ_EXTERNAL_STORAGE" to Risk(10, "can read your files and photos"),
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to Risk(30, "accessibility service: can read screen content and keystrokes"),
            "android.permission.BIND_DEVICE_ADMIN" to Risk(25, "device admin: hard to uninstall, can lock or wipe the phone"),
            "android.permission.SYSTEM_ALERT_WINDOW" to Risk(15, "can draw over other apps (tapjacking risk)"),
            "android.permission.REQUEST_INSTALL_PACKAGES" to Risk(15, "can install other apps silently"),
            "android.permission.READ_PHONE_STATE" to Risk(10, "can read phone identity (IMEI/MEID on older APIs)")
        )
    }

    /**
     * Audit every installed package. Returns findings with riskScore > 0,
     * sorted most-risky first. System apps are included but flagged.
     */
    fun audit(): List<PermissionFinding> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val findings = mutableListOf<PermissionFinding>()

        for (pkg in packages) {
            val finding = auditOne(pm, pkg) ?: continue
            if (finding.riskScore > 0) findings.add(finding)
        }
        return findings.sortedByDescending { it.riskScore }
    }

    private fun auditOne(pm: PackageManager, pkg: PackageInfo): PermissionFinding? {
        val appInfo: ApplicationInfo = pkg.applicationInfo ?: return null
        val requested = pkg.requestedPermissions ?: return null
        val flags = pkg.requestedPermissionsFlags ?: IntArray(0)

        // Only count permissions actually GRANTED to the app.
        val granted = requested.filterIndexed { i, perm ->
            RISKY.containsKey(perm) &&
                    i < flags.size &&
                    (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
        if (granted.isEmpty()) return null

        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val reasons = granted.map { RISKY.getValue(it).reason }.toMutableList()
        var score = granted.sumOf { RISKY.getValue(it).weight }

        // --- combo bonuses: sensitive capability + INTERNET = exfiltration path ---
        val hasInternet = requested.contains(INTERNET)
        if (hasInternet) {
            fun combo(perm: String, label: String, bonus: Int) {
                if (granted.contains(perm)) {
                    score += bonus
                    reasons += "$label + internet: data can leave the phone"
                }
            }
            combo("android.permission.READ_SMS", "SMS reading", 20)
            combo("android.permission.RECEIVE_SMS", "SMS interception", 15)
            combo("android.permission.READ_CALL_LOG", "call-log reading", 15)
            combo("android.permission.READ_CONTACTS", "contact reading", 15)
            combo("android.permission.ACCESS_FINE_LOCATION", "precise location", 15)
            combo("android.permission.ACCESS_BACKGROUND_LOCATION", "background location", 20)
            combo("android.permission.RECORD_AUDIO", "audio recording", 20)
            combo("android.permission.CAMERA", "camera access", 10)
        }
        // Accessibility + device admin together is the classic persistence combo.
        if (granted.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
            granted.contains("android.permission.BIND_DEVICE_ADMIN")
        ) {
            score += 20
            reasons += "accessibility + device admin: extremely hard to remove"
        }

        val label = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            pkg.packageName
        }

        return PermissionFinding(
            packageName = pkg.packageName,
            appName = label,
            isSystemApp = isSystem,
            dangerousPermissions = granted,
            riskScore = score.coerceAtMost(100),
            reasons = reasons
        )
    }
}
