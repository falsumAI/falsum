package ai.falsum

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager

/**
 * Infrastructure detector for Android.
 *
 * Detects if this phone is being used as infrastructure:
 * - Device admin apps (MDM) that shouldn't be there
 * - Carrier bloatware with excessive permissions
 * - Unknown device administrators
 * - Developer options / USB debugging (attack surface)
 * - Unknown sources enabled
 *
 * Plain language. No jargon.
 */
class InfrastructureDetector(private val context: Context) {

    data class Finding(
        val category: String,
        val severity: String,  // "critical", "warning", "info"
        val title: String,
        val description: String,
        val recommendation: String
    )

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()

        // 1. Check for device admin apps (MDM)
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
            as android.app.admin.DevicePolicyManager
        val admins = dpm.activeAdmins ?: emptyList()
        if (admins.isNotEmpty()) {
            findings.add(Finding(
                category = "device-admin",
                severity = "warning",
                title = "Device administrator apps found",
                description = "These apps have deep control over your phone: ${admins.size} found.",
                recommendation = "If you didn't install these for work, remove them. " +
                    "A personal phone should not have device administrators."
            ))
        }

        // 2. Check for USB debugging
        val adbEnabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) == 1
        if (adbEnabled) {
            findings.add(Finding(
                category = "usb-debugging",
                severity = "warning",
                title = "USB debugging is turned on",
                description = "This lets a computer control your phone over USB.",
                recommendation = "Turn this off unless you are actively developing. " +
                    "Settings > Developer options > USB debugging."
            ))
        }

        // 3. Check for unknown sources
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            val unknownSources = Settings.Secure.getInt(
                context.contentResolver,
                Settings.Secure.INSTALL_NON_MARKET_APPS, 0
            ) == 1
            if (unknownSources) {
                findings.add(Finding(
                    category = "unknown-sources",
                    severity = "warning",
                    title = "Installing apps from unknown sources is allowed",
                    description = "This lets any website install apps on your phone.",
                    recommendation = "Turn this off. Settings > Security > Unknown sources."
                ))
            }
        }

        // 4. Check for carrier bloatware with dangerous permissions
        val pm = context.packageManager
        val carrierPackages = listOf(
            "com.verizon", "com.att", "com.tmobile", "com.sprint"
        )
        val installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        for (pkg in installed) {
            val isCarrier = carrierPackages.any { pkg.packageName.startsWith(it) }
            if (isCarrier) {
                val dangerous = pkg.requestedPermissions?.count { perm ->
                    perm.contains("LOCATION") || perm.contains("SMS") ||
                    perm.contains("CALL") || perm.contains("CONTACTS")
                } ?: 0
                if (dangerous > 0) {
                    findings.add(Finding(
                        category = "carrier-bloatware",
                        severity = "info",
                        title = "Carrier app with sensitive permissions",
                        description = "${pkg.packageName} can access $dangerous sensitive permission(s).",
                        recommendation = "Carrier apps serve the carrier, not you. " +
                            "Disable it if you don't use it."
                    ))
                }
            }
        }

        return findings
    }
}
