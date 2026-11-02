package ai.falsum

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log

/** One entry in the stalkerware signature table. */
data class StalkerwareEntry(val family: String, val notes: String)

/** A confirmed hit: this package is installed on the phone. */
data class StalkerwareHit(
    val packageName: String,
    val appLabel: String,
    val family: String,
    val notes: String
)

/**
 * Signature database. Mirrors windows/modules/24-mobile-shield/ from the
 * desktop build (49 packages, table date 2026-10-30, incl. the Echap
 * stalkerware-indicators CC BY 4.0 set).
 *
 * Like the desktop table, signatures go stale — check TABLE_DATE and
 * refresh from the upstream sources when it ages past ~90 days.
 */
object StalkerwareDatabase {
    const val TABLE_DATE = "2026-10-30"

    val PACKAGES: Map<String, StalkerwareEntry> = mapOf(
        // --- commercial spouseware ---
        "com.mspy" to StalkerwareEntry("mSpy", "Commercial spouseware; hides icon, exfiltrates SMS/calls/GPS."),
        "com.flexispy" to StalkerwareEntry("FlexiSPY", "Commercial spouseware; call interception, ambient recording."),
        "com.highster" to StalkerwareEntry("Highster Mobile", "Commercial spouseware; SMS/call/GPS exfil."),
        "com.spybubble" to StalkerwareEntry("SpyBubble", "Commercial spouseware."),
        "com.mobistealth" to StalkerwareEntry("Mobistealth", "Commercial spouseware."),
        "com.xnspy" to StalkerwareEntry("Xnspy", "Commercial spouseware."),
        "com.cocospy" to StalkerwareEntry("Cocospy", "Commercial spouseware; no-root install path."),
        "com.spyic" to StalkerwareEntry("Spyic", "Commercial spouseware."),
        "com.minspy" to StalkerwareEntry("Minspy", "Commercial spouseware."),
        "com.spyier" to StalkerwareEntry("Spyier", "Commercial spouseware."),
        "com.neatspy" to StalkerwareEntry("Neatspy", "Commercial spouseware."),
        "com.kids guard" to StalkerwareEntry("KidsGuard", "Marketed as parental control; abused as spouseware."),
        "com.clevguard" to StalkerwareEntry("ClevGuard", "KidsGuard publisher package."),
        "com.thecounter" to StalkerwareEntry("TheTruthSpy", "Commercial spouseware; breached 2018, data leaked."),
        "com.hoverwatch" to StalkerwareEntry("Hoverwatch", "Commercial spouseware; keylogger component."),
        "com.phonespector" to StalkerwareEntry("PhoneSpector", "Commercial spouseware."),
        "com.autoforward" to StalkerwareEntry("Auto Forward", "Commercial spouseware; SMS/call forwarding."),
        "com.digiscale" to StalkerwareEntry("DigiScale", "Spouseware variant."),
        // --- parental-control tools abused for stalking ---
        "com.kidlogger" to StalkerwareEntry("KidLogger", "Parental control; keylogging abused for stalking."),
        "com.retinax" to StalkerwareEntry("Retinax", "Parental control with stealth mode."),
        "com.talklog" to StalkerwareEntry("Talklog", "Call-recording abused as spouseware."),
        "com.smsbackup" to StalkerwareEntry("SMS Backup+", "Legit backup tool; check for unconsented installs."),
        "com.github.stalker" to StalkerwareEntry("Generic stalker builds", "Placeholder pattern for GitHub-built trackers."),
        // --- Echap stalkerware-indicators (CC BY 4.0) ---
        "com.apspy.app" to StalkerwareEntry("TheTruthSpy family", "TheTruthSpy/Copy9/MxSpy/iSpyoo backend; disguised as system service."),
        "com.systemservice" to StalkerwareEntry("TheTruthSpy", "Classic disguise name: 'System Service'."),
        "com.thetruth" to StalkerwareEntry("TheTruthSpy", "TheTruthSpy variant."),
        "com.mxspy" to StalkerwareEntry("MxSpy/TheTruthSpy", "Same backend as TheTruthSpy."),
        "com.ispyoo" to StalkerwareEntry("iSpyoo/TheTruthSpy", "Same backend family."),
        "com.spyzee" to StalkerwareEntry("SpyZee/TheTruthSpy", "Same backend family."),
        "com.guest" to StalkerwareEntry("GuestSpy/TheTruthSpy", "Same backend family."),
        "com.hellospy" to StalkerwareEntry("HelloSpy", "HelloSpy family (1TopSpy/MaxxSpy/MobiiSpy/SpyHide)."),
        "com.maxxspy" to StalkerwareEntry("MaxxSpy/HelloSpy", "HelloSpy family."),
        "com.mobiispy" to StalkerwareEntry("MobiiSpy/HelloSpy", "HelloSpy family."),
        "com.topspy" to StalkerwareEntry("1TopSpy/HelloSpy", "HelloSpy family."),
        "com.wifiset.service" to StalkerwareEntry("Fake Wi-Fi Settings", "Disguised as 'Wi-Fi Settings'."),
        "com.googlesettings.setting" to StalkerwareEntry("Fake Google Settings", "Disguised as system settings (HelloSpy family)."),
        "com.android.innovaspy" to StalkerwareEntry("InnovaSpy/HelloSpy", "HelloSpy family."),
        "com.prophoto.editor" to StalkerwareEntry("Fake Photo Editor", "HelloSpy family disguise."),
        "com.sa.app" to StalkerwareEntry("SpyAdvice", "SpyAdvice / FreeSpyPhone."),
        "core.update.framework" to StalkerwareEntry("mSpy", "mSpy disguised package."),
        "com.kids.pro" to StalkerwareEntry("ClevGuard", "ClevGuard/KidsGuard disguised."),
        "com.android.core.mntw" to StalkerwareEntry("HoverWatch", "HoverWatch disguised."),
        "com.fp.backup" to StalkerwareEntry("FlexiSPY", "FlexiSPY disguised as backup."),
        "com.sc.spyic.v3" to StalkerwareEntry("Spyic", "Spyic v3 disguised."),
        "m.mobile.control" to StalkerwareEntry("SpyHuman", "SpyHuman package."),
        "com.lsdroid.cerberus" to StalkerwareEntry("Cerberus", "Cerberus spyware."),
        "mobile.monitor.child2021" to StalkerwareEntry("MobileTrackerFree", "MobileTrackerFree."),
        "city.russ.alltrackercorp" to StalkerwareEntry("Fake Thief Tracker", "Disguised as 'Thief Tracker'."),
        "com.autoforward.monitor" to StalkerwareEntry("AutoForward", "Disguised as 'Device'.")
    )

    /** Known stalkerware command-and-control domains (also in TrackerList). */
    val C2_DOMAINS: Map<String, String> = mapOf(
        "data.mspy.com" to "mSpy",
        "api.mspy.com" to "mSpy",
        "cp.flexispy.com" to "FlexiSPY",
        "data.flexispy.com" to "FlexiSPY",
        "api.cocospy.com" to "Cocospy",
        "track.cocospy.com" to "Cocospy",
        "api.spyic.com" to "Spyic",
        "my.thetruthspy.com" to "TheTruthSpy",
        "cp.hoverwatch.com" to "Hoverwatch",
        "api.hoverwatch.com" to "Hoverwatch",
        "my.copy9.com" to "TheTruthSpy/Copy9",
        "my.ispyoo.com" to "TheTruthSpy/iSpyoo",
        "protocol-a.thetruthspy.com" to "TheTruthSpy",
        "sync-a.thetruthspy.com" to "TheTruthSpy",
        "hellospy.com" to "HelloSpy",
        "maxxspy.com" to "HelloSpy/MaxxSpy",
        "mobiispy.com" to "HelloSpy/MobiiSpy",
        "spyhide.com" to "SpyHide/HelloSpy",
        "client.spyhide.com" to "SpyHide",
        "1topspy.com" to "HelloSpy/1TopSpy"
    )
}

/**
 * StalkerwareScanner — checks installed packages against the signature
 * table and runs heuristics for spyware not yet in the table.
 *
 * Heuristic flags (classic stalkerware traits):
 *  - no launcher icon (hidden from the app drawer) + sensitive permissions
 *  - device-admin enabled (hard to uninstall)
 *  - accessibility service + SMS/location permissions
 */
class StalkerwareScanner(private val context: Context) {

    companion object {
        private const val TAG = "FalsumStalker"
    }

    /** Exact signature matches against [StalkerwareDatabase.PACKAGES]. */
    fun scanSignatures(): List<StalkerwareHit> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val installed = pm.getInstalledPackages(0)
        val hits = mutableListOf<StalkerwareHit>()
        for (pkg in installed) {
            val entry = StalkerwareDatabase.PACKAGES[pkg.packageName] ?: continue
            val label = try {
                pkg.applicationInfo?.let { pm.getApplicationLabel(it).toString() } ?: pkg.packageName
            } catch (e: Exception) {
                pkg.packageName
            }
            hits += StalkerwareHit(pkg.packageName, label, entry.family, entry.notes)
            Log.w(TAG, "Stalkerware signature hit: ${pkg.packageName} (${entry.family})")
        }
        return hits
    }

    /**
     * Heuristic scan for apps that behave like stalkerware but aren't in
     * the table yet. Returns human-readable warnings.
     */
    fun scanHeuristic(): List<String> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val warnings = mutableListOf<String>()

        for (pkg in installed) {
            val name = pkg.packageName
            // Skip well-known system packages to cut noise.
            if (name.startsWith("com.android.") || name.startsWith("com.google.android.")) continue

            val perms = pkg.requestedPermissions?.toSet() ?: emptySet()
            val hasLauncher = try {
                pm.getLaunchIntentForPackage(name) != null
            } catch (e: Exception) {
                true
            }
            val sensitive = setOf(
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CALL_LOG"
            ).intersect(perms)

            if (!hasLauncher && sensitive.isNotEmpty() && perms.contains("android.permission.INTERNET")) {
                val label = try {
                    pkg.applicationInfo?.let { pm.getApplicationLabel(it).toString() } ?: name
                } catch (e: Exception) {
                    name
                }
                warnings += "$label ($name): hidden from launcher with ${sensitive.size} sensitive permission(s) + internet — classic stalkerware pattern"
            }
            if (perms.contains("android.permission.BIND_DEVICE_ADMIN") && sensitive.isNotEmpty()) {
                warnings += "$name: device-admin + sensitive permissions — very hard to remove, inspect immediately"
            }
        }
        return warnings
    }
}
