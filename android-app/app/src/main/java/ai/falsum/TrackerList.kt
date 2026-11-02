package ai.falsum

/**
 * Curated tracker / advertising / analytics domain blocklist used by
 * [FalsumVpnService] for on-device DNS sinkholing.
 *
 * Matching is suffix-based: "sub.google-analytics.com" matches
 * "google-analytics.com". All decisions happen locally; this list ships
 * with the APK and is never fetched from a server.
 */
object TrackerList {

    val DOMAINS: Set<String> = setOf(
        // Google analytics / ads
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "app-measurement.com",
        "firebaseinstallations.googleapis.com",
        // Meta
        "connect.facebook.net",
        "graph.facebook.com",
        // Amazon
        "amazon-adsystem.com",
        // Microsoft
        "bat.bing.com",
        // General ad networks
        "adsrvr.org",            // The Trade Desk
        "ads.yahoo.com",
        "scorecardresearch.com", // Comscore
        "quantserve.com",        // Quantcast
        "outbrain.com",
        "taboola.com",
        "criteo.com",
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "moatads.com",
        // Analytics / product telemetry
        "hotjar.com",
        "mixpanel.com",
        "amplitude.com",
        "segment.io",
        "fullstory.com",
        "crazyegg.com",
        "inspectlet.com",
        "mouseflow.com",
        // Mobile attribution / SDKs
        "branch.io",
        "appsflyer.com",
        "adjust.com",
        "kochava.com",
        "singular.net",
        "tenjin.com",
        "crashlytics.com",
        // Misc trackers
        "newrelic.com",
        "bugsnag.com",
        "sentry.io",
        "pendo.io",
        "intercom.io",
        "drift.com",
        "hubspot.com",
        // Stalkerware C2 (mirrors desktop module 24 table)
        "data.mspy.com",
        "api.mspy.com",
        "cp.flexispy.com",
        "data.flexispy.com",
        "api.cocospy.com",
        "track.cocospy.com",
        "api.spyic.com",
        "my.thetruthspy.com",
        "cp.hoverwatch.com",
        "api.hoverwatch.com",
        "my.copy9.com",
        "my.ispyoo.com",
        "protocol-a.thetruthspy.com",
        "sync-a.thetruthspy.com",
        "hellospy.com",
        "maxxspy.com",
        "mobiispy.com",
        "spyhide.com",
        "client.spyhide.com",
        "1topspy.com"
    )

    /**
     * Returns true if [host] is a known tracker (exact or subdomain match).
     */
    fun isTracker(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        if (h.isEmpty()) return false
        for (domain in DOMAINS) {
            if (h == domain || h.endsWith(".$domain")) return true
        }
        return false
    }
}
