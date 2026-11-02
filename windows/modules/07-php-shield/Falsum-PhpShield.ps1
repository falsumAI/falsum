<#
.SYNOPSIS
    Falsum PHP Shield — PHP install discovery, PHP2Shell (CVE-2026-109618 /
    CVE-2026-109619) vulnerability detection, and mitigation writer.

.DESCRIPTION
    The proof case for this module is PHP2Shell, disclosed 2026-10-21:
    CVE-2026-109618 (upload-progress unserializer use-after-free, OOM
    longjmp RCE — also discloses freed worker memory) and CVE-2026-109619
    (fatal-error backtrace / stale worker state use-after-free RCE) —
    both CVSS v4.0 9.2, both CISA KEV-listed, affecting PHP 5.4.0–8.5.11
    on mod_php and PHP-FPM. Patched in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
    (source backports for 7.4 / 8.0 / 8.1 only).
    Honest limits, stated up front: session.upload_progress.enabled=Off
    closes ONE route to CVE-2026-109619 and blocks the post-patch
    session-file LFI-to-RCE chain — it does NOT fix either engine bug, and
    the .htaccess/web.config trigger rules reduce one route further.
    Updating PHP is the only complete fix. Better-Way Law therefore means
    the module also ships the rotation plan: CVE-2026-109618 can disclose
    freed worker memory, so a host that ran unpatched PHP must rotate
    session keys, app secrets and credentials/TLS keys that lived in
    worker memory after patching. About 884K hosts still run PHP 8.1 or
    older — EOL, with only the source backports as a path for 7.4/8.0/8.1.

    THE BETTER-WAY LAW (Gregg): a detection without its fix is unfinished
    work. This module does not just report a vulnerable PHP — it ships the
    fix:
      1. Detection: finds every PHP on the box (PATH, where.exe, common
         stacks, scoop/chocolatey/winget/Herd/MAMP, registry) and versions
         it with evidence, including the SAPI (cli/fpm/cgi) it runs.
      2. CVE match: says exactly why a version is vulnerable (CVE, CVSS,
         affected range, patch release) or why it is end-of-life.
      3. Hardening audit: ships a php.ini hardening table (expose_php,
         disable_functions, session cookie flags, upload limits, ...) and
         checks every install live — with the CLI-context caveat stated
         plainly (php -r reads the CLI SAPI, which may differ from the web
         SAPI; two CLI-default-divergent checks are N/A on CLI).
      4. Web bindings: reads IIS applicationHost.config (read-only) for
         FastCGI php-cgi.exe registrations and matches them to discovered
         installs — a PHP that serves the web is the one that matters.
      5. Mitigation: writes web-server WAF rules (.htaccess for Apache,
         web.config for IIS) blocking the upload_progress trigger field
         name AND the CVE-2024-4577 CGI option-injection trigger, and can
         disable session.upload_progress.enabled in php.ini (with backup).
         These are partial stopgaps — stated as such in the rule text —
         not the fix. The IIS writers merge into existing requestFiltering
         instead of writing a second <security> element (which would break
         web.config).
      6. Verification: re-checks that every mitigation is actually in place.
      7. Docroot webshell scan: Find-PhpSuspiciousFiles sweeps a web root
         against a 12-indicator webshell table (per-file SHA-256), and
         Move-PhpSuspiciousFileToQuarantine moves confirmed hits out with
         a reversible SHA-256 manifest.
      8. Apache bindings: reads httpd.conf (+ conf.d includes) for php
         LoadModule / ProxyPassMatch / SetHandler registrations — the
         Apache side of "which PHP serves the web".
      9. Live workers: lists running php-fpm.exe / php-cgi.exe processes
         and matches them to discovered installs — a running PHP is the
         one PHP2Shell can actually reach.
     10. Recent-change sweep: PHP files in a docroot modified in the last
         N days with per-file SHA-256 — the webshell-drop signal. Plus
         every php.exe probe runs through a kill-timeout so a hung binary
         cannot stall the scan.

    CHANGELOG
      1.5.0 (2026-10-30): hardening pass — TRUTH pass on the PHP2Shell
        threat data (verified this run against the Oct 21 2026 PHP release
        + Sansec/Upwind/cveplayground writeups): (a) CVE-2026-109618 is an
        OOM-longjmp use-after-free (NOT "session state corruption") and
        ALSO discloses freed worker memory — Mechanism/Mitigation rewritten
        with the official stopgap (memory_limit=-1, with the DoS trade-off
        stated); (b) CVE-2026-109619 was shipped as CVSS 8.1/High — it is
        CVSS v4.0 9.2/Critical (stale-worker-state use-after-free), both
        CVEs corrected, CISA KEV noted; (c) the ini table's upload_progress
        row claimed Off "kills the whole attack class" — it does not; it
        closes one route to 109619 + the post-patch session-file LFI chain
        (upload_progress stays ON by default even in patched releases),
        Why/Fix rewritten; (d) memory_limit row carries the official
        memory_limit=-1 bridge note; (e) EOL rows for 8.1/8.0/7.4 note the
        Oct 2026 source backports, and EOL findings carry the backport
        caveat instead of "no patch"; (f) NEW Test-PhpMemoryExposureRisk
        (pure): unpatched/backport-only installs get an EXPOSED verdict
        with the rotate-after-patching plan (Better-Way Law — detection of
        the RCE ships its secret-rotation follow-up), wired into
        Test-PhpInstalls and the txt export; (g) REAL VERIFICATION GAP:
        Test-PhpMitigation only verified the php.ini layer when DocRoot
        was EMPTY, so New-PhpMitigation -DocRoot X -DisableUploadProgress
        never verified the one layer it changed — the ini layer is now
        verified across all discovered installs whenever no install is
        pinned, regardless of DocRoot; (h) New-PhpMitigation and the WAF
        rule text now say "stopgap" honestly (POST bodies invisible to
        mod_rewrite, upload_progress.name renamable). Battery +11 cases.
      1.4.0 (2026-10-30): hardening pass — REAL gaps closed: (a) the shipped
        CVE table covered only the PHP2Shell pair; added CVE-2024-4577
        (PHP-CGI argument injection, CVSS 9.8, CISA KEV — patches
        8.1.29/8.2.20/8.3.8 verified 2026-10-30); (b) REAL BUG: Test-PhpCveMatch
        hardcoded the upload_progress mitigation text into every CVE finding,
        so any new CVE would have shipped the wrong fix — findings now use
        each CVE row's own Mitigation, and CGI-applicable CVEs carry a SAPI
        exposure note (cgi-fcgi = exposed surface; other SAPIs = check the
        php-cgi.exe FastCGI registrations); (c) ini table 22->24 rows: new
        cgi.force_redirect=1 (High — CGI binary directly reachable when 0)
        and mail.add_x_header=Off (Medium — leaks the script path in mail
        headers); (d) Better-Way Law for the new CVE: New-PhpCgiWafRuleText
        (Apache .htaccess — blocks the %AD soft-hyphen trigger and
        leading-dash option probes, anchored ^ patterns mod_rewrite can do)
        and New-PhpCgiIisRuleText (IIS requestFiltering — denyQueryStringSequences
        for the %-encoded trigger only, honest comment: anchoring -s/-d as
        substrings would over-block legit params), with Add-PhpCgiWafRule /
        Add-PhpCgiIisWafRule writers (per-block markers, backups) wired into
        New-PhpMitigation and verified by Test-PhpMitigation; (e) FIXED A
        REAL BREAK-THE-SITE BUG in the EXISTING Add-IisWafRule: it inserted
        a second <security> element whenever the web.config already had
        requestFiltering — IIS rejects duplicate sections (500.19), so the
        "mitigation" could take the site down. Both IIS writers now merge
        through pure Merge-IisDenyQueryStringSequences (existing
        <denyQueryStringSequences> -> <requestFiltering> -> <security> ->
        fresh <security>; sequences already present are skipped; malformed
        configs with no anchor are refused, not appended to). New-PhpMitigation
        writes both rule sets per docroot (upload_progress + CGI-4577) and
        Test-PhpMitigation verifies all four layers. Battery +19 cases incl.
        writer idempotence and the no-dup-security merge proof.
      1.3.0 (2026-10-30): hardening pass — REAL bugs closed: (a) every
        php.exe probe (php -v, --ini, -r) now runs through Invoke-PhpProbe
        with a 15s kill-timeout — a hung or weaponized php.exe could
        previously hang the whole scan forever; (b) pre-release versions
        (RC/alpha/beta) now sort OLDER than the release in Compare-PhpVersion
        — 8.2.35RC1 was previously scored as patched when it predates the
        8.2.35 patch; (c) Export-PhpShieldReport fell back to nothing when
        the Desktop special folder was unavailable (now: repo-relative
        Falsum-Reports). NEW: Get-PhpFpmProcesses (live PHP workers mapped
        to installs), Get-ApachePhpBindings (httpd.conf LoadModule /
        ProxyPassMatch / SetHandler discovery), Get-PhpRecentlyChangedFiles
        (docroot files changed in the last N days, SHA-256 — the
        webshell-drop signal), pure helpers ConvertTo-PhpIniUploadProgressOff
        and New-ApacheWafRuleText so the mitigations are offline-testable,
        and Test-PhpShieldHygiene (36-case offline battery).
      1.2.0 (2026-10-30): hardening pass — ini table 14->22 rows (adds
        session.upload_progress.enabled=Off which is the PHP2Shell trigger
        itself, cgi.fix_pathinfo=0, session.use_trans_sid=0,
        session.use_only_cookies=1, gc_maxlifetime/session lifetimes,
        max_input_vars, memory_limit, zend.assertions=-1) with new 'equals'
        and 'le-num' test types; new docroot webshell scanner
        (Find-PhpSuspiciousFiles, 12-indicator table, per-file SHA-256,
        quarantine function Move-PhpSuspiciousFileToQuarantine as the
        Better-Way fix) wired into the report/export.
      1.1.0 (2026-10-30): hardening pass — fixed Apache .htaccess OR-chain
        bug (old rules required the trigger in BOTH query string AND URI;
        now blocks on EITHER), robust upload_progress read via
        (int)(bool)ini_get, SAPI detection, expanded discovery paths,
        Get-PhpIniHardeningTable/Check (14-row shipped table), IIS FastCGI
        binding discovery, Test-PhpMitigation defaults to all installs.
      1.0.0 (2026-10-30): initial build.

    PowerShell 5.1 compatible. Zero external dependencies. Admin is NOT
    required to scan; writing php.ini inside Program Files usually is, and
    the mitigation functions say so cleanly instead of failing.

.EXAMPLE
    . .\Falsum-PhpShield.ps1
    $scan = Test-PhpInstalls
    $scan | Format-Table Path, Version, Vulnerable, Cves, Eol

.EXAMPLE
    # Mitigate a web root (writes .htaccess + web.config rules, backs up originals)
    New-PhpMitigation -DocRoot 'C:\inetpub\wwwroot' -ServerType Both

.EXAMPLE
    # Disable upload_progress in php.ini for a specific install (backs up first)
    $php = (Get-PhpInstalls | Select-Object -First 1)
    New-PhpMitigation -PhpInstall $php -DisableUploadProgress

.EXAMPLE
    Test-PhpMitigation -DocRoot 'C:\inetpub\wwwroot' | Format-Table Check, Pass, Detail

.EXAMPLE
    # Webshell sweep of a docroot, then quarantine a confirmed hit (reversible)
    $hits = Find-PhpSuspiciousFiles -DocRoot 'C:\inetpub\wwwroot'
    $hits | Format-Table File, Line, Severity, Indicator
    Move-PhpSuspiciousFileToQuarantine -Path $hits[0].File -Reason $hits[0].Indicator -WhatIf

.EXAMPLE
    # php.ini hardening audit + which PHP installs actually serve the web via IIS
    $php = (Get-PhpInstalls | Select-Object -First 1)
    Get-PhpIniHardeningCheck -PhpInstall $php | Format-Table Setting, Verdict, Current, Recommended
    Get-PhpWebBindings | Format-Table PhpCgiPath, MatchedInstall, HandlerMapsPhp
#>

$script:PhpShieldVersion = '1.5.0'
$script:PhpShieldMarker  = '# Falsum-PHPShield'
$script:PhpShieldCgiMarker = '# Falsum-PHPShield-CGI4577'
$script:VaultLoaded      = $false

# ---------------------------------------------------------------------------
# Threat table. Shipped Oct 2026. Refresh CVE rows when new PHP security
# releases drop; refresh the EOL table against php.net/supported-versions.php.
# ---------------------------------------------------------------------------
function Get-PhpThreatTable {
    try {
        $cves = @(
            [pscustomobject]@{
                # Facts verified 2026-10-30 against the Oct 21 2026 PHP
                # release + Sansec / Upwind / cveplayground writeups
                # (this run's one web search): BOTH CVEs are engine
                # memory-safety bugs (use-after-free), CVSS v4.0 9.2,
                # fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, CISA KEV.
                # upload_progress is ONE route — disabling it does NOT
                # close either CVE. Only the update is a complete fix.
                Id          = 'CVE-2026-109618'
                Title       = 'PHP2Shell — upload-progress unserializer use-after-free (OOM longjmp RCE)'
                Cvss        = 9.2
                Severity    = 'Critical'
                Disclosed   = '2026-10-21'
                Affects     = 'PHP 5.4.0–8.5.11 (all branches; mod_php and PHP-FPM). Fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Source backports only for 7.4 / 8.0 / 8.1.'
                Mechanism   = 'A fatal error during a request — typically an out-of-memory error when the request crosses memory_limit — interrupts native PHP code via longjmp() while internal request structures are only partly initialized. Request shutdown then treats that incomplete data as valid, corrupting memory. One confirmed chain goes through the upload-progress multipart handler; a second independent chain drives the memory-allocator bailout on Apache mod_php with default settings — no login, no LFI, no application code needed. The same bug discloses freed worker memory to the client inside the response cookie: on an exploited host, assume secrets in worker memory (passwords, session tokens, API keys, TLS private keys) may have leaked.'
                Patches     = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
                EolBranches = @('8.1','8.0','7.4','7.3','7.2','7.1','7.0','5.6','5.5','5.4')
                AppliesSapi = 'any'
                Mitigation  = 'UPDATE — the only complete fix: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or the 7.4/8.0/8.1 source backports). Interim per PHP: memory_limit=-1 (removes the OOM trigger — this removes a DoS safety net, so pair it with request-size limits and container/cgroup caps, then restore a sane limit after patching). session.upload_progress.enabled=Off does NOT close this CVE. After patching a host that ran vulnerable: rotate session keys, app secrets, and any credentials/TLS keys that lived in worker memory.'
            },
            [pscustomobject]@{
                Id          = 'CVE-2026-109619'
                Title       = 'PHP2Shell — fatal-error backtrace / stale worker state use-after-free (RCE)'
                Cvss        = 9.2
                Severity    = 'Critical'
                Disclosed   = '2026-10-21'
                Affects     = 'PHP 5.4.0–8.5.11 (all branches; mod_php and PHP-FPM). Fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Source backports only for 7.4 / 8.0 / 8.1.'
                Mechanism   = 'PHP workers retain global state pointing to freed request memory. A fatal error — including an out-of-memory error — skips the reset, and the next request on the same PHP-FPM/mod_php worker reads those stale pointers: cross-request use-after-free. The upload-progress multipart handler is one confirmed route. CISA KEV-listed.'
                Patches     = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
                EolBranches = @('8.1','8.0','7.4','7.3','7.2','7.1','7.0','5.6','5.5','5.4')
                AppliesSapi = 'any'
                Mitigation  = 'UPDATE — the only complete fix: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or the 7.4/8.0/8.1 source backports). Interim: session.upload_progress.enabled=0 closes ONE route to this CVE only — it MUST be set in php.ini or an FPM pool config, NOT via ini_set() or .user.ini (the multipart parser runs before any script), and workers must be restarted. On PHP 8.5, disabling fatal-error backtraces is an additional partial mitigation. Disabling upload_progress does NOT close CVE-2026-109618.'
            },
            [pscustomobject]@{
                # Added 2026-10-30: patch versions verified against Tenable
                # plugin 200464 / NVD the same day (this run's one web
                # search): 8.1.29 / 8.2.20 / 8.3.8, CVSS 3.0 9.8, CISA KEV.
                Id          = 'CVE-2024-4577'
                Title       = 'PHP-CGI argument injection — unauthenticated RCE on Windows'
                Cvss        = 9.8
                Severity    = 'Critical'
                Disclosed   = '2024-06-06'
                Affects     = 'PHP 8.1.x < 8.1.29, 8.2.x < 8.2.20, 8.3.x < 8.3.8 served via PHP-CGI on Windows (Apache); older branches were affected too but received no patches (EOL)'
                Mechanism   = 'Windows Best-Fit code-page behavior converts the 0xAD soft-hyphen into 0x2D (dash) when passing arguments to Win32 APIs. PHP-CGI then misinterprets the crafted query string as PHP command-line options (-s source disclosure, -d ini injection such as -d allow_url_include=1), yielding unauthenticated RCE or source disclosure. CISA KEV-listed; exploited in the wild (Quasar RAT / XMRig campaigns).'
                Patches     = @{ '8.3' = '8.3.8'; '8.2' = '8.2.20'; '8.1' = '8.1.29' }
                EolBranches = @('8.0','7.4','7.3','7.2','7.1','7.0','5.6','5.5','5.4')
                AppliesSapi = 'cgi'
                Mitigation  = 'Upgrade to 8.1.29 / 8.2.20 / 8.3.8 or newer. Interim: stop serving PHP through CGI (switch Apache to php-fpm via mod_proxy_fcgi), and block the trigger shapes at the web server — this module writes Apache (.htaccess) and IIS (web.config) CGI-4577 blocks via Add-PhpCgiWafRule / Add-PhpCgiIisWafRule.'
            }
        )
        $eol = @(
            [pscustomobject]@{ Branch = '8.1'; SecurityEnd = '2025-12-31'; Note = 'EOL from PHP — but a SOURCE backport for PHP2Shell (Oct 2026) exists; you must compile it or use a distro that ships it. ~884K hosts still on 8.1 or older per Oct-2026 estimates' },
            [pscustomobject]@{ Branch = '8.0'; SecurityEnd = '2023-11-26'; Note = 'EOL from PHP — source backport for PHP2Shell (Oct 2026) exists; compile it or find a distro carrying it' },
            [pscustomobject]@{ Branch = '7.4'; SecurityEnd = '2022-11-28'; Note = 'EOL from PHP — source backport for PHP2Shell (Oct 2026) exists; compile it or find a distro carrying it' },
            [pscustomobject]@{ Branch = '7.3'; SecurityEnd = '2021-12-06'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '7.2'; SecurityEnd = '2020-11-30'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '7.1'; SecurityEnd = '2019-12-01'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '7.0'; SecurityEnd = '2018-12-03'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '5.6'; SecurityEnd = '2018-12-31'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '5.5'; SecurityEnd = '2016-07-21'; Note = 'EOL' },
            [pscustomobject]@{ Branch = '5.4'; SecurityEnd = '2015-09-03'; Note = 'EOL' }
        )
        return [pscustomobject]@{ CVEs = $cves; EOL = $eol }
    } catch {
        Write-Host "[-] Get-PhpThreatTable failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ---------------------------------------------------------------------------
# php.ini hardening table. Shipped data — the settings an exposed PHP must
# carry, each with its why and its fix. Checked live per install by
# Get-PhpIniHardeningCheck (one `php -r` spawn). Test kinds:
#   bool-off | bool-on | nonempty | disablefuncs | size-le | time-range | samesite
# ---------------------------------------------------------------------------
function Get-PhpIniHardeningTable {
    try {
        return @(
            [pscustomobject]@{ Setting = 'expose_php'; Recommended = 'Off'; Severity = 'Medium'; Test = 'bool-off'; Param = '';
                Why = 'Advertises the exact PHP version in X-Powered-By headers and default error pages — free recon for an attacker.';
                Fix = 'expose_php=Off in php.ini, then restart the web SAPI.' },
            [pscustomobject]@{ Setting = 'display_errors'; Recommended = 'Off'; Severity = 'Medium'; Test = 'bool-off'; Param = '';
                Why = 'Prints file paths and stack traces to the browser on failure — information disclosure. Log instead.';
                Fix = 'display_errors=Off, log_errors=On, error_log=<writable path>.' },
            [pscustomobject]@{ Setting = 'log_errors'; Recommended = 'On'; Severity = 'Low'; Test = 'bool-on'; Param = '';
                Why = 'Without an error log, attacks and crashes are invisible — you cannot investigate what you never recorded.';
                Fix = 'log_errors=On and set error_log to a writable path.' },
            [pscustomobject]@{ Setting = 'allow_url_include'; Recommended = 'Off'; Severity = 'Critical'; Test = 'bool-off'; Param = '';
                Why = 'Lets include/require load REMOTE code — one attacker-controlled string becomes unauthenticated RCE.';
                Fix = 'allow_url_include=Off. No legitimate use survives review.' },
            [pscustomobject]@{ Setting = 'allow_url_fopen'; Recommended = 'Off'; Severity = 'Medium'; Test = 'bool-off'; Param = '';
                Why = 'Lets file functions open URLs — the SSRF and data-exfiltration primitive. Some apps need it; review first.';
                Fix = 'Off if unused. If required: pair with open_basedir and egress firewall rules.' },
            [pscustomobject]@{ Setting = 'disable_functions'; Recommended = 'exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,assert all disabled'; Severity = 'High'; Test = 'disablefuncs'; Param = '';
                Why = 'Empty means any PHP process — including an uploaded webshell — can run OS commands.';
                Fix = 'disable_functions=exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,assert (verify the app still works).' },
            [pscustomobject]@{ Setting = 'open_basedir'; Recommended = 'set (non-empty)'; Severity = 'Medium'; Test = 'nonempty'; Param = '';
                Why = "Unset lets PHP read any file the OS user can: other vhosts' configs, secrets, /etc/passwd.";
                Fix = 'open_basedir="C:\inetpub\wwwroot;C:\php\tmp" (scope to what the app needs).' },
            [pscustomobject]@{ Setting = 'session.cookie_httponly'; Recommended = '1'; Severity = 'Medium'; Test = 'bool-on'; Param = '';
                Why = 'Without HttpOnly, any XSS steals session cookies via document.cookie.';
                Fix = 'session.cookie_httponly=1.' },
            [pscustomobject]@{ Setting = 'session.cookie_secure'; Recommended = '1'; Severity = 'Medium'; Test = 'bool-on'; Param = '';
                Why = 'Without Secure, session cookies travel over plain HTTP where they can be sniffed.';
                Fix = 'session.cookie_secure=1 — HTTPS sites only.' },
            [pscustomobject]@{ Setting = 'session.use_strict_mode'; Recommended = '1'; Severity = 'Medium'; Test = 'bool-on'; Param = '';
                Why = 'Without strict mode PHP accepts attacker-chosen session IDs (session fixation).';
                Fix = 'session.use_strict_mode=1.' },
            [pscustomobject]@{ Setting = 'session.cookie_samesite'; Recommended = 'Lax or Strict'; Severity = 'Low'; Test = 'samesite'; Param = '';
                Why = 'Missing SameSite lets browsers send the session cookie on cross-site requests (CSRF assist).';
                Fix = 'session.cookie_samesite="Lax".' },
            [pscustomobject]@{ Setting = 'upload_max_filesize'; Recommended = '<= 128M'; Severity = 'Low'; Test = 'size-le'; Param = '128M';
                Why = 'Absurd limits amplify upload abuse and disk-fill attacks.';
                Fix = 'Tighten to what the app actually needs.' },
            [pscustomobject]@{ Setting = 'post_max_size'; Recommended = '<= 128M'; Severity = 'Low'; Test = 'size-le'; Param = '128M';
                Why = 'Same as upload_max_filesize — keep >= upload_max_filesize, tight to need.';
                Fix = 'Tighten to what the app actually needs.' },
            [pscustomobject]@{ Setting = 'max_execution_time'; Recommended = '1-120 s'; Severity = 'Low'; Test = 'time-range'; Param = '';
                Why = '0 = unlimited: a stuck or hijacked script never dies.';
                Fix = 'max_execution_time=60 for web SAPIs.' },
            [pscustomobject]@{ Setting = 'session.upload_progress.enabled'; Recommended = 'Off'; Severity = 'Critical'; Test = 'bool-off'; Param = '';
                Why = 'PHP2Shell uses upload_progress as one attack route: Off closes one route to CVE-2026-109619, blocks the session-file LFI-to-RCE chain on PATCHED installs too (upload_progress stays ON by default even in 8.2.35+, and a crafted PHP_SESSION_UPLOAD_PROGRESS field writes attacker content into session files), but it does NOT fix either engine bug — only the patched releases do.';
                Fix = 'session.upload_progress.enabled=Off in php.ini (or an FPM pool config — NOT via ini_set() or .user.ini: the multipart parser runs before any script), then restart the web SAPI. This is defense-in-depth, not the fix: patch is mandatory.' },
            [pscustomobject]@{ Setting = 'cgi.fix_pathinfo'; Recommended = '0'; Severity = 'High'; Test = 'equals'; Param = '0';
                Why = '1 lets an attacker append /evil.php to a real file (photo.jpg/evil.php) and have the web server execute it — the classic pathinfo RCE on FastCGI setups.';
                Fix = 'cgi.fix_pathinfo=0 (requires exact-match; verify the app does not rely on PATH_INFO).' },
            [pscustomobject]@{ Setting = 'cgi.force_redirect'; Recommended = '1'; Severity = 'High'; Test = 'equals'; Param = '1';
                Why = 'With the CGI SAPI, force_redirect=0 lets direct requests to the CGI binary bypass the web server entirely — the CVE-2012-1823 bypass class, and every CGI argument-injection bug since (including CVE-2024-4577) lands harder on it.';
                Fix = 'cgi.force_redirect=1. The web server must pass REDIRECT_STATUS — standard for Apache mod_cgi/FastCGI and IIS. If PHP is not served via CGI, this is belt-and-braces.' },
            [pscustomobject]@{ Setting = 'mail.add_x_header'; Recommended = 'Off'; Severity = 'Medium'; Test = 'bool-off'; Param = '';
                Why = "On stamps X-PHP-Script with the sending script's filesystem path onto every outgoing mail header — a path-disclosure gift to anyone who reads those headers.";
                Fix = 'mail.add_x_header=Off.' },
            [pscustomobject]@{ Setting = 'session.use_trans_sid'; Recommended = '0'; Severity = 'Medium'; Test = 'equals'; Param = '0';
                Why = '1 appends the session ID to URLs — it leaks in logs, referers, and pasted links. Session fixation and hijack assist.';
                Fix = 'session.use_trans_sid=0. Modern browsers handle cookies fine.' },
            [pscustomobject]@{ Setting = 'session.use_only_cookies'; Recommended = '1'; Severity = 'Medium'; Test = 'bool-on'; Param = '';
                Why = '0 lets the session ID ride in the URL — same leak as use_trans_sid from the other side.';
                Fix = 'session.use_only_cookies=1.' },
            [pscustomobject]@{ Setting = 'session.gc_maxlifetime'; Recommended = '<= 1440 s'; Severity = 'Medium'; Test = 'le-num'; Param = '1440';
                Why = 'Long session lifetimes stretch the window a stolen session ID stays useful.';
                Fix = 'session.gc_maxlifetime=1440 (24 min) or lower; re-auth for sensitive actions.' },
            [pscustomobject]@{ Setting = 'max_input_vars'; Recommended = '<= 1000'; Severity = 'Medium'; Test = 'le-num'; Param = '1000';
                Why = 'Very high limits amplify hash-collision DoS (crafted POST vars) and let huge parameter dumps through.';
                Fix = 'max_input_vars=1000 unless the app provably needs more.' },
            [pscustomobject]@{ Setting = 'memory_limit'; Recommended = '<= 512M'; Severity = 'Low'; Test = 'size-le'; Param = '512M';
                Why = 'Absurd memory limits (-1 = unlimited) let one request starve the box.';
                Fix = 'memory_limit=256M or tighter; raise only for known workloads. ONE exception: PHP''s official interim stopgap for CVE-2026-109618 IS memory_limit=-1 (removes the OOM trigger) — use it ONLY as a bridge to patching, paired with request-size limits and container/cgroup caps, then restore a sane limit.' },
            [pscustomobject]@{ Setting = 'zend.assertions'; Recommended = '-1 (production)'; Severity = 'Low'; Test = 'equals'; Param = '-1';
                Why = 'assert() with zend.assertions=1 executes code strings in production — a latent RCE primitive in any app that asserts on input-derived data.';
                Fix = 'zend.assertions=-1 in production (dev can use 1, never ship with it).' }
        )
    } catch {
        Write-Host "[-] Get-PhpIniHardeningTable failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function ConvertTo-PhpIniBool {
    <#
    Normalizes a php.ini boolean-ish value. Returns $true / $false / $null.
    #>
    param([string]$Raw)
    try {
        $t = $Raw.Trim().ToLower()
        if ($t -in @('1','on','true','yes'))  { return $true }
        if ($t -in @('0','off','false','no','')) { return $false }
        return $null
    } catch { return $null }
}

function ConvertFrom-PhpSize {
    <#
    Parses php.ini size shorthand ("2M", "128M", "1G", "512K", plain bytes,
    "-1" = unlimited). Returns bytes as [long], or $null on junk.
    #>
    param([string]$Raw)
    try {
        $t = $Raw.Trim().ToUpper()
        if ($t -eq '-1') { return -1 }
        $m = [regex]::Match($t, '^([\d\.]+)\s*([KMG]?)$')
        if (-not $m.Success) { return $null }
        $n = [double]$m.Groups[1].Value
        switch ($m.Groups[2].Value) {
            'K' { return [long]($n * 1KB) }
            'M' { return [long]($n * 1MB) }
            'G' { return [long]($n * 1GB) }
            default { return [long]$n }
        }
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------
function ConvertTo-PhpVersion {
    <#
    Parses "PHP 8.2.35 (cli) (built: ...)", "PHP 8.3.25RC2", "8.2.35" into
    a comparable object. Pre-release suffixes (RC, alpha, beta, dev,
    preview, incl. distro forms like "7.4.33-1ubuntu") are captured: a
    pre-release is OLDER than its own release (8.2.35RC1 < 8.2.35), and
    the CVE matcher relies on this to keep scoring RCs as vulnerable
    until the final release lands.
    #>
    param([Parameter(Mandatory=$true)][string]$Raw)
    try {
        $m = [regex]::Match($Raw, '(\d+)\.(\d+)(?:\.(\d+))?')
        if (-not $m.Success) { return $null }
        $major = [int]$m.Groups[1].Value
        $minor = [int]$m.Groups[2].Value
        $patch = 0
        if ($m.Groups[3].Success) { $patch = [int]$m.Groups[3].Value }
        # Pre-release suffix: examine the text immediately after the
        # numeric part. Handles RC1/RC2, alpha/beta/dev/preview, and
        # distro build tags ("7.4.33-1ubuntu0.22.04.1" -> pre-release
        # unknown kind; still older than the plain release).
        $preLabel = ''
        $preNum   = 0
        $rest = $Raw.Substring($m.Index + $m.Length)
        $sm = [regex]::Match($rest, '(?i)^[-_. ]?(alpha|a(?![a-z])|beta|b(?![a-z])|rc|dev|preview)\s*(\d*)')
        if ($sm.Success) {
            $preLabel = $sm.Groups[1].Value.ToLower()
            if ($preLabel -eq 'a') { $preLabel = 'alpha' }
            if ($preLabel -eq 'b') { $preLabel = 'beta' }
            if ($sm.Groups[2].Success -and $sm.Groups[2].Value -ne '') { $preNum = [int]$sm.Groups[2].Value }
        } elseif ($rest -match '(?i)^[-_](\d)') {
            # distro build tag ("-1ubuntu..."): pre-release of unknown
            # kind, definitely not the upstream final release
            $preLabel = 'distro'; $preNum = 0
        }
        return [pscustomobject]@{
            Raw    = $Raw.Trim()
            Major  = $major
            Minor  = $minor
            Patch  = $patch
            Branch = "$major.$minor"
            Tuple  = @($major, $minor, $patch)
            PreRelease = $preLabel      # '' = final release
            PreReleaseNum = $preNum
        }
    } catch {
        Write-Host "[-] ConvertTo-PhpVersion failed on '$Raw': $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-PhpPreReleaseRank {
    <#
    Ordering: dev < alpha < beta < preview < rc < distro < final release.
    Distro builds sit above rc but below the plain release: they are real
    upstream releases for a distro, but the CVE table patches reference
    upstream final versions, so scoring them as pre-release is the safe
    (vulnerable-until-proven) direction for the matcher.
    #>
    param([string]$Label)
    switch ($Label) {
        'dev'     { return 0 }
        'alpha'   { return 1 }
        'beta'    { return 2 }
        'preview' { return 3 }
        'rc'      { return 4 }
        'distro'  { return 5 }
        ''        { return 9 }   # final release beats every pre-release
        default   { return 6 }   # unknown kind: cautious, below release
    }
}

function Compare-PhpVersion {
    <#
    Returns -1 if $A older than $B, 0 if equal, 1 if newer.
    Accepts version objects from ConvertTo-PhpVersion or "x.y.z" strings.
    Pre-release rule: same numbers + a pre-release suffix on one side =>
    the pre-release side is OLDER (8.2.35RC1 < 8.2.35). RC1 < RC2 by number.
    #>
    param($A, $B)
    try {
        if ($A -is [string]) { $A = ConvertTo-PhpVersion $A }
        if ($B -is [string]) { $B = ConvertTo-PhpVersion $B }
        if ($null -eq $A -or $null -eq $B) { return $null }
        for ($i = 0; $i -lt 3; $i++) {
            if ($A.Tuple[$i] -lt $B.Tuple[$i]) { return -1 }
            if ($A.Tuple[$i] -gt $B.Tuple[$i]) { return 1 }
        }
        $ra = Get-PhpPreReleaseRank $A.PreRelease
        $rb = Get-PhpPreReleaseRank $B.PreRelease
        if ($ra -lt $rb) { return -1 }
        if ($ra -gt $rb) { return 1 }
        if ($A.PreReleaseNum -lt $B.PreReleaseNum) { return -1 }
        if ($A.PreReleaseNum -gt $B.PreReleaseNum) { return 1 }
        return 0
    } catch {
        Write-Host "[-] Compare-PhpVersion failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ---------------------------------------------------------------------------
# Vault logging (optional; never blocks the scan)
# ---------------------------------------------------------------------------
function Import-PhpShieldVault {
    try {
        if ($script:VaultLoaded) { return $true }
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $mod  = Join-Path (Split-Path -Parent $here) '12-timeline-vault\Falsum-Vault.ps1'
        if (-not (Test-Path $mod)) { $mod = Join-Path $here '..\12-timeline-vault\Falsum-Vault.ps1' }
        if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true; return $true }
        Write-Host '[!] vault module not found — findings will not be vault-logged'
        return $false
    } catch {
        Write-Host "[!] vault import failed: $($_.Exception.Message)"
        return $false
    }
}

function Write-PhpShieldVaultLog {
    param(
        [Parameter(Mandatory=$true)][string]$Summary,
        [string]$DataHash = ''
    )
    try {
        if (-not $script:VaultLoaded) { if (-not (Import-PhpShieldVault)) { return } }
        if (Get-Command Add-VaultEntry -ErrorAction SilentlyContinue) {
            Add-VaultEntry -Category 'phpshield' -Summary $Summary -DataHash $DataHash | Out-Null
            Write-Host '[+] Vault-logged.' -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] vault log skipped: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Probe runner. Every php.exe invocation on this box (php -v, --ini, -r)
# goes through here: Start-Process with a kill-timeout, stdout+stderr
# captured, and the probe KILLED if it hangs. A hung or weaponized php.exe
# used to be able to stall the entire scan forever (the `&` operator has
# no timeout); now a hung probe reports TimedOut=$true and the scan
# moves on. $TimeoutSec default 15s.
# ---------------------------------------------------------------------------
function Invoke-PhpProbe {
    <#
    Runs a php.exe probe with a hard kill-timeout. Returns
    { ExitCode, Stdout, TimedOut, Error }. Stdout merges stdout+stderr
    (extension warnings on stderr used to carry version evidence too).
    Never throws; a probe that cannot even start reports ExitCode=-1.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 15
    )
    try {
        if (-not (Test-Path $Exe)) {
            return [pscustomobject]@{ ExitCode = -1; Stdout = ''; TimedOut = $false; Error = "exe not found: $Exe" }
        }
        # Quote args that carry whitespace so the -r code block arrives
        # as a single argv entry.
        $quoted = foreach ($a in $Arguments) {
            if ($a -match '\s') { '"' + ($a -replace '"','\"') + '"' } else { $a }
        }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = ($quoted -join ' ')
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        try {
            if (-not $p.Start()) {
                return [pscustomobject]@{ ExitCode = -1; Stdout = ''; TimedOut = $false; Error = 'process start returned false' }
            }
        } catch {
            return [pscustomobject]@{ ExitCode = -1; Stdout = ''; TimedOut = $false; Error = $_.Exception.Message }
        }
        $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
        if ($timedOut) { try { $p.Kill() } catch { } }
        $out = ''; $err = ''
        try { $out = $p.StandardOutput.ReadToEnd() } catch { }
        try { $err = $p.StandardError.ReadToEnd() } catch { }
        # ReadToEnd AFTER the wait can deadlock only if the child is still
        # running; the kill above guarantees it is not (or it died on its
        # own). Kept defensive anyway.
        $code = -1
        try { $code = $p.ExitCode } catch { }
        try { $p.Dispose() } catch { }
        $combined = $out
        if (-not [string]::IsNullOrWhiteSpace($err)) { $combined = "$out`n$err" }
        if ($timedOut) {
            Write-Host "    [!] probe timed out after ${TimeoutSec}s and was killed: $Exe $($Arguments -join ' ')" -ForegroundColor Yellow
        }
        return [pscustomobject]@{
            ExitCode = $code; Stdout = $combined.Trim()
            TimedOut = $timedOut; Error = ''
        }
    } catch {
        return [pscustomobject]@{ ExitCode = -1; Stdout = ''; TimedOut = $false; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Install discovery: PATH, common stack locations, registry
# ---------------------------------------------------------------------------
function Get-PhpInstalls {
    <#
    Finds every PHP on the box. Sources, in order:
      1. PATH (Get-Command php) — flagged IsActive
      2. where.exe — EVERY php.exe on PATH, not just the first hit
      3. Common stack paths: C:\php, XAMPP, WAMP, Laragon, MAMP,
         Program Files, plus scoop / chocolatey / winget / Herd shims
      4. Registry: HKLM\SOFTWARE\PHP (+WOW6432Node) IniFilePath -> install dir
    Each entry is versioned by running php.exe -v with evidence preserved,
    and its SAPI (cli/fpm-fcgi/cgi-fcgi/...) is parsed from the same output.
    #>
    try {
        Write-Host '[*] Hunting PHP installs (PATH, common paths, registry)...'
        $found  = @{}
        $items  = @()

        # 1. PATH
        try {
            $cmd = Get-Command php -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
                $p = (Resolve-Path $cmd.Source -ErrorAction SilentlyContinue).Path
                if ($p) { $items += [pscustomobject]@{ Exe = $p; Source = 'PATH'; IsActive = $true } }
            }
        } catch { Write-Host "[!] PATH probe failed: $($_.Exception.Message)" -ForegroundColor Yellow }

        # 2. where.exe — EVERY php.exe on PATH, not just the first hit.
        # Get-Command resolves a shim's target (an app-alias entry whose
        # .Path is empty when the shim fails); where.exe lists the raw
        # candidates so a broken alias cannot hide an install.
        try {
            $w = (& where.exe php 2>$null)
            foreach ($line in @($w)) {
                try {
                    $t = $line.Trim()
                    if ($t -match '(?i)php\.exe$' -and (Test-Path $t)) {
                        $rp = Resolve-Path $t -ErrorAction SilentlyContinue
                        if ($rp) { $items += [pscustomobject]@{ Exe = $rp.Path; Source = 'where.exe'; IsActive = $false } }
                    }
                } catch { }
            }
        } catch {
            Write-Host "[!] where.exe probe failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # 3. Common paths (wildcards expand stack version dirs)
        $common = @(
            'C:\php\php.exe',
            'C:\Program Files\PHP\php.exe',
            'C:\xampp\php\php.exe',
            'C:\wamp64\bin\php\php*\php.exe',
            'C:\wamp\bin\php\php*\php.exe',
            'C:\laragon\bin\php\php-*\php.exe',
            'C:\MAMP\bin\php\php*\php.exe',
            'C:\Program Files\PHP\v*\php.exe',
            'C:\Program Files (x86)\PHP\v*\php.exe',
            'C:\tools\php*\php.exe',
            'C:\ProgramData\chocolatey\bin\php.exe',
            "$env:USERPROFILE\scoop\apps\php\current\php.exe",
            "$env:USERPROFILE\.config\herd\bin\php.exe",
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\php.exe",
            "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\*\php.exe"
        )
        foreach ($pat in $common) {
            try {
                foreach ($hit in (Resolve-Path $pat -ErrorAction SilentlyContinue)) {
                    $items += [pscustomobject]@{ Exe = $hit.Path; Source = 'common-path'; IsActive = $false }
                }
            } catch { }
        }

        # 4. Registry
        foreach ($key in @('HKLM:\SOFTWARE\PHP', 'HKLM:\SOFTWARE\WOW6432Node\PHP', 'HKCU:\SOFTWARE\PHP')) {
            try {
                if (Test-Path $key) {
                    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
                    if ($props -and $props.IniFilePath) {
                        $dir = Split-Path $props.IniFilePath -Parent
                        $exe = Join-Path $dir 'php.exe'
                        if (Test-Path $exe) {
                            $items += [pscustomobject]@{ Exe = (Resolve-Path $exe).Path; Source = 'registry'; IsActive = $false }
                        }
                    }
                }
            } catch { }
        }

        # Dedupe + version each one
        foreach ($it in $items) {
            try {
                $keyPath = $it.Exe.ToLower()
                if ($found.ContainsKey($keyPath)) { continue }
                $verOut = ''
                $ver    = $null
                $sapi   = ''
                # Timed-out/hung probe cannot stall the scan: Invoke-PhpProbe
                # kills it and reports TimedOut=$true (v1.3 fix).
                $probe = Invoke-PhpProbe -Exe $it.Exe -Arguments @('-v') -TimeoutSec 15
                $verOut = $probe.Stdout
                if ($probe.TimedOut) {
                    $verOut = "TIMED-OUT after 15s — the binary hung on '-v'. Treated as unversioned; investigate by hand."
                } elseif ($probe.Error -ne '') {
                    $verOut = "ERROR: $($probe.Error)"
                }
                if ($verOut -and $verOut -notmatch '^(TIMED-OUT|ERROR)') {
                    $first = ($verOut -split "`n" | Select-Object -First 1)
                    $ver = ConvertTo-PhpVersion $first
                    # SAPI: "PHP 8.2.35 (cli) (built: ...)" -> cli
                    $sm = [regex]::Match($first, '\((cli|fpm-fcgi|cgi-fcgi|apache2handler|litespeed|phpdbg|embed)\)')
                    if ($sm.Success) { $sapi = $sm.Groups[1].Value }
                }
                $rec = [pscustomobject]@{
                    Exe        = $it.Exe
                    Dir        = Split-Path $it.Exe -Parent
                    Source     = $it.Source
                    IsActive   = $it.IsActive
                    Sapi       = $sapi
                    Version    = $ver
                    VersionRaw = if ($ver) { $ver.Raw } else { $verOut }
                    Error      = if ($ver) { '' } else { $verOut }
                }
                $found[$keyPath] = $rec
                $tag = if ($ver) { "$($ver.Branch).$($ver.Patch)" } else { 'UNVERSIONED' }
                $sapiTag = if ($sapi) { " [$sapi]" } else { '' }
                Write-Host "    [+] $($it.Source): $($it.Exe) -> $tag$sapiTag"
            } catch {
                Write-Host "[-] failed on $($it.Exe): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        $list = @($found.Values)
        Write-Host "[*] Found $($list.Count) PHP install(s)."
        return $list
    } catch {
        Write-Host "[-] Get-PhpInstalls failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PhpIniPath {
    <#
    Returns the loaded php.ini path for an install, or '' if none.
    #>
    param([Parameter(Mandatory=$true)]$PhpInstall)
    try {
        $probe = Invoke-PhpProbe -Exe $PhpInstall.Exe -Arguments @('--ini') -TimeoutSec 15
        if ($probe.TimedOut -or $probe.Error -ne '') {
            Write-Host '    [!] --ini probe failed (timeout or start error) — no ini path resolvable' -ForegroundColor Yellow
            return ''
        }
        $m = [regex]::Match($probe.Stdout, 'Loaded Configuration File:\s+(.+)')
        if ($m.Success) {
            $p = $m.Groups[1].Value.Trim()
            if ($p -and $p -ne '(none)') { return $p }
        }
        return ''
    } catch {
        Write-Host "[-] Get-PhpIniPath failed: $($_.Exception.Message)" -ForegroundColor Yellow
        return ''
    }
}

function Get-PhpUploadProgressSetting {
    <#
    Reads session.upload_progress.enabled for an install, live via php -r
    (truth, not the ini file). ini_get on a boolean setting returns '1' for
    On and '' for Off, so we cast to (int)(bool): the answer is exactly 0
    or 1, and stray stderr lines (extension warnings) cannot corrupt it —
    we take the last clean [01] line. Returns 'On'/'Off'/'Unknown'.
    #>
    param([Parameter(Mandatory=$true)]$PhpInstall)
    try {
        $code = "echo (int)(bool)ini_get('session.upload_progress.enabled');"
        $probe = Invoke-PhpProbe -Exe $PhpInstall.Exe -Arguments @('-r', $code) -TimeoutSec 15
        if ($probe.TimedOut -or $probe.Error -ne '') { return 'Unknown' }
        $hits = @($probe.Stdout -split "`r?`n" | Where-Object { $_ -match '^[01]$' } | Select-Object -Last 1)
        if ($hits.Count -eq 1) {
            if ($hits[0] -eq '1') { return 'On' }
            return 'Off'
        }
        return 'Unknown'
    } catch {
        Write-Host "[-] Get-PhpUploadProgressSetting failed: $($_.Exception.Message)" -ForegroundColor Yellow
        return 'Unknown'
    }
}

# ---------------------------------------------------------------------------
# php.ini hardening audit — the shipped table checked live, per install
# ---------------------------------------------------------------------------
function Get-PhpIniHardeningCheck {
    <#
    Live-reads every setting in the shipped hardening table via ONE `php -r`
    spawn (setting=value lines), then evaluates each row. HONEST LIMIT,
    printed every run: `php -r` executes the CLI SAPI, which may load a
    different php.ini than the web SAPI (php-fpm / mod_php). Checks whose
    CLI defaults diverge from web best practice (display_errors,
    max_execution_time) are marked N/A on CLI installs — verify on the web
    SAPI (phpinfo page) before changing anything.
    #>
    param([Parameter(Mandatory=$true)]$PhpInstall)
    try {
        if ($null -eq $PhpInstall.Version) {
            Write-Host '    [!] skipping ini hardening: install unversioned' -ForegroundColor Yellow
            return @()
        }
        $table = Get-PhpIniHardeningTable
        if (-not $table -or $table.Count -eq 0) { return @() }
        $settings = @($table | Select-Object -ExpandProperty Setting -Unique)
        $phpList  = ($settings | ForEach-Object { "'$_'" }) -join ','
        $code = '$s=array(' + $phpList + ');foreach($s as $k){echo $k,"=",ini_get($k),"\n";}'
        $probe = Invoke-PhpProbe -Exe $PhpInstall.Exe -Arguments @('-r', $code) -TimeoutSec 20
        $out = $probe.Stdout
        if ($probe.TimedOut -or $probe.Error -ne '') {
            Write-Host '    [!] ini dump probe failed (timeout or start error) — ini hardening skipped for this install' -ForegroundColor Yellow
            return @()
        }
        $vals = @{}
        foreach ($ln in ($out -split "`r?`n")) {
            $m = [regex]::Match($ln, '^([^=]+)=(.*)$')
            if ($m.Success) { $vals[$m.Groups[1].Value.Trim()] = $m.Groups[2].Value }
        }
        # CLI-context honesty: these two diverge from web best practice on CLI
        $cliNa = @('display_errors','max_execution_time')
        $checks = @()
        foreach ($row in $table) {
            $cur = ''
            if ($vals.ContainsKey($row.Setting)) { $cur = $vals[$row.Setting] }
            if ($PhpInstall.Sapi -eq 'cli' -and $cliNa -contains $row.Setting) {
                $checks += [pscustomobject]@{
                    Setting = $row.Setting; Current = $cur; Recommended = $row.Recommended
                    Pass = $null; Verdict = 'N/A'; Severity = $row.Severity
                    Detail = 'CLI context — the CLI default differs; verify on the web SAPI (phpinfo) before changing.'
                    Why = $row.Why; Fix = $row.Fix
                }
                continue
            }
            $pass = $false
            $detail = "current='$cur'"
            switch ($row.Test) {
                'bool-off' { $pass = ((ConvertTo-PhpIniBool $cur) -eq $false) }
                'bool-on'  { $pass = ((ConvertTo-PhpIniBool $cur) -eq $true) }
                'nonempty' {
                    $pass = (-not [string]::IsNullOrWhiteSpace($cur))
                    if ($pass) { $detail = 'set' }
                }
                'disablefuncs' {
                    $disabled = @($cur -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne '' })
                    $danger = @('exec','passthru','shell_exec','system','proc_open','popen','pcntl_exec','assert')
                    $left = @($danger | Where-Object { $disabled -notcontains $_ })
                    $pass = ($left.Count -eq 0)
                    $detail = if ($pass) { "all $($danger.Count) dangerous functions disabled" } else { "STILL ENABLED: $($left -join ', ')" }
                }
                'size-le' {
                    $bytes = ConvertFrom-PhpSize $cur
                    $limit = ConvertFrom-PhpSize $row.Param
                    $pass = ($null -ne $bytes -and $null -ne $limit -and $bytes -ge 0 -and $bytes -le $limit)
                }
                'time-range' {
                    $t = 0
                    $ok = [int]::TryParse($cur.Trim(), [ref]$t)
                    $pass = ($ok -and $t -ge 1 -and $t -le 120)
                    if ($pass) { $detail = "current='${t}s'" }
                }
                'samesite' { $pass = ($cur.Trim().ToLower() -in @('lax','strict')) }
                'equals' {
                    $pass = ($cur.Trim() -eq $row.Param)
                    $detail = "current='$($cur.Trim())' expected='$($row.Param)'"
                }
                'le-num' {
                    $t = 0
                    $ok = [long]::TryParse($cur.Trim(), [ref]$t)
                    $lim = 0
                    $okLim = [long]::TryParse($row.Param, [ref]$lim)
                    $pass = ($ok -and $okLim -and $t -le $lim)
                    if ($pass) { $detail = "current='$t'" }
                }
            }
            $checks += [pscustomobject]@{
                Setting = $row.Setting; Current = $cur; Recommended = $row.Recommended
                Pass = $pass; Verdict = (if ($pass) { 'PASS' } else { 'FAIL' }); Severity = $row.Severity
                Detail = $detail; Why = $row.Why; Fix = $row.Fix
            }
        }
        $fails = @($checks | Where-Object { $_.Pass -eq $false }).Count
        $nas   = @($checks | Where-Object { $_.Verdict -eq 'N/A' }).Count
        Write-Host "    ini hardening: $($checks.Count) checks, $fails FAIL, $nas N/A (CLI context)"
        foreach ($c in ($checks | Where-Object { $_.Pass -eq $false })) {
            Write-Host "      [FAIL:$($c.Severity)] $($c.Setting) — $($c.Detail)" -ForegroundColor Red
            Write-Host "        WHY: $($c.Why)"
            Write-Host "        FIX: $($c.Fix)"
        }
        return $checks
    } catch {
        Write-Host "[-] Get-PhpIniHardeningCheck failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Docroot webshell scanner. A hardened PHP install can still serve a
# webshell someone uploaded earlier — detection without the fix is
# unfinished work (Better-Way Law), so the scanner ships with a
# quarantine function. HONEST LIMIT, printed every run: regex indicators
# catch KNOWN webshell shapes; a fully novel or encrypted payload can
# evade them, and legit code (frameworks, CMS cores) trips Medium
# indicators. REVIEW before quarantining anything.
# ---------------------------------------------------------------------------
function Get-PhpWebshellIndicatorTable {
    <#
    Shipped indicator table: regex, name, severity, why. Single-quoted
    patterns — $_ inside a single-quoted PowerShell string is literal.
    #>
    try {
        return @(
            [pscustomobject]@{ Name = 'eval() execution primitive'; Severity = 'High'; Pattern = 'eval\s*\(';
                Why = 'eval() runs a string as PHP code — the universal webshell payload executor.' },
            [pscustomobject]@{ Name = 'base64 payload decode'; Severity = 'High'; Pattern = 'base64_decode\s*\(';
                Why = 'base64_decode hides the real payload from plain-text inspection; almost every encoded webshell uses it.' },
            [pscustomobject]@{ Name = 'compressed payload decode'; Severity = 'High'; Pattern = 'gzinflate\s*\(|gzuncompress\s*\(';
                Why = 'Compressed + encoded payloads are the standard way to smuggle a full webshell past naive filters.' },
            [pscustomobject]@{ Name = 'rot13 obfuscation'; Severity = 'Medium'; Pattern = 'str_rot13\s*\(';
                Why = 'rot13 is obfuscation, not a feature — legit code rarely needs it in production.' },
            [pscustomobject]@{ Name = 'chr() string assembly'; Severity = 'High'; Pattern = 'chr\s*\(\s*\d+\s*\)(\s*\.\s*chr\s*\(\s*\d+\s*\))+';
                Why = 'Building strings from character codes hides function names (e.g. "assert") from grep-style scans.' },
            [pscustomobject]@{ Name = 'preg_replace /e modifier'; Severity = 'Critical'; Pattern = 'preg_replace\s*\([^)]*/e';
                Why = 'The /e modifier evaluates the replacement as code — classic unauthenticated RCE in old PHP apps.' },
            [pscustomobject]@{ Name = 'assert() code execution'; Severity = 'High'; Pattern = 'assert\s*\(';
                Why = 'assert() executes string arguments as PHP code when zend.assertions=1 (see ini table).' },
            [pscustomobject]@{ Name = 'create_function()'; Severity = 'High'; Pattern = 'create_function\s*\(';
                Why = 'Deprecated RCE primitive: compiles a string into a function at runtime. No modern app should call it.' },
            [pscustomobject]@{ Name = 'OS command execution'; Severity = 'High'; Pattern = 'shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|pcntl_exec\s*\(';
                Why = 'Any of these inside a web file means PHP can run OS commands — the webshell payoff.' },
            [pscustomobject]@{ Name = 'file upload primitive'; Severity = 'Medium'; Pattern = 'move_uploaded_file\s*\(';
                Why = 'Legit in upload handlers; webshells also use it. Corroborate before acting.' },
            [pscustomobject]@{ Name = 'file write fed by request input'; Severity = 'High'; Pattern = 'file_put_contents\s*\([^)]*\$_';
                Why = 'Writing request-supplied data to a file is the drop-a-webshell primitive.' },
            [pscustomobject]@{ Name = 'dynamic call on request input'; Severity = 'Critical'; Pattern = '(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\s*\[[^\]]+\]\s*\(';
                Why = 'Calls a function named by the attacker (e.g. $_GET["x"]($_GET["y"])) — the textbook backdoor shape.' }
        )
    } catch {
        Write-Host "[-] Get-PhpWebshellIndicatorTable failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Find-PhpSuspiciousFiles {
    <#
    Scans a docroot for PHP files matching the webshell indicator table.
    Returns hit objects: File, Sha256, Line, Indicator, Severity, Snippet.
    Per-file try/catch; unreadable or oversized files are skipped and
    counted, never fatal.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$DocRoot,
        [string[]]$Extensions = @('.php','.phtml','.phar','.inc'),
        [int]$MaxFileKB = 512,
        [int]$MaxHitsPerFile = 25
    )
    try {
        if (-not (Test-Path $DocRoot)) {
            Write-Host "[-] docroot not found: $DocRoot" -ForegroundColor Red
            return @()
        }
        $table = Get-PhpWebshellIndicatorTable
        if (-not $table -or $table.Count -eq 0) { return @() }
        Write-Host "[*] Webshell scan of $DocRoot ($($table.Count) indicators, $($Extensions -join ',') files)" -ForegroundColor Cyan
        $files = @(Get-ChildItem -Path $DocRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $Extensions -contains $_.Extension.ToLower() })
        Write-Host "    PHP files found: $($files.Count)"
        $hits = @()
        $skipped = 0
        $i = 0
        foreach ($f in $files) {
            $i++
            if ($i % 200 -eq 0) { Write-Host "    ...$i/$($files.Count)" }
            try {
                if ($f.Length -gt ($MaxFileKB * 1KB)) { $skipped++; continue }
                $lines = @(Get-Content -Path $f.FullName -ErrorAction Stop)
                $fileHits = 0
                $hash = ''
                for ($ln = 0; $ln -lt $lines.Count; $ln++) {
                    if ($fileHits -ge $MaxHitsPerFile) { break }
                    foreach ($ind in $table) {
                        if ($lines[$ln] -match $ind.Pattern) {
                            if ([string]::IsNullOrEmpty($hash)) {
                                $hash = (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                            }
                            $snip = $lines[$ln].Trim()
                            if ($snip.Length -gt 160) { $snip = $snip.Substring(0, 160) + '...' }
                            $hits += [pscustomobject]@{
                                File = $f.FullName; Sha256 = $hash
                                Line = ($ln + 1); Indicator = $ind.Name
                                Severity = $ind.Severity; Snippet = $snip
                                Why = $ind.Why
                            }
                            $fileHits++
                            break
                        }
                    }
                }
            } catch {
                $skipped++
            }
        }
        $crit = @($hits | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high = @($hits | Where-Object { $_.Severity -eq 'High' }).Count
        Write-Host "    hits: $($hits.Count) (Critical: $crit, High: $high) across $(@($hits | Select-Object -ExpandProperty File -Unique).Count) files; skipped: $skipped" -ForegroundColor $(if ($crit -gt 0) { 'Red' } elseif ($high -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host '    HONEST LIMIT: indicators match known shapes; novel/encrypted payloads can evade. REVIEW before quarantining.' -ForegroundColor Yellow
        return $hits
    } catch {
        Write-Host "[-] Find-PhpSuspiciousFiles failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Move-PhpSuspiciousFileToQuarantine {
    <#
    Better-Way fix for the scanner: renames the file to .suspect inside a
    quarantine dir, writes a SHA-256 manifest, vault-logs the action.
    The original path is recorded so the move is reversible.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$QuarantineDir = (Join-Path (Get-Location) 'php-quarantine'),
        [string]$Reason = 'webshell indicator match'
    )
    try {
        if (-not (Test-Path $Path)) {
            Write-Host "[-] file not found: $Path" -ForegroundColor Red
            return $null
        }
        if (-not (Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null }
        $hash = (Get-FileHash $Path -Algorithm SHA256).Hash
        $base = [System.IO.Path]::GetFileName($Path)
        $dest = Join-Path $QuarantineDir ("$base.$((Get-Date).ToString('yyyyMMdd-HHmmss')).suspect")
        if ($PSCmdlet.ShouldProcess($Path, "quarantine to $dest")) {
            Move-Item -Path $Path -Destination $dest -Force
            $manifest = Join-Path $QuarantineDir 'quarantine-manifest.json'
            $entry = [pscustomobject]@{
                OriginalPath = $Path; QuarantinedTo = $dest
                Sha256 = $hash; Reason = $Reason
                QuarantinedUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
            $all = @()
            if (Test-Path $manifest) {
                try { $all = @(Get-Content $manifest -Raw | ConvertFrom-Json) } catch { $all = @() }
            }
            $all += $entry
            $all | ConvertTo-Json -Depth 4 | Set-Content $manifest -Encoding UTF8
            Write-PhpShieldVaultLog -Summary "Quarantined suspicious PHP: $base (SHA-256 $hash)" -DataHash $hash
            Write-Host "[+] Quarantined: $base -> $dest" -ForegroundColor Green
            Write-Host "    SHA-256 $hash — reversible: move the .suspect file back to restore."
            return $entry
        }
        return $null
    } catch {
        Write-Host "[-] Move-PhpSuspiciousFileToQuarantine failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ---------------------------------------------------------------------------
# CVE matching — the "say exactly why" engine
# ---------------------------------------------------------------------------
function Test-PhpCveMatch {
    <#
    Matches one versioned install against the shipped CVE + EOL tables.
    Returns an array of finding objects (empty = not vulnerable to anything
    shipped). Each finding carries the exact why: CVE id, CVSS, the affected
    range, and the patch release (or the EOL truth when there is no patch).
    #>
    param(
        [Parameter(Mandatory=$true)]$PhpInstall,
        $ThreatTable = $null
    )
    try {
        if ($null -eq $ThreatTable) { $ThreatTable = Get-PhpThreatTable }
        if ($null -eq $PhpInstall.Version) {
            return @([pscustomobject]@{
                Install  = $PhpInstall.Exe; Id = 'UNKNOWN-VERSION'; Severity = 'Medium'
                Why      = 'php.exe would not run or its version string did not parse — could not rule out PHP2Shell. Investigate manually.'
                Fix      = 'Re-run php -v by hand; if the binary is corrupt, reinstall PHP.'
                Evidence = $PhpInstall.VersionRaw
            })
        }
        $v      = $PhpInstall.Version
        $finds  = @()
        foreach ($cve in $ThreatTable.CVEs) {
            try {
                # SAPI-scoped CVEs (e.g. CVE-2024-4577 = CGI only): say
                # exactly which deployment shape is exposed, so a CLI-only
                # install does not read like a web RCE.
                $sapiNote = ''
                if ($cve.AppliesSapi -eq 'cgi') {
                    $sapi = [string]$PhpInstall.Sapi
                    if ($sapi -eq 'cgi-fcgi') {
                        $sapiNote = ' This install reports SAPI cgi-fcgi — it IS the CGI attack surface.'
                    } elseif ($sapi -ne '') {
                        $sapiNote = " This install reports SAPI '$sapi', not CGI — the exposure applies wherever php-cgi.exe serves the web; check the FastCGI registrations in this report."
                    } else {
                        $sapiNote = ' Exposure applies where PHP-CGI serves the web on Windows — check the FastCGI registrations in this report.'
                    }
                }
                if ($cve.Patches.ContainsKey($v.Branch)) {
                    $patched = ConvertTo-PhpVersion $cve.Patches[$v.Branch]
                    $cmp = Compare-PhpVersion $v.Raw $patched.Raw
                    if ($cmp -lt 0) {
                        $finds += [pscustomobject]@{
                            Install  = $PhpInstall.Exe
                            Id       = $cve.Id
                            Severity = $cve.Severity
                            Cvss     = $cve.Cvss
                            Why      = "$($cve.Title). Branch $($v.Branch) is patched only at $($cve.Patches[$v.Branch]) and this box runs $($v.Branch).$($v.Patch), which is OLDER. Disclosed $($cve.Disclosed). Affects: $($cve.Affects).$sapiNote"
                            Fix      = "Upgrade to PHP $($cve.Patches[$v.Branch]) or newer on the $($v.Branch) branch (or the newest stable branch). Interim: $($cve.Mitigation)"
                            Evidence = "php -v -> $($v.Raw) | mechanism: $($cve.Mechanism)"
                        }
                    }
                } elseif ($cve.EolBranches -contains $v.Branch -or ($v.Major -lt 8) -or ($v.Major -eq 8 -and $v.Minor -lt 2)) {
                    $eolRow = $ThreatTable.EOL | Where-Object { $_.Branch -eq $v.Branch } | Select-Object -First 1
                    $eolNote = if ($eolRow) { "Security support ended $($eolRow.SecurityEnd). $($eolRow.Note)" } else { 'End-of-life branch.' }
                    $backportNote = ''
                    if ($v.Branch -in @('7.4','8.0','8.1')) {
                        $backportNote = ' (PHP published a source backport for 7.4/8.0/8.1 for PHP2Shell in Oct 2026 — it exists, but it is NOT an official release: compile it or use a distro that backported it.)'
                    }
                    $finds += [pscustomobject]@{
                        Install  = $PhpInstall.Exe
                        Id       = $cve.Id
                        Severity = 'Critical'
                        Cvss     = $cve.Cvss
                        Why      = "$($cve.Title). Branch $($v.Branch) is END-OF-LIFE: $eolNote$backportNote There is NO official patched $($v.Branch).x release — every stock $($v.Branch).x ever released is vulnerable. Disclosed $($cve.Disclosed). Affects: $($cve.Affects).$sapiNote"
                        Fix      = "Upgrade to a supported branch (8.4+). There is no patched $($v.Branch).x — mitigation is mandatory in the meantime: $($cve.Mitigation)"
                        Evidence = "php -v -> $($v.Raw) | mechanism: $($cve.Mechanism)"
                    }
                } else {
                    # Newer branch than the table knows (e.g. a future 8.6+): assume patched, flag for review
                    $finds += [pscustomobject]@{
                        Install  = $PhpInstall.Exe
                        Id       = "$($cve.Id)-UNVERIFIED-BRANCH"
                        Severity = 'Low'
                        Why      = "Branch $($v.Branch) is newer than the shipped CVE table (covers through 8.5). Assumed patched, but VERIFY against the current PHP security releases."
                        Fix      = 'Check php.net security announcements for this branch.'
                        Evidence = "php -v -> $($v.Raw)"
                    }
                }
            } catch {
                Write-Host "[-] CVE match failed for $($cve.Id): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        return $finds
    } catch {
        Write-Host "[-] Test-PhpCveMatch failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Memory-exposure risk (pure logic — offline testable). CVE-2026-109618 can
# disclose freed worker memory to the client: on a host that ran an
# UNPATCHED PHP, assume session keys, passwords, API keys and TLS private
# keys that lived in worker memory may have leaked. This returns what to
# do about it, so a vulnerable-PHP finding ships the rotation plan with
# the patch plan instead of just the patch plan (Better-Way Law).
# ---------------------------------------------------------------------------
function Test-PhpMemoryExposureRisk {
    <#
    Pure classifier over a ConvertTo-PhpVersion object.
    Verdicts:
      exposed        — ran unpatched: assume worker-memory secrets leaked; rotate.
      covered        — patched release or newer: no engine-bug exposure window.
      backport-only  — 7.4/8.0/8.1: PHP published source backports; unless the
                       binary was built from them, treat as exposed.
    #>
    param($Version)
    try {
        $patches = @{ '8.5' = '8.5.12'; '8.4' = '8.4.27'; '8.3' = '8.3.36'; '8.2' = '8.2.35' }
        if ($null -eq $Version) {
            return [pscustomobject]@{ Verdict = 'unknown'; Detail = 'Version unknown — could not rule out exposure. Identify the binary by hand.' }
        }
        $branch = $Version.Branch
        if ($patches.ContainsKey($branch)) {
            $pv  = ConvertTo-PhpVersion $patches[$branch]
            $cmp = Compare-PhpVersion $Version.Raw $pv.Raw
            if ($cmp -lt 0) {
                return [pscustomobject]@{
                    Verdict = 'exposed'
                    Detail  = "PHP $($Version.Raw) predates the PHP2Shell patch ($($patches[$branch])). CVE-2026-109618 discloses freed worker memory — assume session keys, passwords, API keys and TLS private keys in worker memory may have leaked. Patch, restart workers, then ROTATE those secrets."
                }
            }
            return [pscustomobject]@{ Verdict = 'covered'; Detail = "PHP $($Version.Raw) is patched against PHP2Shell — no engine-bug memory-exposure window. (Keep session.upload_progress.enabled=Off anyway: patched PHP still ships it ON by default, and it feeds the post-patch session-file LFI-to-RCE chain.)" }
        }
        if ($branch -in @('7.4','8.0','8.1')) {
            return [pscustomobject]@{
                Verdict = 'backport-only'
                Detail  = "Branch $branch is EOL; PHP published a source backport for PHP2Shell in Oct 2026. If this binary was NOT built from it, treat as EXPOSED: patch or compile the backport, restart workers, then rotate session keys, app secrets, and any credentials/TLS keys in worker memory."
            }
        }
        if ($Version.Major -eq 8 -and $Version.Minor -gt 5) {
            return [pscustomobject]@{ Verdict = 'covered'; Detail = "Branch $branch is newer than the shipped table — presumed to carry the PHP2Shell fix; verify against php.net security announcements." }
        }
        return [pscustomobject]@{
            Verdict = 'exposed'
            Detail  = "Branch $branch has no patched release at all. Treat as EXPOSED: CVE-2026-109618 can disclose freed worker memory on every unpatched version since 5.4.0. Upgrade to a supported branch, restart workers, then rotate session keys, app secrets, and any credentials/TLS keys in worker memory."
        }
    } catch {
        Write-Host "[-] Test-PhpMemoryExposureRisk failed: $($_.Exception.Message)" -ForegroundColor Red
        return [pscustomobject]@{ Verdict = 'unknown'; Detail = 'Classifier error — could not rule out exposure. Investigate manually.' }
    }
}

function Test-PhpInstalls {
    <#
    Full scan: discover installs, CVE-match each, read upload_progress state,
    and roll everything into one report object. Prints a plain-language
    verdict per install.
    #>
    try {
        Write-Host "`n=== PHP Shield scan ===" -ForegroundColor Cyan
        $table    = Get-PhpThreatTable
        $installs = Get-PhpInstalls
        $results  = @()
        foreach ($inst in $installs) {
            try {
                Write-Host "`n[*] Assessing: $($inst.Exe)"
                $findings = @(Test-PhpCveMatch -PhpInstall $inst -ThreatTable $table)
                $up = 'Unknown'
                $hard = @()
                $hardFails = 0
                if ($inst.Version) {
                    $up = Get-PhpUploadProgressSetting -PhpInstall $inst
                    $hard = @(Get-PhpIniHardeningCheck -PhpInstall $inst)
                    $hardFails = @($hard | Where-Object { $_.Pass -eq $false }).Count
                }
                $vuln = ($findings | Where-Object { $_.Severity -in @('Critical','High') }).Count -gt 0
                $worst = 'OK'
                if ($findings | Where-Object { $_.Severity -eq 'Critical' }) { $worst = 'CRITICAL' }
                elseif ($findings | Where-Object { $_.Severity -eq 'High' }) { $worst = 'HIGH' }
                elseif ($findings.Count -gt 0) { $worst = 'REVIEW' }
                $color = 'Green'; if ($worst -eq 'CRITICAL') { $color = 'Red' } elseif ($worst -ne 'OK') { $color = 'Yellow' }
                $verLabel = if ($inst.Version) {
                    "$($inst.Version.Branch).$($inst.Version.Patch)" + $(if ($inst.Version.PreRelease) { " $($inst.Version.PreRelease.ToUpper())$($inst.Version.PreReleaseNum)" } else { '' })
                } else { 'unversioned' }
                $sapiLabel = if ($inst.Sapi) { $inst.Sapi } else { 'sapi?' }
                Write-Host "    Version: $verLabel [$sapiLabel] | upload_progress: $up | ini-hardening fails: $hardFails | Verdict: $worst" -ForegroundColor $color
                foreach ($f in $findings) {
                    Write-Host "      [$($f.Severity)] $($f.Id)" -ForegroundColor $color
                    Write-Host "        WHY: $($f.Why)"
                    Write-Host "        FIX: $($f.Fix)"
                }
                $mx = Test-PhpMemoryExposureRisk -Version $inst.Version
                if ($mx.Verdict -in @('exposed','backport-only')) {
                    Write-Host "      [MEMORY-EXPOSURE: $($mx.Verdict.ToUpper())] $($mx.Detail)" -ForegroundColor Red
                }
                $results += [pscustomobject]@{
                    Install        = $inst.Exe
                    Source         = $inst.Source
                    IsActive       = $inst.IsActive
                    Sapi           = $inst.Sapi
                    Version        = $verLabel
                    UploadProgress = $up
                    IniHardening   = $hard
                    IniHardeningFails = $hardFails
                    Verdict        = $worst
                    Vulnerable     = $vuln
                    Findings       = $findings
                    MemoryExposure = $mx.Verdict
                    MemoryExposureDetail = $mx.Detail
                    ScannedUtc     = (Get-Date).ToUniversalTime().ToString('o')
                }
            } catch {
                Write-Host "[-] assessment failed for $($inst.Exe): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Write-Host "`n[*] Scan complete: $($results.Count) install(s), $(($results | Where-Object { $_.Vulnerable }).Count) vulnerable."
        return $results
    } catch {
        Write-Host "[-] Test-PhpInstalls failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# IIS web bindings — which PHP installs actually serve the web (read-only)
# ---------------------------------------------------------------------------
function Get-PhpWebBindings {
    <#
    Reads IIS applicationHost.config (READ-ONLY — never writes) and lists
    every FastCGI registration pointing at php-cgi.exe, plus whether the
    global handler mappings route *.php through FastCgiModule. Each
    registration is matched back to a discovered PHP install by directory.

    Why this exists: a PHP that serves the web is the one PHP2Shell can
    reach. A CLI-only install on the same box is lower risk. Returns @()
    cleanly when IIS is absent. Reading the config usually needs admin;
    the function says so plainly instead of failing cryptically.
    #>
    try {
        Write-Host '[*] Checking IIS FastCGI registrations for php-cgi.exe...'
        $cfg = Join-Path $env:WINDIR 'System32\inetsrv\config\applicationHost.config'
        if (-not (Test-Path $cfg)) {
            Write-Host '    [=] No IIS applicationHost.config — IIS not installed/configured.'
            return @()
        }
        try {
            $xml = [xml](Get-Content $cfg -Raw -ErrorAction Stop)
        } catch {
            Write-Host '    [-] Could not read applicationHost.config (usually needs Administrator). Run elevated to map web bindings.' -ForegroundColor Yellow
            return @()
        }
        $regs = @()
        $fastCgi = $xml.configuration.'system.webServer'.fastCgi
        if ($fastCgi) {
            foreach ($app in @($fastCgi.application)) {
                try {
                    $fp = [string]$app.fullPath
                    if ($fp -match '(?i)php-cgi\.exe$') {
                        $regs += [pscustomobject]@{ PhpCgi = $fp; Arguments = [string]$app.arguments }
                    }
                } catch { }
            }
        }
        $phpHandler = $false
        try {
            $handlers = $xml.configuration.'system.webServer'.handlers
            if ($handlers) {
                foreach ($h in @($handlers.add)) {
                    if ([string]$h.path -eq '*.php' -and [string]$h.modules -match 'FastCgiModule') { $phpHandler = $true }
                }
            }
        } catch { }
        $installs = @()
        try { $installs = @(Get-PhpInstalls) } catch { }
        $out = @()
        foreach ($r in $regs) {
            $dir = ''
            try { $dir = [IO.Path]::GetDirectoryName($r.PhpCgi) } catch { }
            $match = ''
            foreach ($i in $installs) {
                if ($i.Dir -and $dir -and ($i.Dir.TrimEnd('\') -ieq $dir.TrimEnd('\'))) { $match = $i.Exe; break }
            }
            $out += [pscustomobject]@{
                PhpCgiPath     = $r.PhpCgi
                Arguments      = $r.Arguments
                InstallDir     = $dir
                MatchedInstall = $match
                HandlerMapsPhp = $phpHandler
                ConfigFile     = $cfg
            }
        }
        if ($out.Count -eq 0) {
            Write-Host '    [=] No php-cgi.exe FastCGI registrations found.'
        } else {
            Write-Host "    [+] $($out.Count) php-cgi FastCGI registration(s):"
            foreach ($o in $out) {
                $m = if ($o.MatchedInstall) { "matches install: $($o.MatchedInstall)" } else { 'no discovered install in that dir — investigate' }
                Write-Host "      $($o.PhpCgiPath) — $m — *.php handler: $($o.HandlerMapsPhp)"
            }
        }
        return $out
    } catch {
        Write-Host "[-] Get-PhpWebBindings failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Live exposure: running PHP workers, Apache bindings, recent docroot
# changes. Discovery tells you what COULD run; these tell you what IS
# running and what just changed — the PHP PHP2Shell can actually reach.
# ---------------------------------------------------------------------------
function Get-PhpFpmProcesses {
    <#
    Lists running php-fpm.exe / php-cgi.exe workers with PID, path, start
    time, and the discovered install they belong to. A PHP that is RUNNING
    is serving something — that is the install PHP2Shell reaches first.
    A running php-cgi with no discovered install in its dir is flagged
    for manual investigation (shadow copy, portable install, or a binary
    discovery missed).
    #>
    try {
        Write-Host '[*] Looking for running PHP workers (php-fpm / php-cgi)...'
        $procs = @(Get-Process -Name 'php-fpm','php-cgi','php' -ErrorAction SilentlyContinue)
        if ($procs.Count -eq 0) {
            Write-Host '    [=] No running php-fpm/php-cgi workers.'
            return @()
        }
        $installs = @()
        try { $installs = @(Get-PhpInstalls) } catch { }
        $out = @()
        foreach ($p in $procs) {
            try {
                $path = ''
                try { $path = $p.Path } catch { }
                $dir = ''
                if ($path) { try { $dir = [IO.Path]::GetDirectoryName($path) } catch { } }
                $match = ''
                foreach ($i in $installs) {
                    if ($i.Dir -and $dir -and ($i.Dir.TrimEnd('\') -ieq $dir.TrimEnd('\'))) { $match = $i.Exe; break }
                }
                $started = ''
                try { $started = $p.StartTime.ToUniversalTime().ToString('o') } catch { }
                $out += [pscustomobject]@{
                    ProcessName  = $p.ProcessName
                    Pid          = $p.Id
                    Path         = $path
                    Dir          = $dir
                    StartTimeUtc = $started
                    MatchedInstall = $match
                    ShadowCopy   = (($match -eq '') -and ($path -ne ''))
                }
            } catch {
                Write-Host "[-] process row failed for PID $($p.Id): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        $shadow = @($out | Where-Object { $_.ShadowCopy }).Count
        Write-Host "    [+] $($out.Count) PHP worker process(es); $shadow with no discovered install (shadow)."
        foreach ($o in ($out | Where-Object { $_.ShadowCopy })) {
            Write-Host "      [SHADOW] PID $($o.Pid): $($o.Path) — investigate by hand" -ForegroundColor Red
        }
        return $out
    } catch {
        Write-Host "[-] Get-PhpFpmProcesses failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-ApachePhpBindings {
    <#
    Reads httpd.conf (+ conf.d / conf/extra includes) for PHP wiring:
      - LoadModule php*_module ...php*.dll        (mod_php)
      - ProxyPassMatch ...\.php$ fcgi://...       (php-fpm over TCP/socket)
      - SetHandler proxy:fcgi://... / "proxy:fcgi://..." inside
        <FilesMatch \.php$>                        (php-fpm via SetHandler)
      - AddHandler application/x-httpd-php .php    (mod_php handler form)
    READ-ONLY. Returns rows with ConfigFile, Kind, Detail, and the
    discovered install matched by directory. Skipped cleanly when no
    httpd.conf is found. DocumentRoot rows are surfaced too — the docroot
    is what Find-PhpSuspiciousFiles should sweep.
    #>
    try {
        Write-Host '[*] Checking Apache httpd.conf for PHP bindings...'
        $confPatterns = @(
            'C:\Apache24\conf\httpd.conf',
            'C:\xampp\apache\conf\httpd.conf',
            'C:\wamp64\bin\apache\apache*\conf\httpd.conf',
            'C:\wamp\bin\apache\apache*\conf\httpd.conf',
            'C:\laragon\bin\apache\httpd-*\conf\httpd.conf',
            'C:\Apache*\conf\httpd.conf'
        )
        $confs = @()
        foreach ($pat in $confPatterns) {
            foreach ($hit in (Resolve-Path $pat -ErrorAction SilentlyContinue)) {
                $confs += $hit.Path
            }
        }
        $confs = @($confs | Select-Object -Unique)
        if ($confs.Count -eq 0) {
            Write-Host '    [=] No httpd.conf found — Apache not installed/configured.'
            return @()
        }
        $installs = @()
        try { $installs = @(Get-PhpInstalls) } catch { }
        $out = @()
        foreach ($cfg in $confs) {
            try {
                $lines = @(Get-Content $cfg -ErrorAction Stop)
                # Include / IncludeOptional conf.d-style files
                $includes = @()
                foreach ($ln in $lines) {
                    $m = [regex]::Match($ln, '(?i)^\s*Include(Optional)?\s+"?([^"]+)"?\s*$')
                    if ($m.Success) {
                        $inc = $m.Groups[2].Value
                        if ($inc -notmatch '^[A-Za-z]:\\' -and $inc -notmatch '^/') {
                            $inc = Join-Path (Split-Path $cfg -Parent) $inc
                        }
                        $includes += $inc
                    }
                }
                $allFiles = @($cfg)
                foreach ($inc in $includes) {
                    try { foreach ($h in (Resolve-Path $inc -ErrorAction SilentlyContinue)) { $allFiles += $h.Path } } catch { }
                }
                $allFiles = @($allFiles | Select-Object -Unique)
                foreach ($f in $allFiles) {
                    try {
                        $flines = @(Get-Content $f -ErrorAction Stop)
                        $lnNo = 0
                        foreach ($ln in $flines) {
                            $lnNo++
                            $t = $ln.Trim()
                            if ($t -eq '' -or $t.StartsWith('#')) { continue }
                            $kind = ''; $detail = ''
                            $m1 = [regex]::Match($t, '(?i)^LoadModule\s+php\S*_module\s+(\S+)')
                            if ($m1.Success) { $kind = 'mod_php'; $detail = $m1.Groups[1].Value }
                            # v1.5: the old pattern demanded "php$" before the
                            # target, but real configs are
                            #   ProxyPassMatch "^/(.*\.php(/.*)?)$" "fcgi://localhost:9000/..."
                            # so the most common php-fpm wiring was silently
                            # missed. Parse the two arguments and treat it as
                            # an FPM binding when the source pattern or target
                            # names PHP / FastCGI.
                            $m2 = [regex]::Match($t, '(?i)^ProxyPassMatch\s+(\S+)\s+(\S+)')
                            if ($m2.Success -and ($m2.Groups[1].Value + ' ' + $m2.Groups[2].Value) -match '(?i)\.php|fcgi://|php-fpm') {
                                $kind = 'php-fpm-proxypass'; $detail = $m2.Groups[2].Value
                            }
                            $m3 = [regex]::Match($t, '(?i)^SetHandler\s+(proxy:fcgi://\S+)')
                            if ($m3.Success -and $kind -eq '') { $kind = 'php-fpm-sethandler'; $detail = $m3.Groups[1].Value }
                            $m4 = [regex]::Match($t, '(?i)^AddHandler\s+application/x-httpd-php\s+(.*)')
                            if ($m4.Success -and $kind -eq '') { $kind = 'mod_php-addhandler'; $detail = $m4.Groups[1].Value.Trim() }
                            $m5 = [regex]::Match($t, '(?i)^DocumentRoot\s+"?([^"]+)"?')
                            if ($m5.Success -and $kind -eq '') { $kind = 'document-root'; $detail = $m5.Groups[1].Value.Trim() }
                            if ($kind -ne '') {
                                # Match a binary dir when the detail names one
                                $match = ''
                                $bd = [regex]::Match($detail, '(?i)^([A-Za-z]:\\[^"]*?)(?:php-cgi|php-fpm|php\d?)?\.?(dll|exe)?$')
                                $candDir = ''
                                if ($bd.Success) {
                                    $candDir = $bd.Groups[1].Value.TrimEnd('\')
                                    if (-not (Test-Path $candDir)) { $candDir = '' }
                                }
                                if ($candDir -eq '') {
                                    $dirGuess = [regex]::Match($detail, '(?i)([A-Za-z]:\\[^"]*\\php[^"\\]*)')
                                    if ($dirGuess.Success -and (Test-Path $dirGuess.Groups[1].Value)) {
                                        $candDir = $dirGuess.Groups[1].Value.TrimEnd('\')
                                    }
                                }
                                foreach ($i in $installs) {
                                    if ($i.Dir -and $candDir -and ($i.Dir.TrimEnd('\') -ieq $candDir.TrimEnd('\'))) { $match = $i.Exe; break }
                                }
                                $out += [pscustomobject]@{
                                    ConfigFile = $f; Line = $lnNo; Kind = $kind
                                    Detail = $detail; MatchedInstall = $match
                                }
                            }
                        }
                    } catch {
                        Write-Host "    [!] could not read $f : $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "    [!] could not parse $cfg : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        if ($out.Count -eq 0) {
            Write-Host '    [=] httpd.conf found but no PHP wiring detected.'
        } else {
            Write-Host "    [+] $($out.Count) Apache PHP binding row(s):"
            foreach ($o in $out) {
                $mm = if ($o.MatchedInstall) { "matches: $($o.MatchedInstall)" } else { '' }
                Write-Host "      [$($o.Kind)] $($o.Detail) $mm"
            }
        }
        return $out
    } catch {
        Write-Host "[-] Get-ApachePhpBindings failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# FPM pool override audit. php.ini is not the last word: php-fpm pool
# files support php_admin_value[session.upload_progress.enabled]=On,
# which RE-ARMS the PHP2Shell trigger even when php.ini says Off.
# v1.5: this audit reads every pool conf it can find, extracts the
# php_admin_value / php_flag / php_value directives, and judges each
# against the SAME shipped hardening table the ini audit uses — same
# test kinds, same recommendations. Read-only. HONEST LIMIT: an override
# applies to one pool, not the whole install; the report names the pool
# file and line so the fix is exact. Pools can only be fixed by editing
# the conf + restarting php-fpm, so the report ships the exact edit —
# Better-Way Law, without touching a running service for you.
# ---------------------------------------------------------------------------
function ConvertFrom-FpmPoolOverrideLine {
    <#
    Pure parser: "php_admin_value[session.upload_progress.enabled] = On"
    -> { Setting, Value, Directive, Raw }. Returns $null for non-directive
    lines (comments, section headers, plain pool settings). Case preserved
    on the setting name; value trimmed.
    #>
    param([string]$Line)
    try {
        $t = $Line.Trim()
        if ($t -eq '' -or $t.StartsWith('#') -or $t.StartsWith(';')) { return $null }
        $m = [regex]::Match($t, '(?i)^php_(admin_value|admin_flag|flag|value)\s*\[\s*([^\]]+?)\s*\]\s*=\s*(.+?)\s*$')
        if (-not $m.Success) { return $null }
        return [pscustomobject]@{
            Setting   = $m.Groups[2].Value.Trim()
            Value     = $m.Groups[3].Value.Trim()
            Directive = ('php_' + $m.Groups[1].Value.ToLower())
            Raw       = $t
        }
    } catch { return $null }
}

function Test-FpmPoolOverrideVerdict {
    <#
    Pure classifier: judges one pool override against a hardening-table
    row (same Test kinds as Get-PhpIniHardeningCheck). Returns
      'weakens' — the override loosens the setting vs the recommendation
      'aligns'  — the override matches the recommendation
      'unknown' — the setting is not in the shipped table (never guessed)
    Why table rows instead of magic: the shipped table is the one source
    of truth for what "hardened" means.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Setting,
        [Parameter(Mandatory=$true)][string]$Value,
        $Table = $null
    )
    try {
        if ($null -eq $Table) { $Table = Get-PhpIniHardeningTable }
        $row = @($Table | Where-Object { $_.Setting -ieq $Setting }) | Select-Object -First 1
        if ($null -eq $row) { return 'unknown' }
        switch ($row.Test) {
            'bool-off' {
                $b = ConvertTo-PhpIniBool $Value
                if ($null -eq $b) { return 'unknown' }
                if ($b) { return 'weakens' } else { return 'aligns' }
            }
            'bool-on' {
                $b = ConvertTo-PhpIniBool $Value
                if ($null -eq $b) { return 'unknown' }
                if ($b) { return 'aligns' } else { return 'weakens' }
            }
            'equals' {
                if ($Value.Trim() -eq $row.Param) { return 'aligns' } else { return 'weakens' }
            }
            'nonempty' {
                if ([string]::IsNullOrWhiteSpace($Value)) { return 'weakens' } else { return 'aligns' }
            }
            'disablefuncs' {
                $disabled = @($Value -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne '' })
                $danger = @('exec','passthru','shell_exec','system','proc_open','popen','pcntl_exec','assert')
                $left = @($danger | Where-Object { $disabled -notcontains $_ })
                if ($left.Count -eq 0) { return 'aligns' } else { return 'weakens' }
            }
            'size-le' {
                $bytes = ConvertFrom-PhpSize $Value
                $limit = ConvertFrom-PhpSize $row.Param
                if ($null -eq $bytes -or $null -eq $limit) { return 'unknown' }
                if ($bytes -ge 0 -and $bytes -le $limit) { return 'aligns' } else { return 'weakens' }
            }
            'time-range' {
                $t = 0; $ok = [int]::TryParse($Value.Trim(), [ref]$t)
                if (-not $ok) { return 'unknown' }
                if ($t -ge 1 -and $t -le 120) { return 'aligns' } else { return 'weakens' }
            }
            'samesite' {
                if ($Value.Trim().ToLower() -in @('lax','strict')) { return 'aligns' } else { return 'weakens' }
            }
            'le-num' {
                $t = 0; $ok = [long]::TryParse($Value.Trim(), [ref]$t)
                $lim = 0; $okLim = [long]::TryParse($row.Param, [ref]$lim)
                if (-not $ok -or -not $okLim) { return 'unknown' }
                if ($t -le $lim) { return 'aligns' } else { return 'weakens' }
            }
            default { return 'unknown' }
        }
    } catch { return 'unknown' }
}

function Get-PhpFpmPoolOverrides {
    <#
    Reads php-fpm pool confs and flags ini overrides. Pool files live next
    to discovered installs (<dir>\etc\php-fpm.d\*.conf, <dir>\etc\pool.d\*)
    and at the usual stack paths. Returns per-pool rows:
    PoolFile, Line, Setting, Value, Verdict, Recommended, Fix. Only
    'weakens' and 'aligns' rows on table settings are printed by default;
    'unknown' rows are kept in the report for manual review.
    #>
    param($PhpInstalls = $null)
    try {
        if ($null -eq $PhpInstalls) {
            try { $PhpInstalls = @(Get-PhpInstalls) } catch { $PhpInstalls = @() }
        }
        $dirs = @()
        foreach ($i in @($PhpInstalls)) {
            if ($i.Dir) {
                foreach ($sub in @('etc\php-fpm.d', 'etc\pool.d', 'etc')) {
                    $dirs += Join-Path $i.Dir $sub
                }
            }
        }
        $dirs += @('C:\php\etc\php-fpm.d', 'C:\xampp\php\etc\php-fpm.d', 'C:\wamp64\bin\php', 'C:\laragon\bin\php')
        $dirs = @($dirs | Select-Object -Unique)
        $files = @()
        foreach ($d in $dirs) {
            try {
                if (Test-Path $d) {
                    foreach ($f in @(Get-ChildItem -Path $d -Filter '*.conf' -Recurse -Depth 1 -File -ErrorAction SilentlyContinue)) {
                        $files += $f.FullName
                    }
                }
            } catch { }
        }
        $files = @($files | Select-Object -Unique)
        if ($files.Count -eq 0) {
            Write-Host '    [=] No php-fpm pool confs found — nothing to audit.'
            return @()
        }
        $table = Get-PhpIniHardeningTable
        $rows = @()
        foreach ($f in $files) {
            try {
                $pool = ''
                try { $pool = ([regex]::Match((Get-Content $f -Raw -ErrorAction Stop), '(?im)^\s*\[([^\]]+)\]').Groups[1].Value) } catch { }
                $lns = @(Get-Content $f -ErrorAction Stop)
                $lnNo = 0
                foreach ($ln in $lns) {
                    $lnNo++
                    $ov = ConvertFrom-FpmPoolOverrideLine -Line $ln
                    if ($null -eq $ov) { continue }
                    $verdict = Test-FpmPoolOverrideVerdict -Setting $ov.Setting -Value $ov.Value -Table $table
                    if ($verdict -eq 'unknown') { continue }
                    $rowT = @($table | Where-Object { $_.Setting -ieq $ov.Setting }) | Select-Object -First 1
                    $fix = "In $f : change $($ov.Directive)[$($ov.Setting)] to match the hardening table — $($rowT.Fix) Then restart php-fpm."
                    $rows += [pscustomobject]@{
                        PoolFile = $f; Pool = $pool; Line = $lnNo
                        Setting = $ov.Setting; Value = $ov.Value
                        Directive = $ov.Directive; Verdict = $verdict
                        Recommended = $rowT.Recommended; Severity = $rowT.Severity
                        Fix = $fix
                    }
                }
            } catch {
                Write-Host "    [!] could not read pool conf $f : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        $weak = @($rows | Where-Object { $_.Verdict -eq 'weakens' }).Count
        Write-Host "    [+] $($files.Count) pool conf(s), $($rows.Count) ini override(s), $weak WEAKEN hardening."
        foreach ($r in ($rows | Where-Object { $_.Verdict -eq 'weakens' })) {
            Write-Host "      [WEAKENS:$($r.Severity)] $($r.Setting)=$($r.Value) — $($r.PoolFile):$($r.Line) (pool [$($r.Pool)])" -ForegroundColor Red
            Write-Host "        FIX: $($r.Fix)"
        }
        return $rows
    } catch {
        Write-Host "[-] Get-PhpFpmPoolOverrides failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PhpRecentlyChangedFiles {
    <#
    The webshell-drop signal: PHP files under a docroot whose last-write
    time is within the last $Days days, with per-file SHA-256. A webshell
    is a NEW file (or a recently edited one); Find-PhpSuspiciousFiles
    catches known shapes, this catches the timing. Cap at $MaxFiles rows
    so a mass deploy does not drown the report.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$DocRoot,
        [int]$Days = 30,
        [int]$MaxFiles = 200,
        [string[]]$Extensions = @('.php','.phtml','.phar','.inc')
    )
    try {
        if (-not (Test-Path $DocRoot)) {
            Write-Host "[-] docroot not found: $DocRoot" -ForegroundColor Red
            return @()
        }
        $cutoff = (Get-Date).AddDays(-$Days)
        Write-Host "[*] Files changed in the last $Days days under $DocRoot ..."
        $files = @(Get-ChildItem -Path $DocRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $Extensions -contains $_.Extension.ToLower() -and $_.LastWriteTime -gt $cutoff } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $MaxFiles)
        $out = @()
        foreach ($f in $files) {
            try {
                $h = (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                $out += [pscustomobject]@{
                    File = $f.FullName; Sha256 = $h
                    LastWriteUtc = $f.LastWriteTimeUtc.ToString('o')
                    SizeBytes = $f.Length
                }
            } catch { }
        }
        Write-Host "    [+] $($out.Count) recently-changed PHP file(s)."
        return $out
    } catch {
        Write-Host "[-] Get-PhpRecentlyChangedFiles failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Mitigation writers — the fix that ships with the detection
# ---------------------------------------------------------------------------
function Test-PhpShieldMarkerPresent {
    <#
    Pure predicate: does $Content carry $Marker as a REAL marker, not as a
    prefix of a longer one? The CGI marker '# Falsum-PHPShield-CGI4577'
    contains the base marker '# Falsum-PHPShield' as a strict prefix —
    a naive -match of the base marker would claim the upload_progress
    block is present when only the CGI block was written (the false-green
    Test-PhpMitigation shipped for exactly that case). Require the marker
    NOT be followed by '-' (the CGI suffix begins there).
    #>
    param(
        [string]$Content,
        [Parameter(Mandatory=$true)][string]$Marker
    )
    try {
        if ([string]::IsNullOrEmpty($Content)) { return $false }
        $pat = [regex]::Escape($Marker) + '(?!-)'
        return ($Content -match $pat)
    } catch { return $false }
}

function Backup-PhpShieldFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        if (-not (Test-Path $Path)) { return '' }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $bak = "$Path.bak-$stamp"
        Copy-Item $Path $bak -Force
        Write-Host "    [backup] $Path -> $bak"
        return $bak
    } catch {
        Write-Host "[-] backup failed for ${Path}: $($_.Exception.Message)" -ForegroundColor Red
        return ''
    }
}

function New-ApacheWafRuleText {
    <#
    Pure builder: returns the .htaccess rule text Add-ApacheWafRule writes.
    Kept as a separate function so the hygiene battery can assert the
    OR-chain structure offline (four RewriteConds, first three [NC,OR],
    last [NC]) without touching a docroot.
    #>
    try {
        return @"
$($script:PhpShieldMarker) — PHP2Shell (CVE-2026-109618) upload_progress mitigation, written $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# Blocks requests carrying the session upload_progress trigger field.
# The four conditions below are ONE OR chain: block when the trigger is in
# the query string OR the request URI.
# LIMIT (honest): mod_rewrite cannot inspect POST bodies, which is where
# the PHP2Shell routes actually ride; PHP also lets apps rename the field
# via session.upload_progress.name, so blocking the default name is
# indicator-class only. This rule reduces ONE route to CVE-2026-109619
# and does nothing for CVE-2026-109618. Pair it with
# session.upload_progress.enabled=Off in php.ini — and patch. The real fix
# is upgrading PHP.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} PHP_SESSION_UPLOAD_PROGRESS [NC,OR]
RewriteCond %{QUERY_STRING} upload_progress [NC,OR]
RewriteCond %{REQUEST_URI} PHP_SESSION_UPLOAD_PROGRESS [NC,OR]
RewriteCond %{REQUEST_URI} upload_progress [NC]
RewriteRule ^ - [F,L]
</IfModule>
"@
    } catch {
        Write-Host "[-] New-ApacheWafRuleText failed: $($_.Exception.Message)" -ForegroundColor Red
        return ''
    }
}

function Add-ApacheWafRule {
    <#
    Appends PHP2Shell upload_progress blocking rules to a docroot .htaccess
    (idempotent via the Falsum marker). The four RewriteConds form one OR
    chain: block when the trigger appears in EITHER the query string OR the
    request URI. Honest limit, stated in the file: mod_rewrite cannot
    inspect POST bodies, so this blocks query-string / request-URI delivery
    of the trigger; php.ini upload_progress=Off covers the body path.
    Upgrading PHP is the real fix.
    #>
    param([Parameter(Mandatory=$true)][string]$DocRoot)
    try {
        $file = Join-Path $DocRoot '.htaccess'
        if (Test-Path $file) {
            $cur = Get-Content $file -Raw -ErrorAction SilentlyContinue
            # v1.5: the CGI marker contains the base marker as a prefix —
            # the helper keeps a CGI-only file from looking "already done"
            # for the upload_progress block.
            if (Test-PhpShieldMarkerPresent -Content $cur -Marker $script:PhpShieldMarker) {
                Write-Host '    [=] .htaccess already carries Falsum rules — skipping.'
                return $true
            }
            Backup-PhpShieldFile -Path $file | Out-Null
        }
        $rules = New-ApacheWafRuleText
        if ($rules -eq '') { return $false }
        Add-Content -Path $file -Value $rules -Encoding UTF8
        Write-Host "    [+] .htaccess rules written: $file" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Add-ApacheWafRule failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Add-IisWafRule {
    <#
    Adds PHP2Shell upload_progress blocking to a docroot web.config via
    requestFiltering/denyQueryStringSequences (native IIS 7+, no modules).
    MERGES into the existing config via Merge-IisDenyQueryStringSequences —
    the old code inserted a second <security> element whenever the config
    already had requestFiltering, and IIS rejects duplicate sections
    (500.19), so the "mitigation" could take the site down. Fixed v1.4.0.
    Creates web.config if absent; idempotent via the Falsum marker.
    #>
    param([Parameter(Mandatory=$true)][string]$DocRoot)
    try {
        $seqs = @('PHP_SESSION_UPLOAD_PROGRESS', 'upload_progress')
        $cmt = "$($script:PhpShieldMarker) — PHP2Shell (CVE-2026-109618) upload_progress mitigation, written $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        $file = Join-Path $DocRoot 'web.config'
        if (Test-Path $file) {
            $cur = Get-Content $file -Raw -ErrorAction SilentlyContinue
            # v1.5: prefix-safe marker check (see Test-PhpShieldMarkerPresent).
            if (Test-PhpShieldMarkerPresent -Content $cur -Marker $script:PhpShieldMarker) {
                Write-Host '    [=] web.config already carries Falsum rules — skipping.'
                return $true
            }
            Backup-PhpShieldFile -Path $file | Out-Null
            $merged = Merge-IisDenyQueryStringSequences -WebConfig $cur -Sequences $seqs -Comment ($cmt + ' LIMIT: requestFiltering cannot inspect POST bodies; pair with session.upload_progress.enabled=Off in php.ini. The real fix is upgrading PHP.')
            if ($null -eq $merged) {
                Write-Host '[-] web.config has no </system.webServer> anchor — refusing to append to a malformed config. Fix the XML first.' -ForegroundColor Red
                return $false
            }
            Set-Content -Path $file -Value $merged -Encoding UTF8
        } else {
            $new = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <!-- $cmt -->
    <!-- LIMIT: requestFiltering cannot inspect POST bodies; pair with session.upload_progress.enabled=Off in php.ini. The real fix is upgrading PHP. -->
    <security>
      <requestFiltering>
        <denyQueryStringSequences>
          <add sequence="PHP_SESSION_UPLOAD_PROGRESS" />
          <add sequence="upload_progress" />
        </denyQueryStringSequences>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
"@
            Set-Content -Path $file -Value $new -Encoding UTF8
        }
        Write-Host "    [+] web.config rules written: $file" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Add-IisWafRule failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ---------------------------------------------------------------------------
# CVE-2024-4577 web-server blocks + the web.config merge engine.
# The v1.4.0 changelog described these builders/writers before they existed;
# this pass makes the changelog true. Better-Way Law for the CGI CVE: the
# detection ships the server-side blocks.
# ---------------------------------------------------------------------------
function New-PhpCgiWafRuleText {
    <#
    Pure builder: Apache .htaccess text blocking the CVE-2024-4577 CGI
    argument-injection trigger shapes. Three conditions, ONE OR chain:
      ^%AD   — the 0xAD soft hyphen, %-encoded, at the START of the query
               string. Windows Best-Fit converts 0xAD to 0x2D (dash) before
               php-cgi.exe parses it, so the trigger arrives as a PHP CLI
               option (-s source disclosure, -d allow_url_include=1, ...).
      ^%C2%AD — the UTF-8 encoding of the same soft hyphen; some stacks
               normalize to this form before Best-Fit conversion.
      ^-     — a bare leading dash at the start of the query string: the
               classic -s / -d option probe shape (CVE-2012-1823 family).
               A legitimate application query string never starts with '-'
               on a PHP site.
    Every condition is anchored to the START (^) so ordinary parameters
    containing dashes or %-sequences mid-string are never blocked.
    LIMIT, stated in the file: mod_rewrite inspects the QUERY STRING only —
    POST bodies and header delivery are not covered. Pair with
    cgi.force_redirect=1 in php.ini. The real fix is upgrading PHP
    (8.1.29 / 8.2.20 / 8.3.8) or not serving PHP through CGI at all.
    #>
    try {
        return @"
$($script:PhpShieldCgiMarker) — CVE-2024-4577 CGI argument-injection mitigation, written $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# Blocks the CGI option-injection trigger at the start of the query string.
# The three conditions below are ONE OR chain: block when ANY of them matches.
# LIMIT: mod_rewrite cannot inspect POST bodies or headers — pair with
# cgi.force_redirect=1 in php.ini. The real fix is upgrading PHP or dropping CGI.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{QUERY_STRING} ^%AD [NC,OR]
RewriteCond %{QUERY_STRING} ^%C2%AD [NC,OR]
RewriteCond %{QUERY_STRING} ^- [NC]
RewriteRule ^ - [F,L]
</IfModule>
"@
    } catch {
        Write-Host "[-] New-PhpCgiWafRuleText failed: $($_.Exception.Message)" -ForegroundColor Red
        return ''
    }
}

function New-PhpCgiIisRuleText {
    <#
    Pure builder: IIS web.config fragment for the CVE-2024-4577 trigger,
    using requestFiltering/denyQueryStringSequences (native IIS 7+, no modules).
    The ONLY sequence added here is the %-encoded soft hyphen (%AD) — the
    trigger as actually sent by scanners and the documented PoCs.
    HONEST LIMIT, stated in the file: requestFiltering does SUBSTRING
    matching, so the anchoring the Apache rules do (^ = start of query
    string) is impossible here — adding "-s" or "-d" as substrings would
    over-block legitimate parameters, so they are deliberately NOT added.
    %AD is rare enough in real query strings to be safe. For anchored
    matching on IIS, install the URL Rewrite module and translate the
    Apache ^%AD condition. The real fix is upgrading PHP or not serving
    PHP through CGI.
    The returned text is a FRAGMENT — Add-PhpCgiIisWafRule merges its
    sequences into an existing web.config via Merge-IisDenyQueryStringSequences
    (never a second <security> element, which would break the config).
    #>
    try {
        return @"
    <!-- $($script:PhpShieldCgiMarker) — CVE-2024-4577 CGI argument-injection mitigation, written $(Get-Date -Format 'yyyy-MM-dd HH:mm') -->
    <!-- LIMIT: requestFiltering matches SUBSTRINGS — -s/-d are deliberately not blocked here (would over-block legit params). URL Rewrite module for anchored ^ rules. -->
    <security>
      <requestFiltering>
        <denyQueryStringSequences>
          <add sequence="%AD" />
        </denyQueryStringSequences>
      </requestFiltering>
    </security>
"@
    } catch {
        Write-Host "[-] New-PhpCgiIisRuleText failed: $($_.Exception.Message)" -ForegroundColor Red
        return ''
    }
}

function Merge-IisDenyQueryStringSequences {
    <#
    Pure merge: returns $WebConfig with $Sequences added as
    <add sequence="..." /> rows inside <denyQueryStringSequences>.
    String-based on purpose — no XML parser: a malformed config stays
    byte-stable instead of being "repaired" into something IIS reads
    differently. We never rewrite what we did not add.
    Merge order: existing <denyQueryStringSequences> -> existing
    <requestFiltering> -> existing <security> -> fresh <security> block
    before </system.webServer>. Sequences already present are skipped
    (idempotent). Returns $null when there is no </system.webServer>
    anchor (caller must not append blindly to a malformed config).
    This is the fix for the live bug the old Add-IisWafRule shipped: it
    inserted a SECOND <security> element whenever the config already had
    requestFiltering — IIS rejects duplicate sections (500.19) and the
    "mitigation" took the site down.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$WebConfig,
        [Parameter(Mandatory=$true)][string[]]$Sequences,
        [string]$Comment = ''
    )
    try {
        $missing = @()
        $hasBlock = $false
        if ($WebConfig -match '(?s)<denyQueryStringSequences>(.*?)</denyQueryStringSequences>') {
            $hasBlock = $true
            $inner = $Matches[1]
            foreach ($s in $Sequences) {
                # v1.5: exact attribute match — the old substring check
                # treated upload_progress_foo as containing upload_progress
                # and silently skipped a sequence that was never added.
                if ($inner -notmatch ('sequence="' + [regex]::Escape($s) + '"')) { $missing += $s }
            }
        } else {
            $missing = @($Sequences)
        }
        if ($missing.Count -eq 0) { return $WebConfig }

        $cmt = if ($Comment -ne '') { "        <!-- $Comment -->`r`n" } else { '' }
        $rows = ($missing | ForEach-Object { "          <add sequence=`"$_`" />" }) -join "`r`n"
        $out = $WebConfig
        if ($hasBlock) {
            $out = [regex]::Replace($out, '</denyQueryStringSequences>', ($rows + "`r`n        </denyQueryStringSequences>"), 1)
        } elseif ($WebConfig -match '</requestFiltering>') {
            $ins = $cmt + "        <denyQueryStringSequences>`r`n$rows`r`n        </denyQueryStringSequences>`r`n      </requestFiltering>"
            $out = [regex]::Replace($out, '</requestFiltering>', $ins, 1)
        } elseif ($WebConfig -match '</security>') {
            $ins = $cmt + "      <requestFiltering>`r`n        <denyQueryStringSequences>`r`n$rows`r`n        </denyQueryStringSequences>`r`n      </requestFiltering>`r`n    </security>"
            $out = [regex]::Replace($out, '</security>', $ins, 1)
        } elseif ($WebConfig -match '</system.webServer>') {
            $ins = $cmt + "    <security>`r`n      <requestFiltering>`r`n        <denyQueryStringSequences>`r`n$rows`r`n        </denyQueryStringSequences>`r`n      </requestFiltering>`r`n    </security>`r`n  </system.webServer>"
            $out = [regex]::Replace($out, '</system.webServer>', $ins, 1)
        } else {
            return $null
        }
        return $out
    } catch {
        Write-Host "[-] Merge-IisDenyQueryStringSequences failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Add-PhpCgiWafRule {
    <#
    Appends the CVE-2024-4577 CGI argument-injection blocks to a docroot
    .htaccess (idempotent via the CGI marker). Backup before write.
    Harmless on non-CGI deployments: a legitimate query string never
    starts with %AD or a bare dash.
    #>
    param([Parameter(Mandatory=$true)][string]$DocRoot)
    try {
        $file = Join-Path $DocRoot '.htaccess'
        if (Test-Path $file) {
            $cur = Get-Content $file -Raw -ErrorAction SilentlyContinue
            if (Test-PhpShieldMarkerPresent -Content $cur -Marker $script:PhpShieldCgiMarker) {
                Write-Host '    [=] .htaccess already carries Falsum CGI-4577 rules — skipping.'
                return $true
            }
            Backup-PhpShieldFile -Path $file | Out-Null
        }
        $rules = New-PhpCgiWafRuleText
        if ($rules -eq '') { return $false }
        Add-Content -Path $file -Value $rules -Encoding UTF8
        Write-Host "    [+] .htaccess CGI-4577 rules written: $file" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Add-PhpCgiWafRule failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Add-PhpCgiIisWafRule {
    <#
    Adds the CVE-2024-4577 %AD trigger to a docroot web.config via
    Merge-IisDenyQueryStringSequences: merges into the existing
    <denyQueryStringSequences> / <requestFiltering> / <security> instead of
    writing a second <security> element (which would break web.config).
    Creates web.config if absent. Idempotent via the CGI marker.
    #>
    param([Parameter(Mandatory=$true)][string]$DocRoot)
    try {
        $seqs = @('%AD')
        $cmt = "$($script:PhpShieldCgiMarker) — CVE-2024-4577 CGI argument-injection mitigation, written $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        $file = Join-Path $DocRoot 'web.config'
        if (Test-Path $file) {
            $cur = Get-Content $file -Raw -ErrorAction SilentlyContinue
            if (Test-PhpShieldMarkerPresent -Content $cur -Marker $script:PhpShieldCgiMarker) {
                Write-Host '    [=] web.config already carries Falsum CGI-4577 rules — skipping.'
                return $true
            }
            Backup-PhpShieldFile -Path $file | Out-Null
            $merged = Merge-IisDenyQueryStringSequences -WebConfig $cur -Sequences $seqs -Comment $cmt
            if ($null -eq $merged) {
                Write-Host '[-] web.config has no </system.webServer> anchor — refusing to append to a malformed config. Fix the XML first.' -ForegroundColor Red
                return $false
            }
            Set-Content -Path $file -Value $merged -Encoding UTF8
        } else {
            $frag = New-PhpCgiIisRuleText
            if ($frag -eq '') { return $false }
            $new = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
$($frag.TrimEnd())
  </system.webServer>
</configuration>
"@
            Set-Content -Path $file -Value $new -Encoding UTF8
        }
        Write-Host "    [+] web.config CGI-4577 rules written: $file" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Add-PhpCgiIisWafRule failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function ConvertTo-PhpIniUploadProgressOff {
    <#
    Pure logic: takes php.ini lines, returns lines with
    session.upload_progress.enabled=Off enforced. Replaces the existing
    line whether active or commented (a commented ";...=On" line that
    someone uncomments later would silently re-arm the PHP2Shell trigger,
    so the regex deliberately matches the ';?' form). Appends the setting
    with the Falsum marker when no line exists. Testable offline by
    Test-PhpShieldHygiene.
    #>
    param([string[]]$Lines)
    try {
        $out = @()
        $hit = $false
        foreach ($ln in $Lines) {
            if ($ln -match '^\s*;?\s*session\.upload_progress\.enabled\s*=') {
                $hit = $true
                $out += 'session.upload_progress.enabled=Off'
            } else {
                $out += $ln
            }
        }
        if (-not $hit) {
            $out += ''
            $out += "$($script:PhpShieldMarker) PHP2Shell mitigation"
            $out += 'session.upload_progress.enabled=Off'
        }
        return $out
    } catch {
        Write-Host "[-] ConvertTo-PhpIniUploadProgressOff failed: $($_.Exception.Message)" -ForegroundColor Red
        return $Lines
    }
}

function Set-PhpUploadProgressDisabled {
    <#
    Sets session.upload_progress.enabled=Off in the install's php.ini.
    Backs up first. Usually needs admin when PHP lives under Program Files —
    checked up front with a clean message instead of a cryptic failure.
    #>
    param([Parameter(Mandatory=$true)]$PhpInstall)
    try {
        $ini = Get-PhpIniPath -PhpInstall $PhpInstall
        if (-not $ini) {
            Write-Host '[-] No loaded php.ini for this install (php --ini reported none). Create one from php.ini-development first.' -ForegroundColor Red
            return $false
        }
        if (-not (Test-Path $ini)) {
            Write-Host "[-] php.ini path reported but file missing: $ini" -ForegroundColor Red
            return $false
        }
        try {
            $probe = [System.IO.File]::Open($ini, 'Open', 'ReadWrite')
            $probe.Close()
        } catch {
            Write-Host '[-] Cannot write php.ini — run PowerShell as Administrator (PHP is in a protected path).' -ForegroundColor Red
            return $false
        }
        Backup-PhpShieldFile -Path $ini | Out-Null
        $lines = @(Get-Content $ini -ErrorAction SilentlyContinue)
        $out = ConvertTo-PhpIniUploadProgressOff -Lines $lines
        Set-Content -Path $ini -Value $out -Encoding UTF8
        Write-Host "    [+] php.ini updated: session.upload_progress.enabled=Off ($ini)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Set-PhpUploadProgressDisabled failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function New-PhpMitigation {
    <#
    Applies the PHP2Shell interim STOPGAPS (not the fix — updating PHP is
    the only complete fix for CVE-2026-109618 / CVE-2026-109619) plus the
    CVE-2024-4577 web-server blocks:
      -DocRoot       : web root to shield with .htaccess (Apache) and/or web.config (IIS)
      -ServerType    : Apache | IIS | Both (default Both)
      -PhpInstall    : specific install object from Get-PhpInstalls (or omit)
      -DisableUploadProgress : also set session.upload_progress.enabled=Off in php.ini
    When -DocRoot is given, BOTH rule sets are written (each idempotent via
    its own marker): the upload_progress block and the CGI-4577 block
    (^%AD / ^%C2%AD / ^- on Apache; %AD sequence on IIS). The CGI rules are
    harmless on non-CGI deployments — a legitimate query string never
    starts with a soft hyphen or a bare dash.
    Originals are backed up before any write. Returns a per-action result table.
    #>
    param(
        [string]$DocRoot = '',
        [ValidateSet('Apache','IIS','Both')][string]$ServerType = 'Both',
        $PhpInstall = $null,
        [switch]$DisableUploadProgress
    )
    try {
        Write-Host "`n=== Applying PHP Shield mitigations ===" -ForegroundColor Cyan
        $actions = @()
        if ($DocRoot) {
            if (-not (Test-Path $DocRoot)) {
                Write-Host "[-] DocRoot not found: $DocRoot" -ForegroundColor Red
            } else {
                if ($ServerType -in @('Apache','Both')) {
                    $ok = Add-ApacheWafRule -DocRoot $DocRoot
                    $actions += [pscustomobject]@{ Action = 'apache-htaccess'; Target = $DocRoot; Applied = $ok }
                    $ok = Add-PhpCgiWafRule -DocRoot $DocRoot
                    $actions += [pscustomobject]@{ Action = 'apache-htaccess-cgi4577'; Target = $DocRoot; Applied = $ok }
                }
                if ($ServerType -in @('IIS','Both')) {
                    $ok = Add-IisWafRule -DocRoot $DocRoot
                    $actions += [pscustomobject]@{ Action = 'iis-webconfig'; Target = $DocRoot; Applied = $ok }
                    $ok = Add-PhpCgiIisWafRule -DocRoot $DocRoot
                    $actions += [pscustomobject]@{ Action = 'iis-webconfig-cgi4577'; Target = $DocRoot; Applied = $ok }
                }
            }
        }
        if ($DisableUploadProgress) {
            $targets = @()
            if ($PhpInstall) { $targets = @($PhpInstall) } else { $targets = Get-PhpInstalls }
            foreach ($t in $targets) {
                $ok = Set-PhpUploadProgressDisabled -PhpInstall $t
                $actions += [pscustomobject]@{ Action = 'phpini-upload_progress-off'; Target = $t.Exe; Applied = $ok }
            }
        }
        if ($actions.Count -eq 0) {
            Write-Host '[!] Nothing to do — pass -DocRoot and/or -DisableUploadProgress.' -ForegroundColor Yellow
        }
        return $actions
    } catch {
        Write-Host "[-] New-PhpMitigation failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Verification — prove the mitigation is actually in place
# ---------------------------------------------------------------------------
function Test-PhpMitigation {
    <#
    Verifies every mitigation layer. Checks, per docroot and per install:
      - .htaccess carries the Falsum marker (upload_progress block)
      - .htaccess carries the Falsum CGI-4577 marker
      - web.config carries the Falsum marker (upload_progress block)
      - web.config carries the Falsum CGI-4577 marker
      - php.ini session.upload_progress.enabled is Off
    Returns check objects with Pass true/false and Detail evidence.
    #>
    param(
        [string]$DocRoot = '',
        $PhpInstall = $null
    )
    try {
        Write-Host "`n=== Verifying PHP Shield mitigations ===" -ForegroundColor Cyan
        $checks = @()
        if ($DocRoot -and (Test-Path $DocRoot)) {
            $ht = Join-Path $DocRoot '.htaccess'
            $wc = Join-Path $DocRoot 'web.config'
            $htContent = $null; $wcContent = $null
            if (Test-Path $ht) { $htContent = Get-Content $ht -Raw -ErrorAction SilentlyContinue }
            if (Test-Path $wc) { $wcContent = Get-Content $wc -Raw -ErrorAction SilentlyContinue }
            $htOk = $false; $htDetail = 'no .htaccess'
            if ($null -ne $htContent) {
                # v1.5: prefix-safe — a CGI-only .htaccess must not pass the
                # upload_progress layer.
                $htOk = Test-PhpShieldMarkerPresent -Content $htContent -Marker $script:PhpShieldMarker
                $htDetail = if ($htOk) { 'marker present' } else { 'marker missing' }
            }
            $checks += [pscustomobject]@{ Layer = 'apache-htaccess'; Target = $ht; Pass = $htOk; Detail = $htDetail }
            $htCgiOk = $false; $htCgiDetail = 'no .htaccess'
            if ($null -ne $htContent) {
                $htCgiOk = Test-PhpShieldMarkerPresent -Content $htContent -Marker $script:PhpShieldCgiMarker
                $htCgiDetail = if ($htCgiOk) { 'CGI-4577 marker present' } else { 'CGI-4577 marker missing' }
            }
            $checks += [pscustomobject]@{ Layer = 'apache-htaccess-cgi4577'; Target = $ht; Pass = $htCgiOk; Detail = $htCgiDetail }

            $wcOk = $false; $wcDetail = 'no web.config'
            if ($null -ne $wcContent) {
                # v1.5: prefix-safe — see the .htaccess layer above.
                $wcOk = Test-PhpShieldMarkerPresent -Content $wcContent -Marker $script:PhpShieldMarker
                $wcDetail = if ($wcOk) { 'marker present' } else { 'marker missing' }
            }
            $checks += [pscustomobject]@{ Layer = 'iis-webconfig'; Target = $wc; Pass = $wcOk; Detail = $wcDetail }
            $wcCgiOk = $false; $wcCgiDetail = 'no web.config'
            if ($null -ne $wcContent) {
                $wcCgiOk = Test-PhpShieldMarkerPresent -Content $wcContent -Marker $script:PhpShieldCgiMarker
                $wcCgiDetail = if ($wcCgiOk) { 'CGI-4577 marker present' } else { 'CGI-4577 marker missing' }
            }
            $checks += [pscustomobject]@{ Layer = 'iis-webconfig-cgi4577'; Target = $wc; Pass = $wcCgiOk; Detail = $wcCgiDetail }
        }
        $targets = @()
        if ($PhpInstall) { $targets = @($PhpInstall) }
        else {
            # v1.5 FIX: no install pin — verify the php.ini layer across
            # every discovered install, whether or not a docroot was also
            # given. The old code only did this when DocRoot was EMPTY, so
            # a New-PhpMitigation -DocRoot X -DisableUploadProgress run's
            # ini changes were NEVER verified — the one layer that took a
            # change was the one layer nobody checked. These checks report
            # the ACTUAL setting state (not "did the last mitigation work"),
            # so a docroot-only run just gets an honest reading of the ini
            # layer alongside the web-server layers.
            Write-Host '[*] No install pinned — verifying php.ini layer on all discovered installs.'
            $targets = @(Get-PhpInstalls)
        }
        foreach ($t in $targets) {
            $state = Get-PhpUploadProgressSetting -PhpInstall $t
            $checks += [pscustomobject]@{
                Layer  = 'phpini-upload_progress'
                Target = $t.Exe
                Pass   = ($state -eq 'Off')
                Detail = "session.upload_progress.enabled = $state"
            }
        }
        foreach ($c in $checks) {
            $icon = if ($c.Pass) { '[PASS]' } else { '[FAIL]' }
            $color = if ($c.Pass) { 'Green' } else { 'Red' }
            Write-Host "  $icon $($c.Layer) — $($c.Detail)" -ForegroundColor $color
        }
        return $checks
    } catch {
        Write-Host "[-] Test-PhpMitigation failed: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# ---------------------------------------------------------------------------
# Self-test battery. Offline, pure logic: version parsing/comparison
# (incl. the pre-release fix), ini bool/size parsing, CVE branch
# classification, the ini-line rewrite, the WAF rule text, the web.config
# merge engine, the CGI-4577 rule builders, the webshell table, and the
# probe runner's failure shape. No php.exe, no network. One self-cleaning
# temp-dir case proves writer idempotence (removed in finally); everything
# else is in memory. Throws when any check fails, returns $true when all pass.
# ---------------------------------------------------------------------------
function Test-PhpShieldHygiene {
    $checks = @()
    # NOTE: the $add scriptblock RETURNS the check object; callers capture
    # it with $checks += & $add ... — writing $checks inside the scriptblock
    # would hit a child scope and silently stay empty (the vault battery
    # caught this pattern in a sibling module).
    $add = {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        return [pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }
    }

    # 1. Version parsing.
    $v = ConvertTo-PhpVersion 'PHP 8.2.35 (cli) (built: Oct 1 2026)'
    $checks += & $add "ver[plain]" (($null -ne $v) -and $v.Major -eq 8 -and $v.Minor -eq 2 -and $v.Patch -eq 35 -and $v.PreRelease -eq '') "got=$($v.Branch).$($v.Patch)/$($v.PreRelease)"
    $v = ConvertTo-PhpVersion 'PHP 8.3.25RC2 (cli)'
    $checks += & $add "ver[rc2]" (($null -ne $v) -and $v.Branch -eq '8.3' -and $v.Patch -eq 25 -and $v.PreRelease -eq 'rc' -and $v.PreReleaseNum -eq 2) "got=$($v.Branch).$($v.Patch)/$($v.PreRelease)$($v.PreReleaseNum)"
    $v = ConvertTo-PhpVersion 'PHP 7.4.33-1ubuntu0.22.04.1 (cli)'
    $checks += & $add "ver[distro]" (($null -ne $v) -and $v.Branch -eq '7.4' -and $v.Patch -eq 33 -and $v.PreRelease -eq 'distro') "got=$($v.Branch).$($v.Patch)/$($v.PreRelease)"
    $v = ConvertTo-PhpVersion '8.1'
    $checks += & $add "ver[two-part]" (($null -ne $v) -and $v.Branch -eq '8.1' -and $v.Patch -eq 0) "got=$($v.Branch).$($v.Patch)"
    $v = ConvertTo-PhpVersion 'not a version'
    $checks += & $add "ver[garbage-null]" ($null -eq $v) "garbage must not parse"

    # 2. Comparison, incl. the pre-release fix (RC < its own release).
    $checks += & $add "cmp[rc1<release]" ((Compare-PhpVersion '8.2.35RC1' '8.2.35') -eq -1) ""
    $checks += & $add "cmp[rc1<rc2]" ((Compare-PhpVersion '8.2.35RC1' '8.2.35RC2') -eq -1) ""
    $checks += & $add "cmp[equal]" ((Compare-PhpVersion '8.4.27' '8.4.27') -eq 0) ""
    $checks += & $add "cmp[older-patch]" ((Compare-PhpVersion '8.2.34' '8.2.35') -eq -1) ""
    $checks += & $add "cmp[newer]" ((Compare-PhpVersion '8.3.36' '8.2.35') -eq 1) ""
    $checks += & $add "cmp[beta<release]" ((Compare-PhpVersion '8.4.0beta1' '8.4.0') -eq -1) ""
    $checks += & $add "cmp[distro<release]" ((Compare-PhpVersion '7.4.33-1ubuntu' '7.4.33') -eq -1) ""

    # 3. ini bool normalization.
    $checks += & $add "bool[On]" ((ConvertTo-PhpIniBool 'On') -eq $true) ""
    $checks += & $add "bool[1]" ((ConvertTo-PhpIniBool '1') -eq $true) ""
    $checks += & $add "bool[Off]" ((ConvertTo-PhpIniBool 'Off') -eq $false) ""
    $checks += & $add "bool[empty]" ((ConvertTo-PhpIniBool '') -eq $false) ""
    $checks += & $add "bool[junk-null]" ($null -eq (ConvertTo-PhpIniBool 'maybe')) ""

    # 4. ini size shorthand.
    $checks += & $add "size[128M]" ((ConvertFrom-PhpSize '128M') -eq 134217728) ""
    $checks += & $add "size[512K]" ((ConvertFrom-PhpSize '512K') -eq 524288) ""
    $checks += & $add "size[1.5G]" ((ConvertFrom-PhpSize '1.5G') -eq 1610612736) ""
    $checks += & $add "size[-1]" ((ConvertFrom-PhpSize '-1') -eq -1) "unlimited"
    $checks += & $add "size[junk-null]" ($null -eq (ConvertFrom-PhpSize 'junk')) ""

    # 5. CVE branch classification on synthetic installs (no php.exe).
    $mk = { param($vstr) [pscustomobject]@{ Exe = 'C:\php\php.exe'; Version = (ConvertTo-PhpVersion $vstr); VersionRaw = $vstr } }
    $tt = Get-PhpThreatTable
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.2.34') -ThreatTable $tt | Where-Object { $_.Id -eq 'CVE-2026-109618' })
    $checks += & $add "cve[8.2.34-vuln]" ($f.Count -eq 1) "one patch release behind"
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.2.35') -ThreatTable $tt)
    $checks += & $add "cve[8.2.35-clean]" ($f.Count -eq 0) "patched release is clean"
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.4.27') -ThreatTable $tt)
    $checks += & $add "cve[8.4.27-clean]" ($f.Count -eq 0) ""
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.1.30') -ThreatTable $tt | Where-Object { $_.Severity -eq 'Critical' })
    $checks += & $add "cve[8.1.30-eol]" ($f.Count -ge 1 -and ($f[0].Id -like 'CVE-2026-10961*')) "EOL branch: no patch exists"
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.6.0') -ThreatTable $tt | Where-Object { $_.Id -like '*-UNVERIFIED-BRANCH' })
    $checks += & $add "cve[8.6-unverified]" ($f.Count -ge 1) "branch newer than the table: flag, do not trust"
    $f = @(Test-PhpCveMatch -PhpInstall (& $mk '8.2.35RC1') -ThreatTable $tt | Where-Object { $_.Id -eq 'CVE-2026-109618' })
    $checks += & $add "cve[8.2.35RC1-vuln]" ($f.Count -eq 1) "the v1.3 fix: RC predates its own release"

    # 6. ini line rewrite (pure logic).
    $lines = @('expose_php=Off', 'session.upload_progress.enabled=On', 'memory_limit=256M')
    $out = ConvertTo-PhpIniUploadProgressOff -Lines $lines
    $checks += & $add "ini[active-replaced]" ((@($out | Where-Object { $_ -eq 'session.upload_progress.enabled=Off' }).Count -eq 1) -and ($out.Count -eq 3)) ""
    $lines = @(';session.upload_progress.enabled=On', 'memory_limit=256M')
    $out = ConvertTo-PhpIniUploadProgressOff -Lines $lines
    $checks += & $add "ini[commented-replaced]" ((@($out | Where-Object { $_ -eq 'session.upload_progress.enabled=Off' }).Count -eq 1) -and ($out.Count -eq 2)) "a commented =On must not survive"
    $lines = @('expose_php=Off')
    $out = ConvertTo-PhpIniUploadProgressOff -Lines $lines
    $tail = @($out | Select-Object -Last 3)
    $checks += & $add "ini[absent-appended]" (($tail[0] -eq '') -and ($tail[1] -like "*$($script:PhpShieldMarker)*") -and ($tail[2] -eq 'session.upload_progress.enabled=Off')) ""

    # 7. WAF rule text structure (the OR-chain must survive refactors).
    $rules = New-ApacheWafRuleText
    $conds = @($rules -split "`r?`n" | Where-Object { $_ -match '^\s*RewriteCond' })
    $checks += & $add "waf[marker]" ($rules -match [regex]::Escape($script:PhpShieldMarker)) ""
    $checks += & $add "waf[4-conds]" ($conds.Count -eq 4) "got=$($conds.Count)"
    $orFlags = @($conds | Where-Object { $_ -match '\[NC,OR\]' }).Count
    $plainNc = @($conds | Where-Object { $_ -match '\[NC\]' -and $_ -notmatch '\[NC,OR\]' }).Count
    $checks += & $add "waf[or-chain]" (($orFlags -eq 3) -and ($plainNc -eq 1)) "first three [NC,OR], last [NC] — block on EITHER"
    $checks += & $add "waf[rule]" ($rules -match 'RewriteRule \^ - \[F,L\]') ""

    # 8. Webshell indicator table sanity.
    $wt = Get-PhpWebshellIndicatorTable
    $names = @($wt | Select-Object -ExpandProperty Name)
    $patOk = $true
    foreach ($row in $wt) { try { [void][regex]::new($row.Pattern) } catch { $patOk = $false } }
    $checks += & $add "ws[12-rows]" ($wt.Count -eq 12) "got=$($wt.Count)"
    $checks += & $add "ws[unique-names]" ((@($names | Select-Object -Unique).Count) -eq $names.Count) ""
    $checks += & $add "ws[patterns-compile]" $patOk ""
    $checks += & $add "ws[has-critical]" ((@($wt | Where-Object { $_.Severity -eq 'Critical' }).Count) -ge 1) ""

    # 9. Probe runner failure shape (never hangs, never throws).
    $pb = Invoke-PhpProbe -Exe 'C:\definitely-not-here\php.exe' -Arguments @('-v') -TimeoutSec 2
    $checks += & $add "probe[missing-exe]" (($pb.ExitCode -eq -1) -and (-not $pb.TimedOut) -and ($pb.Error -ne '')) ""

    # 10. Pre-release rank ordering.
    $checks += & $add "rank[rc<release]" ((Get-PhpPreReleaseRank 'rc') -lt (Get-PhpPreReleaseRank '')) ""

    # 11. CVE-2024-4577 builders + the web.config merge engine.
    $ct = New-PhpCgiWafRuleText
    $checks += & $add "cgi[apache-marker]" ($ct -match [regex]::Escape($script:PhpShieldCgiMarker)) ""
    $cconds = @($ct -split "`r?`n" | Where-Object { $_ -match '^\s*RewriteCond' })
    $checks += & $add "cgi[3-conds]" ($cconds.Count -eq 3) "got=$($cconds.Count)"
    $orN = @($cconds | Where-Object { $_ -match '\[NC,OR\]' }).Count
    $lastN = @($cconds | Where-Object { $_ -match '\[NC\]' -and $_ -notmatch 'OR' }).Count
    $checks += & $add "cgi[or-chain]" (($orN -eq 2) -and ($lastN -eq 1)) "first two [NC,OR], last [NC] — block on ANY"
    $anchored = @($cconds | Where-Object { $_ -match '\^%(AD|C2AD)|\^-' }).Count
    $checks += & $add "cgi[anchored]" ($anchored -eq 3) "every trigger anchored ^ — no mid-string false blocks"
    $checks += & $add "cgi[rule-fl]" ($ct -match 'RewriteRule \^ - \[F,L\]') ""
    $it = New-PhpCgiIisRuleText
    $checks += & $add "cgi[iis-marker]" ($it -match [regex]::Escape($script:PhpShieldCgiMarker)) ""
    $checks += & $add "cgi[iis-seq]" ($it -match '<add sequence="%AD" />') ""
    $checks += & $add "cgi[iis-no-dash]" ($it -notmatch 'sequence="-') "must not over-block -s/-d as substrings"

    # Merge: sequence already present -> config returned unchanged.
    $wc1 = '<configuration><system.webServer><security><requestFiltering><denyQueryStringSequences><add sequence="%AD" /></denyQueryStringSequences></requestFiltering></security></system.webServer></configuration>'
    $m1 = Merge-IisDenyQueryStringSequences -WebConfig $wc1 -Sequences @('%AD') -Comment 'x'
    $checks += & $add "merge[already-there]" ($m1 -eq $wc1) "idempotent when the sequence exists"
    # Merge: inject into an existing block, keep old rows.
    $m2 = Merge-IisDenyQueryStringSequences -WebConfig $wc1 -Sequences @('evil_trigger') -Comment 'x'
    $checks += & $add "merge[inject]" (($m2 -match 'sequence="evil_trigger"') -and ($m2 -match 'sequence="%AD"')) ""
    $secN = @([regex]::Matches($m2, '<security>')).Count
    $checks += & $add "merge[one-security]" ($secN -eq 1) "got=$secN — the live duplicate-<security> bug, now refused"
    # Merge: requestFiltering without the block -> block created inside it.
    $wc3 = '<configuration><system.webServer><security><requestFiltering><denyUrlSequences /></requestFiltering></security></system.webServer></configuration>'
    $m3 = Merge-IisDenyQueryStringSequences -WebConfig $wc3 -Sequences @('%AD') -Comment 'x'
    $checks += & $add "merge[into-rf]" (($m3 -match '<denyQueryStringSequences>') -and (@([regex]::Matches($m3, '<security>')).Count -eq 1)) ""
    # Merge: security without requestFiltering -> requestFiltering created inside it.
    $wc4 = '<configuration><system.webServer><security><ipSecurity /></security></system.webServer></configuration>'
    $m4 = Merge-IisDenyQueryStringSequences -WebConfig $wc4 -Sequences @('%AD') -Comment 'x'
    $checks += & $add "merge[into-sec]" (($m4 -match '<requestFiltering>') -and (@([regex]::Matches($m4, '<security>')).Count -eq 1)) ""
    # Merge: no security at all -> exactly one fresh block before </system.webServer>.
    $wc5 = '<configuration><system.webServer><handlers /></system.webServer></configuration>'
    $m5 = Merge-IisDenyQueryStringSequences -WebConfig $wc5 -Sequences @('%AD') -Comment 'x'
    $checks += & $add "merge[fresh-security]" (($m5 -match '<security>') -and (@([regex]::Matches($m5, '<security>')).Count -eq 1)) ""
    # Merge: malformed config, no anchor -> null (caller refuses the write).
    $m6 = Merge-IisDenyQueryStringSequences -WebConfig '<configuration></configuration>' -Sequences @('%AD') -Comment 'x'
    $checks += & $add "merge[no-anchor-null]" ($null -eq $m6) ""

    # Writer idempotence on a self-cleaning temp dir (no residue left behind).
    $td = Join-Path ([IO.Path]::GetTempPath()) ('phpshield-test-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $td -Force | Out-Null
        $w1 = Add-PhpCgiWafRule -DocRoot $td
        $ht = Get-Content (Join-Path $td '.htaccess') -Raw -ErrorAction SilentlyContinue
        $w2 = Add-PhpCgiWafRule -DocRoot $td
        $ht2 = Get-Content (Join-Path $td '.htaccess') -Raw -ErrorAction SilentlyContinue
        $checks += & $add "cgi[writer-idempotent]" ($w1 -and $w2 -and ($ht -eq $ht2) -and ($null -ne $ht)) ""
        $w3 = Add-PhpCgiIisWafRule -DocRoot $td
        $wco = Get-Content (Join-Path $td 'web.config') -Raw -ErrorAction SilentlyContinue
        $w4 = Add-PhpCgiIisWafRule -DocRoot $td
        $wco2 = Get-Content (Join-Path $td 'web.config') -Raw -ErrorAction SilentlyContinue
        $checks += & $add "cgi[iis-writer-idempotent]" ($w3 -and $w4 -and ($wco -eq $wco2) -and ($null -ne $wco)) ""
    } finally { Remove-Item $td -Recurse -Force -ErrorAction SilentlyContinue }

    # 12. v1.5 truth pass: CVE facts match the Oct 21 2026 disclosures, the
    # ini rows state what the mitigations actually do (no "kills the whole
    # attack class"), and the memory-exposure classifier flags rotation
    # duty on unpatched installs.
    $tt2 = Get-PhpThreatTable
    $c18 = @($tt2.CVEs | Where-Object { $_.Id -eq 'CVE-2026-109618' })[0]
    $c19 = @($tt2.CVEs | Where-Object { $_.Id -eq 'CVE-2026-109619' })[0]
    $checks += & $add "cve[618-92crit]" (($c18.Cvss -eq 9.2) -and ($c18.Severity -eq 'Critical')) "cvss=$($c18.Cvss)/$($c18.Severity)"
    $checks += & $add "cve[619-92crit]" (($c19.Cvss -eq 9.2) -and ($c19.Severity -eq 'Critical')) "cvss=$($c19.Cvss)/$($c19.Severity)"
    $checks += & $add "cve[618-mechanism]" (($c18.Mechanism -match 'longjmp') -and ($c18.Mechanism -match 'worker memory')) "no more 'session state corruption' story"
    $checks += & $add "cve[619-mechanism]" ($c19.Mechanism -match 'stale') ""
    $checks += & $add "cve[618-stopgap]" (($c18.Mitigation -match 'memory_limit=-1') -and ($c18.Mitigation -match 'does NOT close this CVE')) ""
    $checks += & $add "cve[619-stopgap]" (($c19.Mitigation -match 'ONE route') -and ($c19.Mitigation -match 'ini_set')) "ini_set caveat present"
    $it2 = Get-PhpIniHardeningTable
    $upRow = @($it2 | Where-Object { $_.Setting -eq 'session.upload_progress.enabled' })[0]
    $checks += & $add "ini[up-honest]" (($upRow.Why -notmatch 'kills the whole attack class') -and ($upRow.Why -match 'does NOT fix either engine bug')) ""
    $mlRow = @($it2 | Where-Object { $_.Setting -eq 'memory_limit' })[0]
    $checks += & $add "ini[ml-bridge]" ($mlRow.Fix -match 'memory_limit=-1') ""
    $eol81 = @($tt2.EOL | Where-Object { $_.Branch -eq '8.1' })[0]
    $checks += & $add "eol[81-backport]" ($eol81.Note -match 'backport') "8.1/8.0/7.4 backports exist"
    $mkv = { param($vstr) ConvertTo-PhpVersion $vstr }
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '8.4.4')
    $checks += & $add "mx[8.4.4-exposed]" (($mx.Verdict -eq 'exposed') -and ($mx.Detail -match 'ROTATE')) ""
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '8.4.27')
    $checks += & $add "mx[8.4.27-covered]" ($mx.Verdict -eq 'covered') ""
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '8.2.35RC1')
    $checks += & $add "mx[8.2.35RC1-exposed]" ($mx.Verdict -eq 'exposed') "pre-release predates its own patch"
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '8.1.30')
    $checks += & $add "mx[8.1.30-backport]" ($mx.Verdict -eq 'backport-only') ""
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '7.2.34')
    $checks += & $add "mx[7.2.34-exposed]" ($mx.Verdict -eq 'exposed') "no backport on this branch"
    $mx = Test-PhpMemoryExposureRisk -Version (& $mkv '8.6.0')
    $checks += & $add "mx[8.6.0-covered]" ($mx.Verdict -eq 'covered') "newer branch presumed patched"
    $mx = Test-PhpMemoryExposureRisk -Version $null
    $checks += & $add "mx[null-unknown]" ($mx.Verdict -eq 'unknown') "never guesses clean"

    $failed = @($checks | Where-Object { -not $_.Passed })
    Write-Host ("[phpshield hygiene] {0}/{1} checks passed" -f ($checks.Count - $failed.Count), $checks.Count)
    foreach ($f in $failed) {
        Write-Host ("  [FAIL] {0} -- {1}" -f $f.Name, $f.Detail)
    }
    if ($failed.Count -gt 0) { throw "$($failed.Count) hygiene checks failed" }
    return $true
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
function New-PhpShieldReport {
    param(
        [Parameter(Mandatory=$true)]$ScanResults,
        $MitigationChecks = @(),
        $WebBindings = @(),
        $ApacheBindings = @(),
        $FpmProcesses = @(),
        $FpmPoolOverrides = @(),
        $ChangedFiles = @(),
        $WebshellScan = @()
    )
    try {
        $vuln  = @($ScanResults | Where-Object { $_.Vulnerable })
        $allFindings = @()
        $hardFails = 0
        foreach ($r in @($ScanResults)) {
            $allFindings += @($r.Findings)
            $hardFails += [int]$r.IniHardeningFails
        }
        $crit  = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $wsHits = @($WebshellScan)
        $wsFiles = @($wsHits | Select-Object -ExpandProperty File -Unique).Count
        $wsCrit  = @($wsHits | Where-Object { $_.Severity -eq 'Critical' }).Count
        $shadow  = @($FpmProcesses | Where-Object { $_.ShadowCopy }).Count
        $poolWeak = @($FpmPoolOverrides | Where-Object { $_.Verdict -eq 'weakens' }).Count
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        return [pscustomobject]@{
            Module       = 'Falsum-PhpShield'
            Version      = $script:PhpShieldVersion
            ScannedUtc   = (Get-Date).ToUniversalTime().ToString('o')
            Installs     = $ScanResults.Count
            Vulnerable   = $vuln.Count
            CriticalHits = $crit
            IniHardeningFails = $hardFails
            WebBindings  = @($WebBindings)
            WebBindingCount = @($WebBindings).Count
            ApacheBindings = @($ApacheBindings)
            ApacheBindingCount = @($ApacheBindings).Count
            FpmProcesses = @($FpmProcesses)
            FpmProcessCount = @($FpmProcesses).Count
            ShadowProcesses = $shadow
            FpmPoolOverrides = @($FpmPoolOverrides)
            FpmPoolFileCount = @(@($FpmPoolOverrides | Select-Object -ExpandProperty PoolFile -Unique)).Count
            FpmPoolWeakened = $poolWeak
            ChangedFiles = @($ChangedFiles)
            ChangedFileCount = @($ChangedFiles).Count
            WebshellHits = $wsHits.Count
            WebshellFiles = $wsFiles
            WebshellCritical = $wsCrit
            WebshellScan = $wsHits
            Results      = $ScanResults
            Mitigations  = $MitigationChecks
            Stamp        = $stamp
        }
    } catch {
        Write-Host "[-] New-PhpShieldReport failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Export-PhpShieldReport {
    param(
        [Parameter(Mandatory=$true)]$Report,
        [string]$OutDir = ''
    )
    try {
        # v1.3 fix: the old default assumed the Desktop special folder always
        # resolves. On Server Core / redirected profiles it can come back
        # empty, and Join-Path then throws. Fall back to a repo-relative dir.
        if ([string]::IsNullOrWhiteSpace($OutDir)) {
            $desk = [Environment]::GetFolderPath('Desktop')
            if ([string]::IsNullOrWhiteSpace($desk)) { $desk = Get-Location }
            $OutDir = Join-Path $desk 'Falsum-Reports'
        }
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $base = "phpshield-$($Report.Stamp)"
        $json = Join-Path $OutDir "$base.json"
        $txt  = Join-Path $OutDir "$base.txt"

        $Report | ConvertTo-Json -Depth 6 | Set-Content $json -Encoding UTF8

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('Falsum PHP Shield report')
        [void]$sb.AppendLine("Scanned (UTC): $($Report.ScannedUtc)")
        [void]$sb.AppendLine("Installs: $($Report.Installs) | Vulnerable: $($Report.Vulnerable) | Critical findings: $($Report.CriticalHits) | Ini-hardening FAILs: $($Report.IniHardeningFails) | IIS web bindings: $($Report.WebBindingCount) | Apache bindings: $($Report.ApacheBindingCount) | Live PHP workers: $($Report.FpmProcessCount) ($($Report.ShadowProcesses) shadow)")
        [void]$sb.AppendLine("Webshell scan: $($Report.WebshellHits) indicator hits in $($Report.WebshellFiles) files ($($Report.WebshellCritical) Critical) | Recently-changed PHP files: $($Report.ChangedFileCount)")
        [void]$sb.AppendLine('')
        foreach ($r in $Report.Results) {
            [void]$sb.AppendLine("INSTALL: $($r.Install)  [source: $($r.Source), active: $($r.IsActive), sapi: $($r.Sapi)]")
            [void]$sb.AppendLine("  version: $($r.Version) | upload_progress: $($r.UploadProgress) | verdict: $($r.Verdict) | ini-hardening fails: $($r.IniHardeningFails)")
            if ($r.MemoryExposure -in @('exposed','backport-only')) {
                [void]$sb.AppendLine("  [MEMORY-EXPOSURE: $($r.MemoryExposure.ToUpper())] $($r.MemoryExposureDetail)")
            }
            foreach ($f in $r.Findings) {
                [void]$sb.AppendLine("  [$($f.Severity)] $($f.Id)")
                [void]$sb.AppendLine("    WHY: $($f.Why)")
                [void]$sb.AppendLine("    FIX: $($f.Fix)")
            }
            $fails = @($r.IniHardening | Where-Object { $_.Pass -eq $false })
            foreach ($hf in $fails) {
                [void]$sb.AppendLine("  [INI-FAIL:$($hf.Severity)] $($hf.Setting) current='$($hf.Current)' recommended='$($hf.Recommended)'")
                [void]$sb.AppendLine("    FIX: $($hf.Fix)")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.WebBindingCount -gt 0) {
            [void]$sb.AppendLine('IIS WEB BINDINGS (php-cgi FastCGI registrations):')
            foreach ($b in $Report.WebBindings) {
                $mm = if ($b.MatchedInstall) { "matches install: $($b.MatchedInstall)" } else { 'no discovered install in that dir — investigate' }
                [void]$sb.AppendLine("  $($b.PhpCgiPath) — $mm — *.php handler: $($b.HandlerMapsPhp)")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.ApacheBindingCount -gt 0) {
            [void]$sb.AppendLine('APACHE PHP BINDINGS (httpd.conf + includes):')
            foreach ($b in $Report.ApacheBindings) {
                $mm = if ($b.MatchedInstall) { "matches install: $($b.MatchedInstall)" } else { '' }
                [void]$sb.AppendLine("  [$($b.Kind)] $($b.Detail) $mm (line $($b.Line) of $($b.ConfigFile))")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.FpmPoolWeakened -gt 0 -or @($Report.FpmPoolOverrides).Count -gt 0) {
            [void]$sb.AppendLine("FPM POOL OVERRIDES (php-fpm pool confs can re-arm settings php.ini disabled):")
            foreach ($o in ($Report.FpmPoolOverrides | Where-Object { $_.Verdict -eq 'weakens' })) {
                [void]$sb.AppendLine("  [WEAKENS:$($o.Severity)] $($o.Setting)=$($o.Value) — $($o.PoolFile):$($o.Line) (pool [$($o.Pool)])")
                [void]$sb.AppendLine("    FIX: $($o.Fix)")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.FpmProcessCount -gt 0) {
            [void]$sb.AppendLine('LIVE PHP WORKERS:')
            foreach ($p in $Report.FpmProcesses) {
                $tag = if ($p.ShadowCopy) { ' [SHADOW — no discovered install: investigate]' } else { " [$($p.MatchedInstall)]" }
                [void]$sb.AppendLine("  PID $($p.Pid) $($p.ProcessName): $($p.Path)$tag (started $($p.StartTimeUtc))")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.ChangedFileCount -gt 0) {
            [void]$sb.AppendLine('RECENTLY-CHANGED PHP FILES (webshell-drop timing signal):')
            foreach ($f in $Report.ChangedFiles) {
                [void]$sb.AppendLine("  $($f.File) — $($f.LastWriteUtc) — SHA-256 $($f.Sha256)")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.Mitigations.Count -gt 0) {
            [void]$sb.AppendLine('MITIGATION VERIFICATION:')
            foreach ($m in $Report.Mitigations) {
                $s = if ($m.Pass) { 'PASS' } else { 'FAIL' }
                [void]$sb.AppendLine("  [$s] $($m.Layer) — $($m.Detail)")
            }
            [void]$sb.AppendLine('')
        }
        if ($Report.WebshellHits -gt 0) {
            [void]$sb.AppendLine('WEBSHELL SCAN HITS (review before quarantining — see Move-PhpSuspiciousFileToQuarantine):')
            foreach ($h in $Report.WebshellScan) {
                [void]$sb.AppendLine("  [$($h.Severity)] $($h.File):$($h.Line) — $($h.Indicator)")
                [void]$sb.AppendLine("    SHA-256 $($h.Sha256)")
                [void]$sb.AppendLine("    $($h.Snippet)")
            }
        }
        Set-Content $txt -Value $sb.ToString() -Encoding UTF8

        $hashes = @{}
        foreach ($f in @($json, $txt)) {
            $h = (Get-FileHash $f -Algorithm SHA256).Hash
            $hashes[$f] = $h
            Write-Host "    SHA-256 $h  $(Split-Path $f -Leaf)"
        }
        $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
        Write-PhpShieldVaultLog -Summary "PHP shield $stamp UTC: $($Report.Installs) installs, $($Report.Vulnerable) vulnerable, $($Report.CriticalHits) critical, $($Report.IniHardeningFails) ini-hardening FAILs, $($Report.WebBindingCount) IIS bindings, $($Report.ApacheBindingCount) Apache bindings, $($Report.FpmProcessCount) live workers ($($Report.ShadowProcesses) shadow), $($Report.ChangedFileCount) changed files" -DataHash $hashes[$json]
        Write-Host "[+] Report exported to $OutDir" -ForegroundColor Green
        return [pscustomobject]@{ Json = $json; Txt = $txt; Hashes = $hashes }
    } catch {
        Write-Host "[-] Export-PhpShieldReport failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

Write-Host "[*] Falsum PHP Shield v$script:PhpShieldVersion loaded. Run Test-PhpInstalls to scan." -ForegroundColor Cyan
