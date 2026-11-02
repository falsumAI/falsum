<#
Module 05 — PEOPLE TRACK (username enumeration + exposure remediation)

Enumerates a username across 200+ sites (built-in table from
Maigret/Sherlock/WhatsMyName URL patterns, {user} placeholder) across
12 categories.
Parallel HTTP checks with per-site calibration: every site is first
probed with a guaranteed-nonexistent username, so the score measures
divergence from the site's own "not found" baseline — not a naive
status-code guess. Scoring is 0-100 per hit with confidence labels
(high/medium/weak/none/uncertain). Binary "found" claims are never
made: a 403/429/redirect is reported as what it is.

Email breach hook: HIBP v3 API (key read from a file you supply,
never hardcoded; graceful without a key).

THE BETTER WAY: a scan that only tells you "you're exposed" is
unfinished work. Every detection ships its fix: New-RemediationPlan
builds a concrete per-account hardening checklist (exact settings
to change, in priority order), plus the global cleanup sequence
(breach check -> broker removal -> rotation -> 2FA -> re-scan).

RESPONSIBLE USE: run this on YOUR OWN usernames, or on usernames you
have authorization to investigate. Mass enumeration of other people
violates most sites' terms and can be harassment. Unauthorized access
to anyone else's systems is a federal crime under the CFAA.

Dot-source:
  . .\Falsum-PeopleTrack.ps1
  $results = Test-Username -Username "somehandle"
  $dossier  = Get-Dossier -Username "somehandle" -Results $results
  Export-Dossier -Dossier $dossier -OutputDir "C:\Falsum\people"
  # or the whole pipeline in one call:
  Invoke-PeopleTrack -Username "somehandle" -Email "you@example.com" -OutputDir "C:\Falsum\people"
  # handle variants for thorough sweeps (one handle is one searchable identity):
  $variants = Get-UsernameVariants -Username "somehandle"
  # re-scan in 30 days and PROVE the cleanup worked:
  Compare-Dossier -OldPath ".\somehandle-20261001-000000-dossier.json" -NewPath ".\somehandle-20261101-000000-dossier.json"
#>

$script:CoherenceLoaded = $false
$script:VaultLoaded = $false
$script:VaultPath = ""

function Import-CoherenceCore {
    if ($script:CoherenceLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $core = Join-Path (Split-Path -Parent $here) "00-coherence-core\Falsum-Coherence.ps1"
    if (-not (Test-Path $core)) {
        $core = Join-Path $here "..\00-coherence-core\Falsum-Coherence.ps1"
    }
    if (Test-Path $core) { . $core; $script:CoherenceLoaded = $true }
    else { Write-Host "[!] coherence core not found at $core — dossiers will lack receipts" }
}

function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — scans will not be vault-logged" }
}

function New-PeopleLog {
    <#
    Logs a scan/dossier to the vault (type "people-track"). Silent when
    the vault module failed to load or no vault path was given — never
    blocks a scan.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)]$Data
    )
    if (-not $script:VaultLoaded -or [string]::IsNullOrWhiteSpace($script:VaultPath)) { return }
    try {
        $vault = New-Vault -path $script:VaultPath
        Add-VaultEntry -vault $vault -type "people-track" -data @{
            action   = $Action
            username = $Username
            data     = $Data
        } | Out-Null
        Write-Host "[vault] logged people-track/$Action for '$Username'"
    } catch {
        Write-Host "[!] vault log failed: $($_.Exception.Message)"
    }
}

function Get-SiteTable {
    <#
    The built-in site table: 290+ username-checkable sites with URL
    patterns ({user} placeholder), categories, and a couple of
    high-confidence not-found markers. Scoring NEVER depends on a
    marker alone -- calibration probing is the primary discriminator;
    markers are bonus evidence. Test-SiteTableValidation confirms every
    entry has a {user} placeholder and unique names before a scan runs.
    #>
    $raw = @(
        # --- Code (16) ---
        @{ Name="GitHub";       Category="Code"; Url="https://github.com/{user}";            FoundMarker=""; NotFoundMarker="Page not found" }
        @{ Name="GitLab";       Category="Code"; Url="https://gitlab.com/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Codeberg";     Category="Code"; Url="https://codeberg.org/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Gitee";        Category="Code"; Url="https://gitee.com/{user}";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="Bitbucket";    Category="Code"; Url="https://bitbucket.org/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="npm";          Category="Code"; Url="https://www.npmjs.com/~{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="PyPI";         Category="Code"; Url="https://pypi.org/user/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="RubyGems";     Category="Code"; Url="https://rubygems.org/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="crates.io";    Category="Code"; Url="https://crates.io/users/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Docker Hub";   Category="Code"; Url="https://hub.docker.com/u/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hugging Face"; Category="Code"; Url="https://huggingface.co/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Kaggle";       Category="Code"; Url="https://www.kaggle.com/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="CodePen";      Category="Code"; Url="https://codepen.io/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Replit";       Category="Code"; Url="https://replit.com/@{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="Dev.to";       Category="Code"; Url="https://dev.to/{user}";                FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hackaday.io";  Category="Code"; Url="https://hackaday.io/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="SourceHut";    Category="Code"; Url="https://sr.ht/~{user}";                FoundMarker=""; NotFoundMarker="" }
        @{ Name="Savannah";     Category="Code"; Url="https://savannah.gnu.org/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Launchpad";    Category="Code"; Url="https://launchpad.net/~{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="SourceForge";  Category="Code"; Url="https://sourceforge.net/u/{user}/profile"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Open Hub";     Category="Code"; Url="https://www.openhub.net/accounts/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="JSFiddle";     Category="Code"; Url="https://jsfiddle.net/user/{user}";      FoundMarker=""; NotFoundMarker="" }
        # --- Social (18) ---
        @{ Name="X";            Category="Social"; Url="https://x.com/{user}";                     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Instagram";    Category="Social"; Url="https://www.instagram.com/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="Threads";      Category="Social"; Url="https://www.threads.com/@{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="TikTok";       Category="Social"; Url="https://www.tiktok.com/@{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="Facebook";     Category="Social"; Url="https://www.facebook.com/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Pinterest";    Category="Social"; Url="https://www.pinterest.com/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="LinkedIn";     Category="Social"; Url="https://www.linkedin.com/in/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Mastodon";     Category="Social"; Url="https://mastodon.social/@{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Bluesky";      Category="Social"; Url="https://bsky.app/profile/{user}.bsky.social"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Reddit";       Category="Social"; Url="https://www.reddit.com/user/{user}";       FoundMarker=""; NotFoundMarker="nobody on Reddit goes by that name" }
        @{ Name="Telegram";     Category="Social"; Url="https://t.me/{user}";                      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Minds";        Category="Social"; Url="https://www.minds.com/{user}";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Disqus";       Category="Social"; Url="https://disqus.com/by/{user}";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Linktree";     Category="Social"; Url="https://linktr.ee/{user}";                 FoundMarker=""; NotFoundMarker="" }
        @{ Name="about.me";     Category="Social"; Url="https://about.me/{user}";                  FoundMarker=""; NotFoundMarker="" }
        @{ Name="Gravatar";     Category="Social"; Url="https://gravatar.com/{user}";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="Keybase";      Category="Social"; Url="https://keybase.io/{user}";                FoundMarker=""; NotFoundMarker="" }
        @{ Name="Flipboard";    Category="Social"; Url="https://flipboard.com/@{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Quora";        Category="Social"; Url="https://www.quora.com/profile/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Snapchat";     Category="Social"; Url="https://www.snapchat.com/add/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Gab";          Category="Social"; Url="https://gab.com/{user}";                    FoundMarker=""; NotFoundMarker="" }
        @{ Name="GETTR";        Category="Social"; Url="https://gettr.com/user/{user}";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Pixelfed";     Category="Social"; Url="https://pixelfed.social/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="MeWe";         Category="Social"; Url="https://mewe.com/i/{user}";                 FoundMarker=""; NotFoundMarker="" }
        @{ Name="VK";           Category="Social"; Url="https://vk.com/{user}";                     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Truth Social"; Category="Social"; Url="https://truthsocial.com/@{user}";           FoundMarker=""; NotFoundMarker="" }
        # --- Video (6) ---
        @{ Name="YouTube";      Category="Video"; Url="https://www.youtube.com/@{user}";  FoundMarker=""; NotFoundMarker="" }
        @{ Name="Twitch";       Category="Video"; Url="https://www.twitch.tv/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Vimeo";        Category="Video"; Url="https://vimeo.com/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Dailymotion";  Category="Video"; Url="https://www.dailymotion.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Rumble";       Category="Video"; Url="https://rumble.com/user/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Odysee";       Category="Video"; Url="https://odysee.com/@{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="BitChute";     Category="Video"; Url="https://www.bitchute.com/channel/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Kick";         Category="Video"; Url="https://kick.com/{user}";           FoundMarker=""; NotFoundMarker="" }
        # --- Audio (4) ---
        @{ Name="SoundCloud";   Category="Audio"; Url="https://soundcloud.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Mixcloud";     Category="Audio"; Url="https://www.mixcloud.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Bandcamp";     Category="Audio"; Url="https://{user}.bandcamp.com";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Last.fm";      Category="Audio"; Url="https://www.last.fm/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Audiomack";    Category="Audio"; Url="https://audiomack.com/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="hearthis.at";  Category="Audio"; Url="https://hearthis.at/{user}";        FoundMarker=""; NotFoundMarker="" }
        # --- Gaming (12) ---
        @{ Name="Steam";        Category="Gaming"; Url="https://steamcommunity.com/id/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Chess.com";    Category="Gaming"; Url="https://www.chess.com/member/{user}";  FoundMarker=""; NotFoundMarker="" }
        @{ Name="Lichess";      Category="Gaming"; Url="https://lichess.org/@/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="Roblox";       Category="Gaming"; Url="https://www.roblox.com/users/profile?username={user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Minecraft";    Category="Gaming"; Url="https://api.mojang.com/users/profiles/minecraft/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="TryHackMe";    Category="Gaming"; Url="https://tryhackme.com/p/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Codewars";     Category="Gaming"; Url="https://www.codewars.com/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Exercism";     Category="Gaming"; Url="https://exercism.org/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="LeetCode";     Category="Gaming"; Url="https://leetcode.com/u/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="HackerRank";   Category="Gaming"; Url="https://www.hackerrank.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Codecademy";   Category="Gaming"; Url="https://www.codecademy.com/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="HackerOne";    Category="Gaming"; Url="https://hackerone.com/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="PSNProfiles";  Category="Gaming"; Url="https://psnprofiles.com/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="speedrun.com"; Category="Gaming"; Url="https://www.speedrun.com/users/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Game Jolt";    Category="Gaming"; Url="https://gamejolt.com/@{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Kongregate";   Category="Gaming"; Url="https://www.kongregate.com/accounts/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Newgrounds";   Category="Gaming"; Url="https://{user}.newgrounds.com";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="BoardGameGeek";Category="Gaming"; Url="https://boardgamegeek.com/user/{user}";   FoundMarker=""; NotFoundMarker="" }
        # --- Writing (13) ---
        @{ Name="Medium";       Category="Writing"; Url="https://medium.com/@{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Substack";     Category="Writing"; Url="https://substack.com/@{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hashnode";     Category="Writing"; Url="https://hashnode.com/@{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Blogger";      Category="Writing"; Url="https://{user}.blogspot.com";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="WordPress.com";Category="Writing"; Url="https://{user}.wordpress.com";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Tumblr";       Category="Writing"; Url="https://{user}.tumblr.com";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="LiveJournal";  Category="Writing"; Url="https://{user}.livejournal.com";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Dreamwidth";   Category="Writing"; Url="https://{user}.dreamwidth.org";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hacker News";  Category="Writing"; Url="https://news.ycombinator.com/user?id={user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Wattpad";      Category="Writing"; Url="https://www.wattpad.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="AO3";          Category="Writing"; Url="https://archiveofourown.org/users/{user}/pseuds/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="MyAnimeList";  Category="Writing"; Url="https://myanimelist.net/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="AniList";      Category="Writing"; Url="https://anilist.co/user/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="LibraryThing"; Category="Writing"; Url="https://www.librarything.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Lobsters";     Category="Writing"; Url="https://lobste.rs/u/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="Tildes";       Category="Writing"; Url="https://tildes.net/user/{user}";       FoundMarker=""; NotFoundMarker="" }
        # --- Design (9) ---
        @{ Name="VSCO";         Category="Design"; Url="https://vsco.co/{user}";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="Flickr";       Category="Design"; Url="https://www.flickr.com/people/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="500px";        Category="Design"; Url="https://500px.com/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="DeviantArt";   Category="Design"; Url="https://www.deviantart.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="ArtStation";   Category="Design"; Url="https://www.artstation.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Behance";      Category="Design"; Url="https://www.behance.net/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Dribbble";     Category="Design"; Url="https://dribbble.com/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="itch.io";      Category="Design"; Url="https://itch.io/profile/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Slideshare";   Category="Design"; Url="https://www.slideshare.net/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="99designs";    Category="Design"; Url="https://99designs.com/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Cargo";        Category="Design"; Url="https://{user}.cargo.site";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Sketchfab";    Category="Design"; Url="https://sketchfab.com/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Redbubble";    Category="Design"; Url="https://www.redbubble.com/people/{user}/shop"; FoundMarker=""; NotFoundMarker="" }
        # --- Marketplace (8) ---
        @{ Name="Kickstarter";  Category="Marketplace"; Url="https://www.kickstarter.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Gumroad";      Category="Marketplace"; Url="https://gumroad.com/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Etsy";         Category="Marketplace"; Url="https://www.etsy.com/people/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="eBay";         Category="Marketplace"; Url="https://www.ebay.com/usr/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Poshmark";     Category="Marketplace"; Url="https://poshmark.com/closet/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Depop";        Category="Marketplace"; Url="https://www.depop.com/{user}";    FoundMarker=""; NotFoundMarker="" }
        @{ Name="Fiverr";       Category="Marketplace"; Url="https://www.fiverr.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Freelancer";   Category="Marketplace"; Url="https://www.freelancer.com/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Mercari";      Category="Marketplace"; Url="https://www.mercari.com/u/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Discogs";      Category="Marketplace"; Url="https://www.discogs.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        # --- Finance (6) ---
        @{ Name="Patreon";      Category="Finance"; Url="https://www.patreon.com/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Ko-fi";        Category="Finance"; Url="https://ko-fi.com/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="BuyMeACoffee"; Category="Finance"; Url="https://www.buymeacoffee.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="OpenCollective"; Category="Finance"; Url="https://opencollective.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Liberapay";    Category="Finance"; Url="https://liberapay.com/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Venmo";        Category="Finance"; Url="https://venmo.com/u/{user}";         FoundMarker=""; NotFoundMarker="" }
        @{ Name="Cash App";     Category="Finance"; Url='https://cash.app/${user}';             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Tipeee";       Category="Finance"; Url="https://en.tipeee.com/{user}";         FoundMarker=""; NotFoundMarker="" }
        # --- Professional (4) ---
        @{ Name="Product Hunt";  Category="Professional"; Url="https://www.producthunt.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Indie Hackers";Category="Professional"; Url="https://www.indiehackers.com/{user}";  FoundMarker=""; NotFoundMarker="" }
        @{ Name="Wellfound";    Category="Professional"; Url="https://wellfound.com/u/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Instructables";Category="Professional"; Url="https://www.instructables.com/member/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Speaker Deck"; Category="Professional"; Url="https://speakerdeck.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Crunchbase";   Category="Professional"; Url="https://www.crunchbase.com/person/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Xing";         Category="Professional"; Url="https://www.xing.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="StackShare";   Category="Professional"; Url="https://stackshare.io/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="Polywork";     Category="Professional"; Url="https://polywork.com/{user}";      FoundMarker=""; NotFoundMarker="" }
        # --- Media (4) ---
        @{ Name="Imgur";        Category="Media"; Url="https://imgur.com/user/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Unsplash";     Category="Media"; Url="https://unsplash.com/@{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Letterboxd";   Category="Media"; Url="https://letterboxd.com/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Trakt";        Category="Media"; Url="https://trakt.tv/users/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Pexels";       Category="Media"; Url="https://www.pexels.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="GIPHY";        Category="Media"; Url="https://giphy.com/channel/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Tenor";        Category="Media"; Url="https://tenor.com/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Spotify";      Category="Media"; Url="https://open.spotify.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        # --- Misc (10) ---
        @{ Name="Pastebin";     Category="Misc"; Url="https://pastebin.com/u/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="pronouns.page";Category="Misc"; Url="https://pronouns.page/@{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Carrd";        Category="Misc"; Url="https://{user}.carrd.co";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="AllMyLinks";   Category="Misc"; Url="https://allmylinks.com/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Duolingo";     Category="Misc"; Url="https://www.duolingo.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Quizlet";      Category="Misc"; Url="https://quizlet.com/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="Internet Archive"; Category="Misc"; Url="https://archive.org/details/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Untappd";      Category="Misc"; Url="https://untappd.com/user/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="RateYourMusic";Category="Misc"; Url="https://rateyourmusic.com/~{user}";    FoundMarker=""; NotFoundMarker="" }
        @{ Name="MyDramaList";  Category="Misc"; Url="https://mydramalist.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        # --- Hardening v1.2 additions (20) ---
        @{ Name="Observable";   Category="Code"; Url="https://observablehq.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Glitch";       Category="Code"; Url="https://glitch.com/@{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="NotABug";      Category="Code"; Url="https://notabug.org/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Framagit";     Category="Code"; Url="https://framagit.org/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Audius";       Category="Audio"; Url="https://audius.co/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="BandLab";      Category="Audio"; Url="https://bandlab.com/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="Plurk";        Category="Social"; Url="https://plurk.com/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Ravelry";      Category="Social"; Url="https://ravelry.com/people/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="RetroAchievements"; Category="Gaming"; Url="https://retroachievements.org/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Backloggd";    Category="Gaming"; Url="https://backloggd.com/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Quotev";       Category="Writing"; Url="https://quotev.com/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="FanFiction.net";Category="Writing"; Url="https://www.fanfiction.net/~{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Cara";         Category="Design"; Url="https://cara.app/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Neocities";    Category="Design"; Url="https://{user}.neocities.org";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Subscribestar";Category="Finance"; Url="https://www.subscribestar.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="ResearchGate"; Category="Professional"; Url="https://www.researchgate.net/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Serializd";    Category="Media"; Url="https://serializd.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Bento";        Category="Misc"; Url="https://bento.me/{user}";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Beacons";      Category="Misc"; Url="https://beacons.ai/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Campsite";     Category="Misc"; Url="https://campsite.bio/{user}";      FoundMarker=""; NotFoundMarker="" }
        # --- Hardening v1.3 additions (40) ---
        @{ Name="WakaTime";     Category="Code"; Url="https://wakatime.com/@{user}";                FoundMarker=""; NotFoundMarker="" }
        @{ Name="CodersRank";   Category="Code"; Url="https://profile.codersrank.io/user/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Devfolio";     Category="Code"; Url="https://devfolio.co/@{user}";                 FoundMarker=""; NotFoundMarker="" }
        @{ Name="Codeforces";   Category="Gaming"; Url="https://codeforces.com/profile/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="AtCoder";      Category="Gaming"; Url="https://atcoder.jp/users/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="CodeChef";     Category="Gaming"; Url="https://www.codechef.com/users/{user}";     FoundMarker=""; NotFoundMarker="" }
        @{ Name="HackerEarth";  Category="Gaming"; Url="https://www.hackerearth.com/@{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="TopCoder";     Category="Gaming"; Url="https://profiles.topcoder.com/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="ModDB";        Category="Gaming"; Url="https://www.moddb.com/members/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="GOG";          Category="Gaming"; Url="https://www.gog.com/u/{user}";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="TrueAchievements"; Category="Gaming"; Url="https://www.trueachievements.com/gamer/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="TrueTrophies"; Category="Gaming"; Url="https://www.truetrophies.com/gamer/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Exophase";     Category="Gaming"; Url="https://www.exophase.com/user/{user}";      FoundMarker=""; NotFoundMarker="" }
        @{ Name="IndieDB";      Category="Gaming"; Url="https://www.indiedb.com/members/{user}";    FoundMarker=""; NotFoundMarker="" }
        @{ Name="Amino";        Category="Social"; Url="http://aminoapps.com/u/{user}";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Locals";       Category="Social"; Url="https://{user}.locals.com";                 FoundMarker=""; NotFoundMarker="" }
        @{ Name="ReverbNation"; Category="Audio"; Url="https://www.reverbnation.com/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Smule";        Category="Audio"; Url="https://www.smule.com/{user}";               FoundMarker=""; NotFoundMarker="" }
        @{ Name="Royal Road";   Category="Writing"; Url="https://www.royalroad.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Scribble Hub"; Category="Writing"; Url="https://www.scribblehub.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Inkitt";       Category="Writing"; Url="https://www.inkitt.com/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="StoryGraph";   Category="Writing"; Url="https://app.thestorygraph.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Issuu";        Category="Writing"; Url="https://issuu.com/{user}";                 FoundMarker=""; NotFoundMarker="" }
        @{ Name="MyMiniFactory";Category="Design"; Url="https://www.myminifactory.com/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Cults3D";      Category="Design"; Url="https://cults3d.com/en/users/{user}/3d-models"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Thingiverse";  Category="Design"; Url="https://www.thingiverse.com/{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Printables";   Category="Design"; Url="https://www.printables.com/@{user}";        FoundMarker=""; NotFoundMarker="" }
        @{ Name="Carbonmade";   Category="Design"; Url="https://{user}.carbonmade.com";             FoundMarker=""; NotFoundMarker="" }
        @{ Name="Fur Affinity"; Category="Design"; Url="https://www.furaffinity.net/user/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Weasyl";       Category="Design"; Url="https://www.weasyl.com/~{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Calameo";      Category="Design"; Url="https://www.calameo.com/accounts/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Sellfy";       Category="Marketplace"; Url="https://{user}.sellfy.store";          FoundMarker=""; NotFoundMarker="" }
        @{ Name="Payhip";       Category="Marketplace"; Url="https://payhip.com/{user}";            FoundMarker=""; NotFoundMarker="" }
        @{ Name="Grailed";      Category="Marketplace"; Url="https://www.grailed.com/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="Reverb";       Category="Marketplace"; Url="https://reverb.com/shop/{user}";       FoundMarker=""; NotFoundMarker="" }
        @{ Name="StreamElements"; Category="Finance"; Url="https://streamelements.com/{user}/tip";  FoundMarker=""; NotFoundMarker="" }
        @{ Name="Kitsu";        Category="Media"; Url="https://kitsu.io/users/{user}";              FoundMarker=""; NotFoundMarker="" }
        @{ Name="iCheckMovies"; Category="Media"; Url="https://www.icheckmovies.com/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Criticker";    Category="Media"; Url="https://www.criticker.com/profile/{user}";   FoundMarker=""; NotFoundMarker="" }
        @{ Name="Wallhaven";    Category="Media"; Url="https://wallhaven.cc/user/{user}";           FoundMarker=""; NotFoundMarker="" }
        @{ Name="Codeberg Pages"; Category="Code"; Url="https://{user}.codeberg.page"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="GitHub Gist"; Category="Code"; Url="https://gist.github.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Packagist"; Category="Code"; Url="https://packagist.org/packages/{user}/"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="NuGet"; Category="Code"; Url="https://www.nuget.org/profiles/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hex.pm"; Category="Code"; Url="https://hex.pm/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Observable"; Category="Code"; Url="https://observablehq.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Glitch"; Category="Code"; Url="https://glitch.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="CodeSandbox"; Category="Code"; Url="https://codesandbox.io/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="StackBlitz"; Category="Code"; Url="https://stackblitz.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Vercel"; Category="Code"; Url="https://vercel.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Netlify"; Category="Code"; Url="https://app.netlify.com/teams/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Diaspora"; Category="Social"; Url="https://diasporafoundation.org/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Misskey"; Category="Social"; Url="https://misskey.io/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Fosstodon"; Category="Social"; Url="https://fosstodon.org/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hachyderm"; Category="Social"; Url="https://hachyderm.io/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Mstdn"; Category="Social"; Url="https://mstdn.social/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Spoutible"; Category="Social"; Url="https://spoutible.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Nostr"; Category="Social"; Url="https://nostr.band/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Stack Overflow"; Category="Forum"; Url="https://stackoverflow.com/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hacker News"; Category="Forum"; Url="https://news.ycombinator.com/user?id={user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Lobsters"; Category="Forum"; Url="https://lobste.rs/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Tildes"; Category="Forum"; Url="https://tildes.net/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Lemmy"; Category="Forum"; Url="https://lemmy.world/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="XDA Developers"; Category="Forum"; Url="https://forum.xda-developers.com/m/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Linus Tech Tips"; Category="Forum"; Url="https://linustechtips.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Epic Games"; Category="Gaming"; Url="https://www.epicgames.com/id/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="GOG"; Category="Gaming"; Url="https://www.gog.com/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Itch.io"; Category="Gaming"; Url="https://{user}.itch.io"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Game Jolt"; Category="Gaming"; Url="https://gamejolt.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Newgrounds"; Category="Gaming"; Url="https://{user}.newgrounds.com"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Speedrun.com"; Category="Gaming"; Url="https://www.speedrun.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Faceit"; Category="Gaming"; Url="https://www.faceit.com/en/players/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Chess24"; Category="Gaming"; Url="https://chess24.com/en/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="BoardGameGeek"; Category="Gaming"; Url="https://boardgamegeek.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Wellfound"; Category="Professional"; Url="https://wellfound.com/u/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Crunchbase"; Category="Professional"; Url="https://www.crunchbase.com/person/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Dribbble"; Category="Professional"; Url="https://dribbble.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Behance"; Category="Professional"; Url="https://www.behance.net/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Muck Rack"; Category="Professional"; Url="https://muckrack.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="ResearchGate"; Category="Professional"; Url="https://www.researchgate.net/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="ORCID"; Category="Professional"; Url="https://orcid.org/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Speaker Deck"; Category="Professional"; Url="https://speakerdeck.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="SlideShare"; Category="Professional"; Url="https://www.slideshare.net/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="DeviantArt"; Category="Creative"; Url="https://www.deviantart.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="ArtStation"; Category="Creative"; Url="https://www.artstation.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Pixiv"; Category="Creative"; Url="https://www.pixiv.net/en/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Cara"; Category="Creative"; Url="https://cara.app/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Wattpad"; Category="Creative"; Url="https://www.wattpad.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Archive of Our Own"; Category="Creative"; Url="https://archiveofourown.org/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Royal Road"; Category="Creative"; Url="https://www.royalroad.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Medium"; Category="Creative"; Url="https://medium.com/@{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Substack"; Category="Creative"; Url="https://{user}.substack.com"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Hashnode"; Category="Creative"; Url="https://{user}.hashnode.dev"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Etsy"; Category="Marketplace"; Url="https://www.etsy.com/shop/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="eBay"; Category="Marketplace"; Url="https://www.ebay.com/usr/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Depop"; Category="Marketplace"; Url="https://www.depop.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Poshmark"; Category="Marketplace"; Url="https://poshmark.com/closet/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Fiverr"; Category="Marketplace"; Url="https://www.fiverr.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Upwork"; Category="Marketplace"; Url="https://www.upwork.com/freelancers/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Letterboxd"; Category="Media"; Url="https://letterboxd.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Trakt"; Category="Media"; Url="https://trakt.tv/users/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="MyAnimeList"; Category="Media"; Url="https://myanimelist.net/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="AniList"; Category="Media"; Url="https://anilist.co/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Goodreads"; Category="Media"; Url="https://www.goodreads.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="RateYourMusic"; Category="Media"; Url="https://rateyourmusic.com/~{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Discogs"; Category="Media"; Url="https://www.discogs.com/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="MusicBrainz"; Category="Media"; Url="https://musicbrainz.org/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Patreon"; Category="Finance"; Url="https://www.patreon.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Ko-fi"; Category="Finance"; Url="https://ko-fi.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="BuyMeACoffee"; Category="Finance"; Url="https://www.buymeacoffee.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Liberapay"; Category="Finance"; Url="https://liberapay.com/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="PayPal.me"; Category="Finance"; Url="https://www.paypal.me/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Strava"; Category="Fitness"; Url="https://www.strava.com/athletes/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Couchsurfing"; Category="Travel"; Url="https://www.couchsurfing.com/people/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="TripAdvisor"; Category="Travel"; Url="https://www.tripadvisor.com/members/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Duolingo"; Category="Education"; Url="https://www.duolingo.com/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Khan Academy"; Category="Education"; Url="https://www.khanacademy.org/profile/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="Coursera"; Category="Education"; Url="https://www.coursera.org/user/{user}"; FoundMarker=""; NotFoundMarker="" }
        @{ Name="247sports"; Category="Hobby"; Url="https://247sports.com/User/{user}/"; FoundMarker="staff-header-container"; NotFoundMarker="<title>247Sports</title>" }
        @{ Name="35photo"; Category="Hobby"; Url="https://35photo.pro/@{user}/"; FoundMarker="userNameBlock"; NotFoundMarker="" }
        @{ Name="3dtoday"; Category="Hobby"; Url="https://3dtoday.ru/blogs/{user}"; FoundMarker="class=`"header_user_name"; NotFoundMarker="" }
        @{ Name="7cup"; Category="Social"; Url="https://www.7cups.com/@{user}"; FoundMarker="Profile - 7 Cups"; NotFoundMarker="Oops! The content you're attempting to access could not be found." }
        @{ Name="7dach"; Category="Social"; Url="https://7dach.ru/profile/{user}"; FoundMarker="Информация / Профиль"; NotFoundMarker="<title>Ошибка / 7dach.ru" }
        @{ Name="ACF"; Category="Code"; Url="https://support.advancedcustomfields.com/forums/users/{user}/"; FoundMarker="bbp-user-body"; NotFoundMarker="<title>Page Not Found - ACF Support</title>" }
        @{ Name="AdmireMe.VIP"; Category="Xx nsfw xx"; Url="https://admireme.vip/{user}/"; FoundMarker="creator-stat subscriber"; NotFoundMarker="<title>Page Not Found |" }
        @{ Name="adultism"; Category="Xx nsfw xx"; Url="https://www.adultism.com/profile/{user}"; FoundMarker="Last login:"; NotFoundMarker="<title> Not Found" }
        @{ Name="ADVFN"; Category="Finance"; Url="https://uk.advfn.com/forum/profile/{user}"; FoundMarker="Profile | ADVFN"; NotFoundMarker="ADVFN ERROR - Page Not Found" }
        @{ Name="alik"; Category="Social"; Url="https://www.alik.cz/u/{user}"; FoundMarker="Vizitka – Alík.cz</title>"; NotFoundMarker="<title>Vizitka nenalezena" }
        @{ Name="Alura"; Category="Tech"; Url="https://cursos.alura.com.br/user/{user}"; FoundMarker="Perfil de"; NotFoundMarker="`"error`":`"Not Found`"" }
        @{ Name="Ameblo"; Category="Creative"; Url="https://ameblo.jp/{user}"; FoundMarker="画像一覧"; NotFoundMarker="削除された可能性がございます。" }
        @{ Name="AmericanThinker"; Category="Political"; Url="https://www.americanthinker.com/author/{user}/"; FoundMarker="class=`"author_image`""; NotFoundMarker="title>404 Not Found</title>" }
        @{ Name="Aparat"; Category="Video"; Url="https://www.aparat.com/api/fa/v1/user/user/information/username/{user}"; FoundMarker="`"data`":{"; NotFoundMarker="`"status`":404" }
        @{ Name="Apex Legends"; Category="Gaming"; Url="https://api.tracker.gg/api/v2/apex/standard/profile/origin/{user}"; FoundMarker="platformInfo"; NotFoundMarker="CollectorResultStatus::NotFound" }
        @{ Name="appian Community"; Category="Tech"; Url="https://community.appian.com/members/{user}"; FoundMarker="class=`"avatar-container"; NotFoundMarker="" }
        @{ Name="Arch Linux GitLab"; Category="Social"; Url="https://gitlab.archlinux.org/api/v4/users?username={user}"; FoundMarker="`"username`":"; NotFoundMarker="[]" }
        @{ Name="Arduino (Forum)"; Category="Tech"; Url="https://forum.arduino.cc/u/{user}.json"; FoundMarker="`"id`":"; NotFoundMarker="`"error_type`":`"not_found`"" }
        @{ Name="Arduino (Project Hub)"; Category="Tech"; Url="https://projecthub.arduino.cc/{user}"; FoundMarker="`"userInfo`":{"; NotFoundMarker="`"userInfo`":null" }
        @{ Name="ArmorGames"; Category="Gaming"; Url="https://armorgames.com/user/{user}"; FoundMarker="about"; NotFoundMarker="404: Oh Noes!" }
        @{ Name="Arsmate"; Category="Xx nsfw xx"; Url="https://arsmate.com/api/creators/{user}"; FoundMarker="`"success`":true"; NotFoundMarker="404,`"Server Error" }
        @{ Name="Artbreeder"; Category="Creative"; Url="https://www.artbreeder.com/{user}"; FoundMarker="data-tutorial=`"profile-filter`""; NotFoundMarker="error: {message:`"User not found`"" }
        @{ Name="asciinema"; Category="Code"; Url="https://asciinema.org/~{user}"; FoundMarker="class=`"profile-page`""; NotFoundMarker="<h1>404 Not Found</h1>" }
        @{ Name="au.ru"; Category="Misc"; Url="https://au.ru/user/{user}/"; FoundMarker="Лоты пользователя"; NotFoundMarker="Пользователь не найден" }
        @{ Name="Audiojungle"; Category="Audio"; Url="https://audiojungle.net/user/{user}"; FoundMarker="s profile on AudioJungle"; NotFoundMarker="404 - Nothing to see here" }
        @{ Name="Avid Community"; Category="Audio"; Url="https://community.avid.com/members/{user}/default.aspx"; FoundMarker="My Activity"; NotFoundMarker="The user you requested cannot be found." }
        @{ Name="babepedia"; Category="Xx nsfw xx"; Url="https://www.babepedia.com/user/{user}"; FoundMarker="'s Profile</title>"; NotFoundMarker="Profile not found" }
        @{ Name="BabyPips"; Category="Social"; Url="https://forums.babypips.com/u/{user}.json"; FoundMarker="user_badges"; NotFoundMarker="The requested URL or resource could not be found" }
        @{ Name="bblog_ru"; Category="Misc"; Url="https://www.babyblog.ru/user/{user}"; FoundMarker=") — дневник на Babyblog.ru"; NotFoundMarker="БэбиБлог - беременность, календарь беременности, дневники" }
        @{ Name="bdsmsingles"; Category="Xx nsfw xx"; Url="https://www.bdsmsingles.com/members/{user}/"; FoundMarker="<title>Profile"; NotFoundMarker="" }
        @{ Name="Bentbox"; Category="Xx nsfw xx"; Url="https://bentbox.co/{user}"; FoundMarker="<div id=`"user_bar`">"; NotFoundMarker="This user is currently not available" }
        @{ Name="BiggerPockets"; Category="Finance"; Url="https://www.biggerpockets.com/users/{user}"; FoundMarker="| BiggerPockets</title>"; NotFoundMarker="Page not found" }
        @{ Name="BIGO Live"; Category="Gaming"; Url="https://www.bigo.tv/user/{user}"; FoundMarker="userInfo:{nickName"; NotFoundMarker="userInfo:{}" }
        @{ Name="Bimpos"; Category="Tech"; Url="https://ask.bimpos.com/user/{user}"; FoundMarker="<title>User"; NotFoundMarker="Page not found" }
        @{ Name="Bio Site"; Category="Social"; Url="https://bio.site/{user}"; FoundMarker="— Bio Sites</title>"; NotFoundMarker="This Bio Site doesn’t exist — Bio Site</title>" }
        @{ Name="biolink"; Category="Misc"; Url="https://bio.link/{user}"; FoundMarker="profile:username"; NotFoundMarker="The page you’re looking for doesn’t exist" }
        @{ Name="blogi.pl"; Category="Creative"; Url="https://www.blogi.pl/osoba,{user}.html"; FoundMarker="Informacje ogólne"; NotFoundMarker="Niepoprawny adres." }
        @{ Name="Blogmarks"; Category="Misc"; Url="http://blogmarks.net/user/{user}"; FoundMarker="Public marks from"; NotFoundMarker="" }
        @{ Name="Bluesky Username"; Category="Social"; Url="https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={user}.bsky.social"; FoundMarker="`"handle`":`""; NotFoundMarker="`"message`":`"Profile not found`"" }
        @{ Name="BoardGameGeek"; Category="Gaming"; Url="https://api.geekdo.com/api/accounts/validate/username?username={user}"; FoundMarker="`"message`":`"Sorry, this username is already taken.`""; NotFoundMarker="`"isValid`":true" }
        @{ Name="Bookcrossing"; Category="Hobby"; Url="https://www.bookcrossing.com/mybookshelf/{user}"; FoundMarker="membersbycity/"; NotFoundMarker="BookCrossing - Not Found" }
        @{ Name="Booknode"; Category="Hobby"; Url="https://booknode.com/profil/{user}"; FoundMarker="<title>Profil de"; NotFoundMarker="<title>Page non trouvée" }
        @{ Name="Boosty"; Category="Social"; Url="https://api.boosty.to/v1/blog/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"error`":`"blog_not_found`"" }
        @{ Name="Booth"; Category="Marketplace"; Url="https://{user}.booth.pm/"; FoundMarker="- BOOTH</title>"; NotFoundMarker="" }
        @{ Name="Brickset"; Category="Hobby"; Url="https://brickset.com/profile/{user}"; FoundMarker="Member since:</dt>"; NotFoundMarker="{name}</h1>" }
        @{ Name="Bugcrowd"; Category="Tech"; Url="https://bugcrowd.com/profile-service/v1/profiles/{user}"; FoundMarker="`"username`":"; NotFoundMarker="`"error`":`"Not Found`"" }
        @{ Name="Bunpro"; Category="Social"; Url="https://community.bunpro.jp/u/{user}.json"; FoundMarker="username"; NotFoundMarker="The requested URL or resource could not be found." }
        @{ Name="BuzzFeed"; Category="Social"; Url="https://www.buzzfeed.com/{user}"; FoundMarker="on BuzzFeed</title><meta"; NotFoundMarker="We can't find the page you're looking for" }
        @{ Name="cafecito"; Category="Misc"; Url="https://cafecito.app/{user}"; FoundMarker="| Cafecito</title>"; NotFoundMarker="Es posible que el enlace que seleccionaste esté roto o que se haya eliminado la " }
        @{ Name="Calendy"; Category="Misc"; Url="https://calendly.com/api/booking/profiles/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"message`":`"not found`"" }
        @{ Name="Cameo"; Category="Marketplace"; Url="https://www.cameo.com/api/v2/users/{user}"; FoundMarker="`"_id`":"; NotFoundMarker="`"message`":`"We could not find the user:" }
        @{ Name="Career.habr"; Category="Professional"; Url="https://career.habr.com/{user}"; FoundMarker="— Хабр Карьера</title>"; NotFoundMarker="Ошибка 404" }
        @{ Name="CastingCallClub"; Category="Professional"; Url="https://www.castingcall.club/{user}"; FoundMarker="class=`"text-sm text-gray-500`">Joined"; NotFoundMarker="" }
        @{ Name="cda.pl"; Category="Video"; Url="https://www.cda.pl/{user}"; FoundMarker="Foldery"; NotFoundMarker="Strona na którą chcesz wejść nie istnieje" }
        @{ Name="Cent"; Category="Social"; Url="https://beta.cent.co/data/user/profile?userHandles={user}"; FoundMarker="`"id`":"; NotFoundMarker="`"results`":[]" }
        @{ Name="cfx.re"; Category="Gaming"; Url="https://forum.cfx.re/u/{user}.json"; FoundMarker="created_at"; NotFoundMarker="The requested URL or resource could not be found." }
        @{ Name="championat"; Category="News"; Url="https://www.championat.com/user/{user}/"; FoundMarker="Личный профил"; NotFoundMarker="Извините, запрашиваемая страница не найдена" }
        @{ Name="Chamsko"; Category="Images"; Url="https://www.chamsko.pl/profil/{user}"; FoundMarker="W serwisie od"; NotFoundMarker="Strona nie istnieje." }
        @{ Name="chatango.com"; Category="Social"; Url="https://{user}.chatango.com"; FoundMarker="<title>Chatango!"; NotFoundMarker="<title>Unknown User!" }
        @{ Name="CHEEZburger"; Category="News"; Url="https://cheezburger.com/Editor/{user}"; FoundMarker="<title>Recent Posts from"; NotFoundMarker="<title>404 Not Found</title>" }
        @{ Name="Chess.com"; Category="Gaming"; Url="https://api.chess.com/pub/player/{user}"; FoundMarker="`"player_id`":"; NotFoundMarker="`"code`":0" }
        @{ Name="Chocolatey"; Category="Tech"; Url="https://community.chocolatey.org/profiles/{user}"; FoundMarker="id =`"bioSection`""; NotFoundMarker="id=`"error404Message`"" }
        @{ Name="Choko.Link"; Category="Social"; Url="https://choko.link/{user}"; FoundMarker="--title-font-family: Roboto;"; NotFoundMarker="The link might be incorrect or the profile has been deleted." }
        @{ Name="Chomikuj.pl"; Category="Misc"; Url="https://chomikuj.pl/{user}/"; FoundMarker="Foldery"; NotFoundMarker="Chomik o takiej nazwie nie istnieje" }
        @{ Name="Chyoa"; Category="Xx nsfw xx"; Url="https://chyoa.com/user/{user}"; FoundMarker="When I'm not reading erotica I like to read"; NotFoundMarker="Sorry, I got distracted..." }
        @{ Name="Cloudflare"; Category="Tech"; Url="https://community.cloudflare.com/u/{user}/card.json"; FoundMarker="user_avatar"; NotFoundMarker="The requested URL or resource could not be found" }
        @{ Name="Clubhouse"; Category="Social"; Url="https://www.clubhouse.com/@{user}"; FoundMarker="`"user`":"; NotFoundMarker="404" }
        @{ Name="cnet"; Category="News"; Url="https://www.cnet.com/profiles/{user}/"; FoundMarker="class=`"author-header__stat-label`""; NotFoundMarker="<title>Page Not Found - CNET" }
        @{ Name="Coda"; Category="Hobby"; Url="https://coda.io/@{user}/"; FoundMarker="- Coda Profile</title>"; NotFoundMarker="<title>Coda | Page not found - Coda</title>" }
        @{ Name="codementor"; Category="Code"; Url="https://www.codementor.io/@{user}"; FoundMarker="ABOUT ME"; NotFoundMarker="404/favicon.png" }
        @{ Name="Coderwall"; Category="Code"; Url="https://coderwall.com/{user}/"; FoundMarker="s profile |"; NotFoundMarker="404! Our feels when that url is used" }
        @{ Name="Commudle"; Category="Tech"; Url="https://json.commudle.com/api/v2/users?username={user}"; FoundMarker="`"status`":200"; NotFoundMarker="`"status`":404" }
        @{ Name="Community Adobe"; Category="Tech"; Url="https://community.adobe.com/t5/forums/searchpage/tab/user?q={user}"; FoundMarker="UserSearchItemContainer"; NotFoundMarker="No search results found." }
        @{ Name="coroflot"; Category="Creative"; Url="https://www.coroflot.com/{user}"; FoundMarker="portfolio"; NotFoundMarker="Looking for something?" }
        @{ Name="Coub"; Category="Social"; Url="https://coub.com/api/v2/channels/{user}"; FoundMarker="`"user_id`":"; NotFoundMarker="`"error`":`"Unhandled exception`"" }
        @{ Name="cowboys4angels"; Category="Xx nsfw xx"; Url="https://cowboys4angels.com/cowboy/{user}/"; FoundMarker="- Cowboys 4 Angels</title>"; NotFoundMarker="Error Page not found" }
        @{ Name="Cracked"; Category="Social"; Url="https://www.cracked.com/members/{user}"; FoundMarker="Member Since"; NotFoundMarker="" }
        @{ Name="crevado"; Category="Images"; Url="https://{user}.crevado.com/"; FoundMarker="Portfolio"; NotFoundMarker="Site not found :-(" }
        @{ Name="Cropty"; Category="Finance"; Url="https://api.cropty.io/v1/auth/{user}"; FoundMarker="`"name`":"; NotFoundMarker="`"errors`":" }
        @{ Name="Crowdin"; Category="Hobby"; Url="https://crowdin.com/profile/{user}"; FoundMarker="id=`"profile-page`""; NotFoundMarker="class=`"error-page`"" }
        @{ Name="Cytoid"; Category="Gaming"; Url="https://cytoid.io/profile/{user}"; FoundMarker="Joined"; NotFoundMarker="Profile not found" }
        @{ Name="Daily Kos"; Category="News"; Url="https://www.dailykos.com/user/{user}"; FoundMarker="`"@type`":`"ProfilePage`""; NotFoundMarker="Page not found! (404)" }
        @{ Name="Dailymotion"; Category="Video"; Url="https://api.dailymotion.com/user/{user}?fields=id,username,screenname,description,avatar_720_url,cover_250_url,followers_total,following_total,videos_total,country,created_time,verified,url"; FoundMarker="`"id`":"; NotFoundMarker="`"code`":404" }
        @{ Name="darudar"; Category="Misc"; Url="https://darudar.org/users/{user}/"; FoundMarker=". Дарудар"; NotFoundMarker="404. Дару~дар: миру~мир!" }
        @{ Name="dateinasia"; Category="Dating"; Url="https://www.dateinasia.com/{user}"; FoundMarker="About me"; NotFoundMarker="The page you are looking for does not exist" }
        @{ Name="datezone"; Category="Xx nsfw xx"; Url="https://en.datezone.com/users/{user}"; FoundMarker="property=`"og:url`""; NotFoundMarker="<title>Page not found</title>" }
        @{ Name="Dating.ru"; Category="Dating"; Url="https://dating.ru/{user}/"; FoundMarker="| dating.ru"; NotFoundMarker="Такой страницы не существует." }
        @{ Name="Demotywatory"; Category="Images"; Url="https://demotywatory.pl/user/{user}"; FoundMarker="Z nami od:"; NotFoundMarker="Użytkownik o podanym pseudonimie nie istnieje." }
        @{ Name="Designspriation"; Category="Creative"; Url="https://www.designspiration.com/{user}/"; FoundMarker="has discovered on Designspiration"; NotFoundMarker="Content Not Found" }
        @{ Name="destream"; Category="Finance"; Url="https://api.destream.net/siteapi/v2/live/details/{user}"; FoundMarker="`"userName`":"; NotFoundMarker="" }
        @{ Name="devRant"; Category="Code"; Url="https://devrant.com/api/get-user-id?app=3&username={user}"; FoundMarker="`"success`":true"; NotFoundMarker="`"success`":false" }
        @{ Name="DFG"; Category="Gaming"; Url="https://www.dfg.com.br/user/{user}"; FoundMarker="class=`"container user-information`""; NotFoundMarker="content=`"https://www.dfg.com.br/Layout/HandleStatusCode/404`"" }
        @{ Name="Diablo"; Category="Gaming"; Url="https://diablo2.io/member/{user}/"; FoundMarker="Viewing profile -"; NotFoundMarker="The requested user does not exist" }
        @{ Name="DIBIZ"; Category="Professional"; Url="https://www.dibiz.com/{user}"; FoundMarker="Add to contacts</span>"; NotFoundMarker="An Error Has Occurred" }
        @{ Name="Digitalspy"; Category="Social"; Url="https://forums.digitalspy.com/profile/discussions/{user}"; FoundMarker="About"; NotFoundMarker="User not found" }
        @{ Name="diigo"; Category="Images"; Url="https://www.diigo.com/interact_api/load_profile_info?name={user}"; FoundMarker="regist_at"; NotFoundMarker="{}" }
        @{ Name="Discogs"; Category="Audio"; Url="https://api.discogs.com/users/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"message`": `"User does not exist or may have been deleted.`"" }
        @{ Name="Discord (Invite)"; Category="Social"; Url="https://discord.com/api/v9/invites/{user}?with_counts=true&with_expiration=true"; FoundMarker="`"channel`":"; NotFoundMarker="`"message`": `"Unknown Invite`"" }
        @{ Name="Discourse"; Category="Misc"; Url="https://meta.discourse.org/u/{user}/summary.json"; FoundMarker="topics"; NotFoundMarker="The requested URL or resource could not be found." }
        @{ Name="discuss.elastic.co"; Category="Tech"; Url="https://discuss.elastic.co/u/{user}"; FoundMarker="<title>  Profile"; NotFoundMarker="Oops!" }
        @{ Name="Dojoverse"; Category="Hobby"; Url="https://dojoverse.com/members/{user}/"; FoundMarker="Joined"; NotFoundMarker="Looks like you got lost!." }
        @{ Name="donate.stream"; Category="Finance"; Url="https://donate.stream/api/v1/streamer.get?path={user}&app=9f4e793cec820015d511dbc77b20c5c1"; FoundMarker="`"response`":"; NotFoundMarker="`"message`":`"Not found`"" }
        @{ Name="Donatello"; Category="Finance"; Url="https://donatello.to/{user}"; FoundMarker="UserPage.init"; NotFoundMarker="<title>Сторінку не знайдено (404) - Donatello</title>" }
        @{ Name="Donatik"; Category="Finance"; Url="https://{user}.donatik.ua/"; FoundMarker="\`"__typename\`":\`"UserPageOutput\`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="Donation Alerts"; Category="Finance"; Url="https://www.donationalerts.com/api/v1/user/{user}/donationpagesettings"; FoundMarker="`"data`":"; NotFoundMarker="`"success`":false" }
        @{ Name="DonationPay"; Category="Finance"; Url="https://give.donationpay.org/hopewell-fund/{user}/"; FoundMarker="id=`"dp-payment-form`""; NotFoundMarker="<title>404 Not Found</title>" }
        @{ Name="Donatty"; Category="Professional"; Url="https://api.donatty.com/users/find/{user}"; FoundMarker="`"response`":"; NotFoundMarker="`"error`":`"internal error`"" }
        @{ Name="dot.cards"; Category="Professional"; Url="https://dot.cards/{user}"; FoundMarker="`"user_id`":`""; NotFoundMarker="`"status`":`"username_not_found" }
        @{ Name="Dota2.ru"; Category="Gaming"; Url="https://dota2.ru/forum/search/?type=user&keywords={user}&sort_by=username"; FoundMarker="class=`"forum-section__item forum-section__item--first`""; NotFoundMarker="id=`"no-activity-posts`"" }
        @{ Name="DOTAFire"; Category="Gaming"; Url="https://www.dotafire.com/ajax/searchSite?text={user}&search=members"; FoundMarker="href=`"/profile/"; NotFoundMarker=">No results found</span>" }
        @{ Name="DOU"; Category="Social"; Url="https://dou.ua/users/{user}/"; FoundMarker="class=`"page-profile`""; NotFoundMarker="class=`"page-error`"" }
        @{ Name="DRIVE2.RU"; Category="Social"; Url="https://www.drive2.ru/users/{user}/"; FoundMarker="itemprop=`"name`""; NotFoundMarker="<title>404 — Страница не найдена</title>" }
        @{ Name="Droners"; Category="Hobby"; Url="https://droners.io/accounts/{user}/"; FoundMarker="- Professional Drone Pilot"; NotFoundMarker="(404)</title>" }
        @{ Name="easyen"; Category="Social"; Url="https://easyen.ru/index/8-0-{user}"; FoundMarker="День рождения"; NotFoundMarker="Пользователь не найден" }
        @{ Name="Etoro"; Category="Finance"; Url="https://www.etoro.com/api/logininfo/v1.1/users/{user}"; FoundMarker="`"gcid`":"; NotFoundMarker="`"ErrorCode`":`"NotFound`"" }
        @{ Name="Evolution CMS"; Category="Tech"; Url="https://community.evocms.ru/users/?search={user}"; FoundMarker="id=`"user-search`""; NotFoundMarker="" }
        @{ Name="Expressional.social (Mastodon Instance)"; Category="Social"; Url="https://expressional.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Fabswingers"; Category="Dating"; Url="https://www.fabswingers.com/profile/{user}"; FoundMarker="View Profile"; NotFoundMarker="The user you tried to view doesn't seem to be on the site any more" }
        @{ Name="Faktopedia"; Category="Images"; Url="https://faktopedia.pl/user/{user}"; FoundMarker="Zamieszcza fakty od:"; NotFoundMarker="Nie znaleziono użytkownika o podanym loginie." }
        @{ Name="FanCentro"; Category="Xx nsfw xx"; Url="https://fancentro.com/api/profile.get?profileAlias={user}&limit=1"; FoundMarker="`"status`":true"; NotFoundMarker="`"status`":false" }
        @{ Name="Fandom"; Category="Gaming"; Url="https://www.fandom.com/u/{user}"; FoundMarker="| Profile | Fandom"; NotFoundMarker="Not Found" }
        @{ Name="Fanslist (OnlyFans)"; Category="Xx nsfw xx"; Url="https://fanslist.com/search?q={user}"; FoundMarker="data-username="; NotFoundMarker="No results found for query" }
        @{ Name="Fansly"; Category="Xx nsfw xx"; Url="https://apiv3.fansly.com/api/v1/account?usernames={user}"; FoundMarker="`"id`":"; NotFoundMarker="`"response`":[]" }
        @{ Name="Federated.press (Mastodon Instance)"; Category="Social"; Url="https://federated.press/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Figma"; Category="Tech"; Url="https://www.figma.com/api/profile/handle/{user}"; FoundMarker="`"status`":200"; NotFoundMarker="`"status`":404" }
        @{ Name="Filmot Channel Search"; Category="Archived"; Url="https://filmot.com/channelsearch/{user}"; FoundMarker="Subscribers"; NotFoundMarker="No channels found" }
        @{ Name="Filmot Unlisted Videos"; Category="Archived"; Url="https://filmot.com/unlistedSearch?channelQuery={user}&sortField=uploaddate&sortOrder=desc&"; FoundMarker="clips found"; NotFoundMarker="No results" }
        @{ Name="Filmweb"; Category="Hobby"; Url="https://www.filmweb.pl/api/v1/users/{user}/id"; FoundMarker="`"userId`":"; NotFoundMarker="" }
        @{ Name="fine_art_america"; Category="Marketplace"; Url="https://fineartamerica.com/profiles/{user}"; FoundMarker="Shop for artwork by"; NotFoundMarker="Browse through millions of independent artists in our extensive" }
        @{ Name="FL.ru"; Category="Social"; Url="https://www.fl.ru/users/{user}/portfolio/"; FoundMarker="class=`"page-profile`""; NotFoundMarker="content=`"404 Not Found`"" }
        @{ Name="Flightradar24"; Category="Misc"; Url="https://my.flightradar24.com/{user}/"; FoundMarker="class=`"profile-card`" data-profile-user="; NotFoundMarker="class=`"main page-not-found-main" }
        @{ Name="flowcode"; Category="Social"; Url="https://www.flow.page/{user}"; FoundMarker="`"page`":{"; NotFoundMarker="`"page`":null" }
        @{ Name="Fodors Forum"; Category="Social"; Url="https://www.fodors.com/community/profile/{user}/forum-activity"; FoundMarker="User Profile | Fodor’s Travel</title>"; NotFoundMarker="Plan Your Trip Online</title>" }
        @{ Name="Folkd"; Category="Social"; Url="https://www.folkd.com/?app=core&module=system&controller=ajax&do=usernameExists&input={user}"; FoundMarker="`"message`":`"That display name is in use by another member.`""; NotFoundMarker="`"result`":`"ok`"" }
        @{ Name="Fortnite Tracker"; Category="Gaming"; Url="https://fortnitetracker.com/profile/all/{user}"; FoundMarker="s Fortnite Stats - Fortnite Tracker"; NotFoundMarker="Fortnite Player Stats -" }
        @{ Name="fotka"; Category="Social"; Url="https://api.fotka.com/v2/user/dataStatic?login={user}"; FoundMarker="`"profil`":"; NotFoundMarker="`"status`":`"ERROR`"" }
        @{ Name="Foursquare"; Category="Social"; Url="https://foursquare.com/{user}"; FoundMarker="class=`"userProfile2Page`""; NotFoundMarker="" }
        @{ Name="freeCodeCamp"; Category="Code"; Url="https://api.freecodecamp.org/users/get-public-profile?username={user}"; FoundMarker="`"user`":"; NotFoundMarker="{}" }
        @{ Name="Freelance.RU"; Category="Professional"; Url="https://freelance.ru/{user}"; FoundMarker="class=`" user-top-container user-portfolio`""; NotFoundMarker="class=`"msg_error alert alert-danger`"" }
        @{ Name="Freelance.ua"; Category="Social"; Url="https://freelance.ua/user/{user}/"; FoundMarker="p-profile-avatar"; NotFoundMarker="Схоже, дана сторінка не знайдена" }
        @{ Name="Freelancehunt (Employer)"; Category="Social"; Url="https://freelancehunt.com/en/employer/{user}.html"; FoundMarker="`"@id`":`"https://freelancehunt.com/en/employers`""; NotFoundMarker="User not found." }
        @{ Name="Freelancehunt (Freelancer)"; Category="Social"; Url="https://freelancehunt.com/en/freelancer/{user}.html"; FoundMarker="`"@id`":`"https://freelancehunt.com/en/freelancers`""; NotFoundMarker="User not found." }
        @{ Name="freesound"; Category="Audio"; Url="https://freesound.org/people/{user}/section/stats/?ajax=1"; FoundMarker="forum posts"; NotFoundMarker="<h1>Page not found</h1>" }
        @{ Name="FriendFinder"; Category="Dating"; Url="https://friendfinder.com/profile/{user}"; FoundMarker="Last Visit:"; NotFoundMarker="302 Found" }
        @{ Name="FriendFinder-X"; Category="Dating"; Url="https://www.friendfinder-x.com/profile/{user}"; FoundMarker="'s Dating Profile on FriendFinder-x"; NotFoundMarker="The document has moved" }
        @{ Name="Gamer DVR"; Category="Gaming"; Url="https://gamerdvr.com/gamer/{user}"; FoundMarker="class=`"gamerpic`""; NotFoundMarker="<body>You are being <" }
        @{ Name="Gamespot"; Category="Gaming"; Url="https://www.gamespot.com/profile/{user}/summary/activity/?ajax"; FoundMarker="`"success`":true"; NotFoundMarker="`"success`":false" }
        @{ Name="Garmin Connect"; Category="Fitness"; Url="https://connect.garmin.com/app/profile/{user}"; FoundMarker="window.VIEWER_USERPREFERENCES = {"; NotFoundMarker="window.VIEWER_USERPREFERENCES = null" }
        @{ Name="GDBrowser"; Category="Gaming"; Url="https://gdbrowser.com/api/profile/{user}"; FoundMarker="`"accountID`":"; NotFoundMarker="-1" }
        @{ Name="GeeksForGeeks"; Category="Code"; Url="https://authapi.geeksforgeeks.org/api-get/user-profile-info/?handle={user}"; FoundMarker="`"message`":`"data retrieved successfully`""; NotFoundMarker="`"message`":`"User not found!`"" }
        @{ Name="Genius (Artist)"; Category="Audio"; Url="https://genius.com/artists/{user}"; FoundMarker="class=`"profile_header`""; NotFoundMarker="class=`"render_404`"" }
        @{ Name="Genius (User)"; Category="Audio"; Url="https://genius.com/{user}"; FoundMarker="class=`"profile_header`""; NotFoundMarker="class=`"render_404`"" }
        @{ Name="Geocaching"; Category="Social"; Url="https://www.geocaching.com/p/?u={user}"; FoundMarker="class=`"hax-profile`""; NotFoundMarker="class=`"callout http-error`"" }
        @{ Name="Gitea"; Category="Code"; Url="https://gitea.com/api/v1/users/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"message`":`"user redirect does not exist" }
        @{ Name="GitHub (Gists)"; Category="Code"; Url="https://api.github.com/users/{user}/gists"; FoundMarker="`"id`":"; NotFoundMarker="`"status`": `"404`"" }
        @{ Name="GitHub (User)"; Category="Code"; Url="https://api.github.com/users/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"status`": `"404`"" }
        @{ Name="gloria.tv"; Category="Social"; Url="https://gloria.tv/{user}"; FoundMarker="Last online"; NotFoundMarker="Page unavailable" }
        @{ Name="GNOME (GitLab)"; Category="Code"; Url="https://gitlab.gnome.org/api/v4/users?username={user}"; FoundMarker="`"username`":"; NotFoundMarker="[]" }
        @{ Name="GNOME (Shell Extensions)"; Category="Code"; Url="https://extensions.gnome.org/accounts/profile/{user}"; FoundMarker="class=`"user-details`""; NotFoundMarker="<h3>404 - Page not Found</h3>" }
        @{ Name="Goodgame_Russia"; Category="Gaming"; Url="https://goodgame.ru/channel/{user}/"; FoundMarker="channel_id"; NotFoundMarker="Такой страницы не существует" }
        @{ Name="gpodder.net"; Category="Audio"; Url="https://gpodder.net/user/{user}/"; FoundMarker="mdash; gpodder.net"; NotFoundMarker="404 - Not found" }
        @{ Name="grandprof"; Category="Misc"; Url="https://grandprof.org/communaute/{user}"; FoundMarker="s Profile"; NotFoundMarker="Mauvaise pioche" }
        @{ Name="Graphics.social (Mastodon Instance)"; Category="Social"; Url="https://graphics.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Gravatar"; Category="Social"; Url="https://en.gravatar.com/{user}.json"; FoundMarker="{`"entry`":"; NotFoundMarker="`"User not found`"" }
        @{ Name="Greasy Fork"; Category="Tech"; Url="https://greasyfork.org/en/users?q={user}"; FoundMarker="class=`"user-list`""; NotFoundMarker="<p>No users!</p>" }
        @{ Name="GTAinside.com"; Category="Gaming"; Url="https://www.gtainside.com/profile/{user}"; FoundMarker="class=`"user-profile-name`""; NotFoundMarker="<title>Page not found - 404</title>" }
        @{ Name="gumroad"; Category="Marketplace"; Url="https://{user}.gumroad.com/"; FoundMarker="s profile picture"; NotFoundMarker="Page not found" }
        @{ Name="Habbo.com"; Category="Gaming"; Url="https://www.habbo.com/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.com.br"; Category="Gaming"; Url="https://www.habbo.com.br/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.com.tr"; Category="Gaming"; Url="https://www.habbo.com.tr/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.de"; Category="Gaming"; Url="https://www.habbo.de/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.es"; Category="Gaming"; Url="https://www.habbo.es/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="not-found" }
        @{ Name="Habbo.fi"; Category="Gaming"; Url="https://www.habbo.fi/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.fr"; Category="Gaming"; Url="https://www.habbo.fr/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.it"; Category="Gaming"; Url="https://www.habbo.it/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habbo.nl"; Category="Gaming"; Url="https://www.habbo.nl/api/public/users?name={user}"; FoundMarker="uniqueId`":"; NotFoundMarker="error`": `"not-found" }
        @{ Name="Habr (Q&A)"; Category="Code"; Url="https://qna.habr.com/user/{user}"; FoundMarker="class=`"page-header__info`""; NotFoundMarker="icon_error_404" }
        @{ Name="Habr (User)"; Category="Social"; Url="https://habr.com/ru/users/{user}/"; FoundMarker="tm-page tm-user"; NotFoundMarker="tm-error-message" }
        @{ Name="Habtium"; Category="Gaming"; Url="https://habtium.es/{user}"; FoundMarker="<div class=`"profile-info"; NotFoundMarker="<h1 class=`"section red`">Oops!" }
        @{ Name="HackAdvisor"; Category="Tech"; Url="https://hackadvisor.io/api/v2/profile/{user}/"; FoundMarker="`"username`":"; NotFoundMarker="{`"detail`":`"Username not found`"}" }
        @{ Name="Hacker News"; Category="Tech"; Url="https://hacker-news.firebaseio.com/v0/user/{user}.json?print=pretty"; FoundMarker="`"id`" :"; NotFoundMarker="null" }
        @{ Name="Hackernoon"; Category="Tech"; Url="https://hackernoon.com/_next/data/foL6JC7ro2FEEMD-gMKgQ/u/{user}.json"; FoundMarker="`"profile`""; NotFoundMarker="__N_REDIRECT" }
        @{ Name="Hackster"; Category="Code"; Url="https://www.hackster.io/{user}"; FoundMarker="data-hypernova-key=`"UserProfile`""; NotFoundMarker="id=`"error`"" }
        @{ Name="hamaha"; Category="Finance"; Url="https://hamaha.net/{user}"; FoundMarker="id=`"profile`""; NotFoundMarker="content=`"HAMAHA  Биткоин форум. Торговля на бирже - ➨ Обучение Криптовалютам, Б" }
        @{ Name="Hanime"; Category="Xx nsfw xx"; Url="https://hanime.tv/channels/{user}"; FoundMarker="Channel Views"; NotFoundMarker="DYNAMIC" }
        @{ Name="Hcommons.social (Mastodon Instance)"; Category="Social"; Url="https://hcommons.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Heylink"; Category="Misc"; Url="https://heylink.me/{user}/"; FoundMarker="HeyLink.me |"; NotFoundMarker="We can't find the page that you're looking for :(" }
        @{ Name="HiHello"; Category="Professional"; Url="https://www.hihello.com/author/{user}"; FoundMarker="`"mainEntity`": {"; NotFoundMarker="class=`"utility-page-wrap-404`"" }
        @{ Name="Home Design 3D"; Category="Hobby"; Url="https://www.homedesign3d.net/user/{user}"; FoundMarker="id=`"user_content`""; NotFoundMarker="<title>Community</title>" }
        @{ Name="Hometech.social (Mastodon Instance)"; Category="Social"; Url="https://hometech.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="hoo.be"; Category="Social"; Url="https://hoo.be/{user}"; FoundMarker="ProfilePage`",`"mainEntity"; NotFoundMarker="<title>hoo.be</title>" }
        @{ Name="Hostux.social (Mastodon Instance)"; Category="Social"; Url="https://hostux.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Houzz"; Category="Hobby"; Url="https://www.houzz.com/user/{user}"; FoundMarker="Followers"; NotFoundMarker="Page Not Found" }
        @{ Name="HubPages"; Category="Creative"; Url="https://hubpages.com/@{user}"; FoundMarker="name`">Followers"; NotFoundMarker="Sorry, that user does not exist" }
        @{ Name="HudsonRock"; Category="Tech"; Url="https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={user}"; FoundMarker="This username is associated with a computer that was infected by an info-stealer"; NotFoundMarker="This username is not associated with a computer infected by an info-stealer" }
        @{ Name="HulkShare"; Category="Social"; Url="https://www.hulkshare.com/{user}"; FoundMarker="id=`"profile_image`""; NotFoundMarker="Invalid user." }
        @{ Name="icq-chat"; Category="Social"; Url="https://icq.icqchat.co/members/{user}/"; FoundMarker="class=`"memberHeader-mainContent"; NotFoundMarker="<title>Oops! We ran into some problems." }
        @{ Name="IFTTT"; Category="Misc"; Url="https://ifttt.com/p/{user}"; FoundMarker="Joined"; NotFoundMarker="The requested page or file does not exist" }
        @{ Name="ifunny"; Category="Misc"; Url="https://ifunny.co/user/{user}"; FoundMarker="subscribers"; NotFoundMarker="404 - page not found" }
        @{ Name="igromania"; Category="Social"; Url="https://forum.igromania.ru/member.php?username={user}"; FoundMarker="Форум Игромании - Просмотр профиля:"; NotFoundMarker="Пользователь не зарегистрирован и не имеет профиля для просмотра." }
        @{ Name="ILGM Growers Forum"; Category="Social"; Url="https://ilgmforum.com/u/{user}/summary.json"; FoundMarker="user_summary`":{"; NotFoundMarker="errors`":[`"The requested URL" }
        @{ Name="imagefap"; Category="Xx nsfw xx"; Url="https://www.imagefap.com/profile/{user}"; FoundMarker="s Profile"; NotFoundMarker="Invalid uid" }
        @{ Name="ImageShack"; Category="Images"; Url="https://imageshack.com/user/{user}"; FoundMarker="s Images</title>"; NotFoundMarker="" }
        @{ Name="iMGSRC.RU"; Category="Images"; Url="https://imgsrc.ru/main/user.php?lang=ru&user={user}"; FoundMarker="Присоединился"; NotFoundMarker="" }
        @{ Name="Imgur"; Category="Images"; Url="https://api.imgur.com/account/v1/accounts/{user}?client_id=546c25a59c58ad7"; FoundMarker="`"username`":"; NotFoundMarker="`"code`":`"404`"" }
        @{ Name="Immunefi"; Category="Tech"; Url="https://immunefi.com/profile/{user}/"; FoundMarker="content=`"profile`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="inaturalist"; Category="Hobby"; Url="https://api.inaturalist.org/v1/users/{user}"; FoundMarker="`"results`":[{"; NotFoundMarker="`"status`":404" }
        @{ Name="Independent academia"; Category="Hobby"; Url="https://independent.academia.edu/{user}"; FoundMarker="- Academia.edu"; NotFoundMarker="Academia.edu" }
        @{ Name="InkBunny"; Category="Xx nsfw xx"; Url="https://inkbunny.net/{user}"; FoundMarker="Profile | Inkbunny, the Furry Art Community</title>"; NotFoundMarker="<title>Members | Inkbunny, the Furry Art Community</title>" }
        @{ Name="InsaneJournal"; Category="Social"; Url="https://{user}.insanejournal.com/profile"; FoundMarker="User:"; NotFoundMarker="The requested URL /profile was not found on this server" }
        @{ Name="Instagram (Imginn)"; Category="Social"; Url="https://imginn.com/{user}/"; FoundMarker="class=`"userinfo`""; NotFoundMarker="class=`"page-error notfound`"" }
        @{ Name="interpals"; Category="Dating"; Url="https://www.interpals.net/{user}"; FoundMarker="Looking for"; NotFoundMarker="User not found" }
        @{ Name="Intigriti"; Category="Tech"; Url="https://app.intigriti.com/api/user/public/profile/{user}"; FoundMarker="`"userName`":"; NotFoundMarker="class=`"error-page-container`"" }
        @{ Name="JapanDict"; Category="Social"; Url="https://forum.japandict.com/u/{user}"; FoundMarker="class=`"UserPage`""; NotFoundMarker="The page you requested could not be found." }
        @{ Name="JBZD"; Category="Images"; Url="https://jbzd.com.pl/uzytkownik/{user}"; FoundMarker="Dzidy użytkownika"; NotFoundMarker="Błąd 404" }
        @{ Name="jeja.pl"; Category="Misc"; Url="https://www.jeja.pl/user,{user}"; FoundMarker="Profil użytkownika"; NotFoundMarker="Niepoprawny login" }
        @{ Name="Jeuxvideo"; Category="Gaming"; Url="https://www.jeuxvideo.com/profil/{user}?mode=infos"; FoundMarker="- jeuxvideo.com"; NotFoundMarker="rence des gamers" }
        @{ Name="Joe Monster"; Category="Misc"; Url="https://joemonster.org/bojownik/{user}"; FoundMarker="jest prywatny"; NotFoundMarker="Nie wiem jak ci to powiedzieć" }
        @{ Name="Justforfans"; Category="Xx nsfw xx"; Url="https://justfor.fans/{user}"; FoundMarker="@ JustFor.Fans"; NotFoundMarker="" }
        @{ Name="kik"; Category="Social"; Url="https://kik.me/{user}"; FoundMarker="/thumb.jpg`"/>"; NotFoundMarker="<h1 class=`"display-name`"> </h1>" }
        @{ Name="KnowYourMeme"; Category="Social"; Url="https://knowyourmeme.com/users/{user}"; FoundMarker="Contributions"; NotFoundMarker="404, File Not Found!" }
        @{ Name="komi"; Category="Social"; Url="https://api.komi.io/api/talent/usernames/{user}"; FoundMarker="accountStatus`":`"active"; NotFoundMarker="The talent profile was not found" }
        @{ Name="Kwai"; Category="Social"; Url="https://www.kwai.com/@{user}"; FoundMarker="name=`"title`""; NotFoundMarker="<title>Kwai</title>" }
        @{ Name="kwejk.pl"; Category="Images"; Url="https://kwejk.pl/uzytkownik/{user}#/tablica/"; FoundMarker="Kwejki użytkownika"; NotFoundMarker="404 - strona nie została znaleziona - KWEJK.pl" }
        @{ Name="Kwork"; Category="Social"; Url="https://kwork.ru/user_kworks/{user}"; FoundMarker="`"success`":true"; NotFoundMarker="`"success`":false" }
        @{ Name="LeakIX"; Category="Tech"; Url="https://leakix.net/u/{user}"; FoundMarker=">Joined"; NotFoundMarker="<title>LeakIX - Server error</title>" }
        @{ Name="Lemon8"; Category="Social"; Url="https://www.lemon8-app.com/{user}?region=us"; FoundMarker="id=`"user-description`""; NotFoundMarker="class=`"not_found_text`"" }
        @{ Name="LevelBlue"; Category="Social"; Url="https://otx.alienvault.com/otxapi/auth/validate?username={user}"; FoundMarker="`"username`": [`"This username is already taken`"]"; NotFoundMarker="{}" }
        @{ Name="Libretooth.gr (Mastodon Instance)"; Category="Social"; Url="https://libretooth.gr/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="LINE"; Category="Social"; Url="https://line.me/R/ti/p/@{user}?from=page"; FoundMarker="Add LINE friend"; NotFoundMarker="404 Not Found" }
        @{ Name="linux.org.ru"; Category="Tech"; Url="https://www.linux.org.ru/people/{user}/profile"; FoundMarker="Дата регистрации"; NotFoundMarker="Пользователя не существует" }
        @{ Name="LiveJasmin"; Category="Xx nsfw xx"; Url="https://www.livejasmin.com/en/flash/get-performer-details/{user}"; FoundMarker="`"success`":true"; NotFoundMarker="`"success`":false" }
        @{ Name="livemaster.ru"; Category="Marketplace"; Url="https://www.livemaster.ru/{user}"; FoundMarker="<title>Магазин мастера"; NotFoundMarker="<title>Вы попали на несуществующую страницу" }
        @{ Name="LoLProfile"; Category="Gaming"; Url="https://lolprofile.net/search/world/{user}-world"; FoundMarker="class=`"content sw`">"; NotFoundMarker="We could not find any results, please try again later or check your input." }
        @{ Name="Lor.sh (Mastodon Instance)"; Category="Social"; Url="https://lor.sh/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="lowcygier.pl"; Category="Gaming"; Url="https://bazar.lowcygier.pl/user/{user}"; FoundMarker="Zarejestrowany"; NotFoundMarker="Błąd 404 - Podana strona nie istnieje" }
        @{ Name="MAGABOOK"; Category="Social"; Url="https://magabook.com/{user}"; FoundMarker="Timeline"; NotFoundMarker="" }
        @{ Name="Magix"; Category="Audio"; Url="https://www.magix.info/us/users/profile/{user}/"; FoundMarker="About me"; NotFoundMarker="Page not found" }
        @{ Name="Magnific"; Category="Creative"; Url="https://www.magnific.com/app/api/community/creator-info-by-name?creator_name={user}&lang=en_US"; FoundMarker="`"creator`":"; NotFoundMarker="`"message`":`"Creator not found`"" }
        @{ Name="Malpedia Actors"; Category="Tech"; Url="https://malpedia.caad.fkie.fraunhofer.de/actor/{user}"; FoundMarker="href=`"/actors`""; NotFoundMarker="Page not Found." }
        @{ Name="MapMyTracks"; Category="Fitness"; Url="https://www.mapmytracks.com/{user}"; FoundMarker="class=`"profile-header`""; NotFoundMarker="Sorry, there is nothing to see here!" }
        @{ Name="Mapstodon.space (Mastodon Instance)"; Category="Social"; Url="https://mapstodon.space/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Maroc_nl"; Category="Social"; Url="https://www.maroc.nl/forums/members/{user}.html"; FoundMarker="Bekijk Profiel:"; NotFoundMarker="Deze gebruiker is niet geregistreerd" }
        @{ Name="Marshmallow"; Category="Social"; Url="https://marshmallow-qa.com/{user}"; FoundMarker="さんにメッセージをおくる"; NotFoundMarker="For compensation, here are cats for you." }
        @{ Name="Martech"; Category="Professional"; Url="https://martech.org/author/{user}/"; FoundMarker="twitter:site"; NotFoundMarker="Page not found" }
        @{ Name="Massage Anywhere"; Category="Fitness"; Url="https://www.massageanywhere.com/profile/{user}"; FoundMarker="<title>MassageAnywhere.com Profile for"; NotFoundMarker="<title>MassageAnywhere.com: Search Results</title>" }
        @{ Name="masto.ai"; Category="Social"; Url="https://masto.ai/api/v1/accounts/lookup?acct={user}"; FoundMarker="`"id`":"; NotFoundMarker="`"error`":`"Record not found`"" }
        @{ Name="Masto.nyc (Mastodon Instance)"; Category="Social"; Url="https://masto.nyc/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Mastodon-101010.pl"; Category="Social"; Url="https://101010.pl/@{user}"; FoundMarker="@101010.pl"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon-C.IM"; Category="Social"; Url="https://c.im/@{user}"; FoundMarker="@c.im) - C.IM</title>"; NotFoundMarker="<title>The page you are looking for isn&#39;t here" }
        @{ Name="Mastodon-Chaos.social"; Category="Social"; Url="https://chaos.social/@{user}"; FoundMarker="@chaos.social) - chaos.social</title>"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon-Defcon"; Category="Social"; Url="https://defcon.social/@{user}"; FoundMarker="- DEF CON Social</title>"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon-meow.social"; Category="Social"; Url="https://meow.social/@{user}"; FoundMarker="- the mastodon instance for creatures fluffy, scaly and otherwise</title>"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon-mstdn.io"; Category="Social"; Url="https://mstdn.io/@{user}"; FoundMarker="@mstdn.io) - Mastodon"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon-rigcz.club"; Category="Social"; Url="https://rigcz.club/@{user}"; FoundMarker="@rigcz.club"; NotFoundMarker="The page you are looking for isn't here." }
        @{ Name="Mastodon-social_tchncs"; Category="Social"; Url="https://social.tchncs.de/@{user}"; FoundMarker="profile:username"; NotFoundMarker="The page you are looking for isn&#39;t here" }
        @{ Name="Mastodon-Toot.Community"; Category="Social"; Url="https://toot.community/@{user}"; FoundMarker="@toot.community) - toot.community</title>"; NotFoundMarker="The page you are looking for isn&#39;t here." }
        @{ Name="Mastodon.online"; Category="Social"; Url="https://mastodon.online/@{user}"; FoundMarker="@mastodon.online) - Mastodon</title>"; NotFoundMarker="<title>The page you are looking for isn&#39;t here." }
        @{ Name="Mastodonbooks.net (Mastodon Instance)"; Category="Social"; Url="https://mastodonbooks.net/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="MAX"; Category="Social"; Url="https://max.ru/{user}"; FoundMarker="в мессенджере MAX</title>"; NotFoundMarker="linkInfo:{}" }
        @{ Name="MCUUID (Minecraft)"; Category="Gaming"; Url="https://playerdb.co/api/player/minecraft/{user}"; FoundMarker="Successfully found player by given ID."; NotFoundMarker="minecraft.api_failure" }
        @{ Name="meet me"; Category="Dating"; Url="https://www.meetme.com/{user}"; FoundMarker="<title>Meet people like"; NotFoundMarker="<title>MeetMe - Chat and Meet New People</title" }
        @{ Name="Meta-Wiki (Wikimedia)"; Category="News"; Url="https://meta.wikimedia.org/wiki/Special:CentralAuth?target={user}"; FoundMarker="id='mw-centralauth-info'"; NotFoundMarker="There is no global account for" }
        @{ Name="metacritic"; Category="Hobby"; Url="https://www.metacritic.com/user/{user}/"; FoundMarker="data-testid=`"profile-name`">"; NotFoundMarker="re looking for. Sorry about that.</p>" }
        @{ Name="Microsoft Learn"; Category="Tech"; Url="https://learn.microsoft.com/api/profiles/{user}"; FoundMarker="`"userId`":"; NotFoundMarker="" }
        @{ Name="Minecraft List"; Category="Gaming"; Url="https://minecraftlist.com/api/legacy/players/{user}"; FoundMarker="`"found`":true"; NotFoundMarker="`"found`":false" }
        @{ Name="mintme"; Category="Finance"; Url="https://www.mintme.com/token/{user}"; FoundMarker="token | mintMe"; NotFoundMarker="Page not found" }
        @{ Name="Mistrzowie"; Category="Images"; Url="https://mistrzowie.org/user/{user}"; FoundMarker="Profil użytkownika"; NotFoundMarker="Nie znaleziono użytkownika o podanym loginie." }
        @{ Name="Mix"; Category="Social"; Url="https://mix.com/{user}/"; FoundMarker="<title>@"; NotFoundMarker="The best content from the open web, personalized." }
        @{ Name="Mixcloud"; Category="Audio"; Url="https://api.mixcloud.com/{user}/"; FoundMarker="`"username`":"; NotFoundMarker="`"error`":" }
        @{ Name="Mixi"; Category="Social"; Url="https://mixi.jp/view_community.pl?id={user}"; FoundMarker="| mixiコミュニティ</title>"; NotFoundMarker="データがありません" }
        @{ Name="Mixlr"; Category="Audio"; Url="https://api.mixlr.com/users/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"error`":`"Resource not found`"" }
        @{ Name="Mmorpg"; Category="Gaming"; Url="https://forums.mmorpg.com/profile/{user}"; FoundMarker="MMORPG.com Forums"; NotFoundMarker="404 Not Not_Found" }
        @{ Name="MobileGTA.net"; Category="Gaming"; Url="https://www.mobilegta.net/en/user/{user}"; FoundMarker="userpage_user"; NotFoundMarker="<h1>404 Not Found" }
        @{ Name="MODX.im"; Category="Tech"; Url="https://modx.evo.im/profile/{user}/"; FoundMarker="class=`"profile`""; NotFoundMarker="class=`"content-error`"" }
        @{ Name="Monkeytype"; Category="Code"; Url="https://api.monkeytype.com/users/{user}/profile"; FoundMarker="`"message`":`"Profile retrieved`""; NotFoundMarker="`"message`":`"User not found`"" }
        @{ Name="Moto Trip"; Category="Hobby"; Url="https://moto-trip.com/profil/{user}"; FoundMarker="<h1 class=`"h2`">Profil de"; NotFoundMarker="<h1>Page introuvable</h1>" }
        @{ Name="Motokiller"; Category="Images"; Url="https://mklr.pl/user/{user}"; FoundMarker="Zamieszcza materiały od:"; NotFoundMarker="Nie znaleziono użytkownika o podanym loginie." }
        @{ Name="Moxfield"; Category="Gaming"; Url="https://api2.moxfield.com/v1/users/{user}"; FoundMarker="`"userName`":"; NotFoundMarker="`"status`":404" }
        @{ Name="mssg.me"; Category="Social"; Url="https://{user}.mssg.me/"; FoundMarker="property=`"og:title`""; NotFoundMarker="id=`"page_404`"" }
        @{ Name="Musician.social (Mastodon Instance)"; Category="Social"; Url="https://musician.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="musictraveler"; Category="Audio"; Url="https://www.musictraveler.com/en/users/{user}/"; FoundMarker="on Music Traveler</title>"; NotFoundMarker="<title>Page Not found</title>" }
        @{ Name="MUYZORRAS"; Category="Xx nsfw xx"; Url="https://www.muyzorras.com/usuarios/{user}"; FoundMarker="og:title"; NotFoundMarker="<title>Error 404" }
        @{ Name="my_instants"; Category="Audio"; Url="https://www.myinstants.com/en/profile/{user}/"; FoundMarker="| Myinstants</title>"; NotFoundMarker="Page not found" }
        @{ Name="MyBuilder"; Category="Professional"; Url="https://www.mybuilder.com/profile/{user}"; FoundMarker="`"legalName`":"; NotFoundMarker="Sorry, we can't find that page." }
        @{ Name="myfitnesspal Author"; Category="Fitness"; Url="https://blog.myfitnesspal.com/author/{user}/"; FoundMarker="`"isPartOf`":"; NotFoundMarker="<title>Page not found | MyFitnessPal Blog</title>" }
        @{ Name="myfitnesspal Community"; Category="Fitness"; Url="https://community.myfitnesspal.com/en/profile/{user}"; FoundMarker=">Last Active<"; NotFoundMarker="User Not Found" }
        @{ Name="MyLot"; Category="Social"; Url="https://www.mylot.com/{user}"; FoundMarker="on myLot</title>"; NotFoundMarker="/ Whoops!" }
        @{ Name="MYM"; Category="Social"; Url="https://mym.fans/{user}"; FoundMarker="class=`"page profile`""; NotFoundMarker="class=`"page page-404`"" }
        @{ Name="MyNickname"; Category="Misc"; Url="https://mynickname.com/en/search?q={user}"; FoundMarker="nickname found:</h2>"; NotFoundMarker="<h2>Nickname not found. Try searching for similar nicknames.</h2>" }
        @{ Name="MySpace"; Category="Social"; Url="https://myspace.com/{user}"; FoundMarker="<!-- Profile -->"; NotFoundMarker="<!-- 404 -->" }
        @{ Name="myWishBoard"; Category="Marketplace"; Url="https://mywishboard.com/@{user}"; FoundMarker="user.profile\`",\`"login\`":"; NotFoundMarker="User not found</span>" }
        @{ Name="naija_planet"; Category="Dating"; Url="https://naijaplanet.com/{user}"; FoundMarker="dating Profile,"; NotFoundMarker="- NaijaPlanet!" }
        @{ Name="nairaland"; Category="News"; Url="https://www.nairaland.com/{user}"; FoundMarker="s Profile"; NotFoundMarker="404: Page Not Found" }
        @{ Name="NaturalNews"; Category="Political"; Url="https://naturalnews.com/author/{user}/"; FoundMarker="class=`"Headline`""; NotFoundMarker="The page you are looking for cannot be found or is no longer available." }
        @{ Name="Naver"; Category="Social"; Url="https://blog.naver.com/{user}"; FoundMarker=": 네이버 블로그"; NotFoundMarker="페이지를 찾을 수 없습니다" }
        @{ Name="newmeet"; Category="Dating"; Url="https://www.newmeet.com/en/profile/{user}/"; FoundMarker="<h2>The profile of"; NotFoundMarker="Chat with , , ,  -" }
        @{ Name="Nifty Gateway"; Category="Social"; Url="https://api.niftygateway.com/user/profile-and-offchain-nifties-by-url/?profile_url={user}"; FoundMarker="&quot;didSucceed&quot;: true"; NotFoundMarker="&quot;didSucceed&quot;: false" }
        @{ Name="Nightbot"; Category="Social"; Url="https://api.nightbot.tv/1/channels/t/{user}"; FoundMarker="`"status`":200"; NotFoundMarker="`"status`":404" }
        @{ Name="Nih Buat Jajan"; Category="Social"; Url="https://www.nihbuatjajan.com/manifest/{user}.json"; FoundMarker="`"name`":"; NotFoundMarker="`"error`":`"Creator not found`"" }
        @{ Name="Nitecrew (Mastodon Instance)"; Category="Social"; Url="https://nitecrew.rip/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="nnru"; Category="Social"; Url="https://{user}.www.nn.ru"; FoundMarker="<title>"; NotFoundMarker="<title>Ошибка 404 -" }
        @{ Name="Note"; Category="Social"; Url="https://note.com/api/v2/creators/{user}"; FoundMarker="`"data`":{"; NotFoundMarker="`"data`":`"リソースが見つかりません`"" }
        @{ Name="oglaszamy24h.pl"; Category="Marketplace"; Url="https://oglaszamy24h.pl/profil,{user}"; FoundMarker="Profil użytkownika:"; NotFoundMarker="Nieprawidłowy link, w bazie danych nie istnieje użytkownik o podanym loginie" }
        @{ Name="ok.ru"; Category="Social"; Url="https://ok.ru/{user}"; FoundMarker="| OK"; NotFoundMarker="class=`"p404_t" }
        @{ Name="okidoki"; Category="Misc"; Url="https://m.okidoki.ee/ru/users/{user}/"; FoundMarker="Пользователь"; NotFoundMarker="Страница не найдена" }
        @{ Name="omg.lol"; Category="Social"; Url="https://api.omg.lol/address/{user}/info"; FoundMarker="`"success`": true"; NotFoundMarker="`"success`": false" }
        @{ Name="OP.GG"; Category="Gaming"; Url="https://eune.op.gg/summoners/eune/{user}"; FoundMarker="- Summoner Stats - League of Legends"; NotFoundMarker="Guide - OP.GG" }
        @{ Name="OpenSource"; Category="Tech"; Url="https://opensource.com/users/{user}"; FoundMarker="`"contentID`":"; NotFoundMarker="`"errorCode`": `"404`"" }
        @{ Name="OpenStreetMap"; Category="Social"; Url="https://www.openstreetmap.org/user/{user}"; FoundMarker="Mapper since:"; NotFoundMarker="does not exist" }
        @{ Name="OpenStreetMap Wiki"; Category="Social"; Url="https://wiki.openstreetmap.org/w/api.php?action=query&format=json&list=users&ususers={user}"; FoundMarker="`"userid`":"; NotFoundMarker="`"missing`":`"`"" }
        @{ Name="Oper.ru"; Category="Tech"; Url="https://oper.ru/visitors/info.php?t={user}"; FoundMarker="Информация о пользователе"; NotFoundMarker="Нет такого пользователя" }
        @{ Name="Origins.Habbo.com"; Category="Gaming"; Url="https://origins.habbo.com/api/public/users?name={user}"; FoundMarker="uniqueId"; NotFoundMarker="not-found" }
        @{ Name="Origins.Habbo.com.br"; Category="Gaming"; Url="https://origins.habbo.com.br/api/public/users?name={user}"; FoundMarker="uniqueId"; NotFoundMarker="not-found" }
        @{ Name="Origins.Habbo.es"; Category="Gaming"; Url="https://origins.habbo.es/api/public/users?name={user}"; FoundMarker="uniqueId"; NotFoundMarker="not-found" }
        @{ Name="osu!"; Category="Gaming"; Url="https://osu.ppy.sh/users/{user}"; FoundMarker=""; NotFoundMarker="User not found! ;_;" }
        @{ Name="palnet"; Category="Social"; Url="https://www.palnet.io/@{user}/"; FoundMarker="class=`"profile-cover`""; NotFoundMarker="Unknown user account!" }
        @{ Name="Paragraph"; Category="Creative"; Url="https://paragraph.com/api/blogs/@{user}"; FoundMarker="`"user`":{"; NotFoundMarker="`"Missing blog`"" }
        @{ Name="Parler"; Category="Social"; Url="https://parler.com/user/{user}"; FoundMarker="People to Follow"; NotFoundMarker="join Parler today" }
        @{ Name="patch"; Category="News"; Url="https://patch.com/users/{user}"; FoundMarker="<title>Patch User Profile"; NotFoundMarker="<title>Page not found</title>" }
        @{ Name="PatientsLikeMe"; Category="Fitness"; Url="https://www.patientslikeme.com/members/{user}"; FoundMarker="s profile | PatientsLikeMe</title>"; NotFoundMarker="" }
        @{ Name="Patriots Win"; Category="Political"; Url="https://patriots.win/api/v2/user/about.json?user={user}"; FoundMarker="`"users`":[{"; NotFoundMarker="`"error`":`"invalid user`"" }
        @{ Name="Patronite"; Category="Finance"; Url="https://patronite.pl/{user}"; FoundMarker="Zostań Patronem"; NotFoundMarker="Nie znaleźliśmy strony której szukasz." }
        @{ Name="PayPal Business"; Category="Finance"; Url="https://www.paypal.com/biz/profile-data/{user}"; FoundMarker="`"payerId`":"; NotFoundMarker="`"error`":`"RESOURCE_NOT_FOUND`"" }
        @{ Name="PayPal.Me"; Category="Finance"; Url="https://www.paypal.com/paypalme/{user}"; FoundMarker="`"recipientSlugDetails`":"; NotFoundMarker="`",`"griffinMetadata`":{`"" }
        @{ Name="PCPartPicker"; Category="Tech"; Url="https://pcpartpicker.com/user/{user}/"; FoundMarker="class=`"active`""; NotFoundMarker="The page you requested could not be found." }
        @{ Name="Peerlist"; Category="Code"; Url="https://peerlist.io/api/v1/users/profile/tldr?handle={user}"; FoundMarker="`"tldr`":"; NotFoundMarker="`"message`":`"User Not found`"" }
        @{ Name="Peing"; Category="Social"; Url="https://peing.net/en/{user}"; FoundMarker="data-route-user-id-main=''"; NotFoundMarker="user_is_not_found" }
        @{ Name="Peoople (Creator)"; Category="Social"; Url="https://peoople.app/en/creator/{user}/"; FoundMarker="`"@type`":`"BreadcrumbList`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="Peoople (Influencer)"; Category="Social"; Url="https://peoople.app/en/influencer/{user}/"; FoundMarker="`"@type`":`"BreadcrumbList`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="Peoople (Star)"; Category="Social"; Url="https://peoople.app/en/star/{user}/"; FoundMarker="`"@type`":`"BreadcrumbList`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="Peoople (Unicorn)"; Category="Social"; Url="https://peoople.app/en/unicorn/{user}/"; FoundMarker="`"@type`":`"BreadcrumbList`""; NotFoundMarker="id=`"__next_error__`"" }
        @{ Name="Periscope"; Category="Video"; Url="https://www.periscope.tv/{user}"; FoundMarker="<label>Followers"; NotFoundMarker="Sorry, this page doesn’t exist" }
        @{ Name="Pewex"; Category="Misc"; Url="https://retro.pewex.pl/user/{user}"; FoundMarker="Zamieszcza eksponaty od:"; NotFoundMarker="Nie znaleziono użytkownika o podanym loginie." }
        @{ Name="Picsart"; Category="Creative"; Url="https://api.picsart.com/users/show/{user}.json"; FoundMarker="`"status`":`"success`""; NotFoundMarker="`"status`":`"error`"" }
        @{ Name="Piekielni"; Category="Misc"; Url="https://piekielni.pl/user/{user}"; FoundMarker="Zamieszcza historie od:"; NotFoundMarker="Nie znaleziono użytkownika o podanym loginie." }
        @{ Name="Pillowfort"; Category="Social"; Url="https://www.pillowfort.social/{user}/json/?p=1"; FoundMarker="`"posts`":"; NotFoundMarker="<title>(404)</title>" }
        @{ Name="PinkBike"; Category="Hobby"; Url="https://www.pinkbike.com/u/{user}/"; FoundMarker="on Pinkbike</title>"; NotFoundMarker="I couldn't find the page you were looking for" }
        @{ Name="Planoly"; Category="Misc"; Url="https://planoly.store/{user}"; FoundMarker="`"creatorLink`":{"; NotFoundMarker="`"statusCode`":404" }
        @{ Name="Plink"; Category="Gaming"; Url="https://plink.gg/user/{user}"; FoundMarker="class=`"user-page`""; NotFoundMarker="<title>PLINK - 404 Page not found</title>" }
        @{ Name="Poe.com"; Category="Tech"; Url="https://poe.com/profile/{user}"; FoundMarker="`"__isNode`":`"PoeUser`""; NotFoundMarker="`"user`":null" }
        @{ Name="Pokec"; Category="Social"; Url="https://pokec.azet.sk/{user}"; FoundMarker="idReportedUser"; NotFoundMarker="profile--unknown_title`">Neexistujúci používateľ" }
        @{ Name="pokemonshowdown"; Category="Gaming"; Url="https://pokemonshowdown.com/users/{user}"; FoundMarker="Official ladder"; NotFoundMarker="(Unregistered)" }
        @{ Name="Polarsteps"; Category="Social"; Url="https://www.polarsteps.com/{user}"; FoundMarker="`"user-profile`""; NotFoundMarker="Ups! User not found." }
        @{ Name="Polchat.pl"; Category="Social"; Url="https://polczat.pl/forum/profile/{user}/"; FoundMarker="Historia wpisów"; NotFoundMarker="Wybrany użytkownik nie istnieje." }
        @{ Name="Poll Everywhere"; Category="Tech"; Url="https://pollev.com/proxy/api/users/{user}"; FoundMarker="name"; NotFoundMarker="ResourceNotFound" }
        @{ Name="polygon"; Category="Gaming"; Url="https://www.polygon.com/users/{user}"; FoundMarker="- Polygon"; NotFoundMarker="404 Not found" }
        @{ Name="popl"; Category="Professional"; Url="https://poplme.co/{user}"; FoundMarker="MuiTypography-root MuiTypography-body1 css-kj7pvm"; NotFoundMarker="Profile not found" }
        @{ Name="Pornhub (Model)"; Category="Xx nsfw xx"; Url="https://www.pornhub.com/model/{user}"; FoundMarker="class=`"topProfileHeader`""; NotFoundMarker="" }
        @{ Name="Pornhub (Pornstar)"; Category="Xx nsfw xx"; Url="https://www.pornhub.com/pornstar/{user}"; FoundMarker="class=`"topProfileHeader`""; NotFoundMarker="" }
        @{ Name="Pornhub (User)"; Category="Xx nsfw xx"; Url="https://www.pornhub.com/users/{user}"; FoundMarker="id=`"topProfileHeader`""; NotFoundMarker="<title>Page Not Found</title>" }
        @{ Name="postcrossing"; Category="Social"; Url="https://www.postcrossing.com/user/{user}"; FoundMarker=", from"; NotFoundMarker="- Postcrossing" }
        @{ Name="Poweredbygay.social (Mastodon Instance)"; Category="Social"; Url="https://poweredbygay.social/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Pr0gramm"; Category="Social"; Url="https://pr0gramm.com/api/profile/info?name={user}"; FoundMarker="`"user`":"; NotFoundMarker="`"code`":404" }
        @{ Name="Pravda.me"; Category="Social"; Url="https://pravda.me/@{user}"; FoundMarker="Социальная сеть - Правда (by mastodon)</title>"; NotFoundMarker="<title>The page you are looking for isn&#39;t here." }
        @{ Name="Privacy Guides"; Category="Tech"; Url="https://discuss.privacyguides.net/u/{user}.json"; FoundMarker="`"user_badges`":"; NotFoundMarker="The requested URL or resource could not be found." }
        @{ Name="Pronouny"; Category="Social"; Url="https://pronouny.xyz/api/users/profile/username/{user}"; FoundMarker="`"username`":"; NotFoundMarker="That user doesn't exist" }
        @{ Name="Prose"; Category="Creative"; Url="https://prose.astral.camp/{user}/"; FoundMarker="blog-title"; NotFoundMarker="Are you sure it was ever here?" }
        @{ Name="prv.pl"; Category="Tech"; Url="https://www.prv.pl/osoba/{user}"; FoundMarker="LOGIN"; NotFoundMarker="Użytkownik nie istnieje." }
        @{ Name="QUEER PL"; Category="Social"; Url="https://queer.pl/user/{user}"; FoundMarker="- Profile</title>"; NotFoundMarker="Strona nie została znaleziona" }
        @{ Name="Raddle.me"; Category="Social"; Url="https://raddle.me/user/{user}"; FoundMarker="sidebar__title"; NotFoundMarker="404 Not Found" }
        @{ Name="Rant.li"; Category="Creative"; Url="https://rant.li/{user}/"; FoundMarker="blog-title"; NotFoundMarker="Are you sure it was ever here?" }
        @{ Name="Rarible"; Category="Tech"; Url="https://rarible.com/marketplace/api/v4/urls/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"success`":false" }
        @{ Name="RedGIFs"; Category="Xx nsfw xx"; Url="https://api.redgifs.com/v1/users/{user}"; FoundMarker="`"name`":"; NotFoundMarker="`"status`":404" }
        @{ Name="Refsheet"; Category="Hobby"; Url="https://refsheet.net/{user}"; FoundMarker="og:title"; NotFoundMarker="That's unfortunate. Where did it go?" }
        @{ Name="resumes_actorsaccess"; Category="Social"; Url="https://resumes.actorsaccess.com/{user}"; FoundMarker="- Resume | Actors Access</title>"; NotFoundMarker="File was not found on this SERVER" }
        @{ Name="Revolut"; Category="Finance"; Url="https://revolut.me/api/web-profile/{user}"; FoundMarker="`"firstName`""; NotFoundMarker="`"User not found`"" }
        @{ Name="risk.ru"; Category="Hobby"; Url="https://risk.ru/people/{user}"; FoundMarker="— Люди — Risk.ru"; NotFoundMarker="404 — Risk.ru" }
        @{ Name="Roberts Space Industries"; Category="Gaming"; Url="https://robertsspaceindustries.com/community-hub/user/{user}"; FoundMarker="Query`",`"creator"; NotFoundMarker="`"/404`",`"query" }
        @{ Name="Roblox"; Category="Gaming"; Url="https://auth.roblox.com/v1/usernames/validate?username={user}&birthday=2019-12-31T23:00:00.000Z"; FoundMarker="Username is already in use"; NotFoundMarker="Username is valid" }
        @{ Name="RoutineHub"; Category="Social"; Url="https://routinehub.co/user/{user}"; FoundMarker="Downloads:"; NotFoundMarker="A community for Apple Shortcuts</title>" }
        @{ Name="ru_123rf"; Category="Hobby"; Url="https://ru.123rf.com/profile_{user}"; FoundMarker="userID"; NotFoundMarker="<title>Фотобанк 123RF - Стоковые Фото, Векторы, Видеоролики. Подписка на Фото. R" }
        @{ Name="RuneScape"; Category="Hobby"; Url="https://apps.runescape.com/runemetrics/profile/profile?user={user}"; FoundMarker="`"name`":"; NotFoundMarker="`"error`":`"NO_PROFILE`"" }
        @{ Name="RuTracker.org"; Category="Misc"; Url="https://rutracker.org/forum/profile.php?mode=viewprofile&u={user}"; FoundMarker="Профиль пользователя"; NotFoundMarker="Пользователь не найден" }
        @{ Name="ruVoIP.net"; Category="Tech"; Url="https://ruvoip.net/members/{user}/"; FoundMarker="id=`"user-xprofile`""; NotFoundMarker="Error 404 - Not Found" }
        @{ Name="Salon24"; Category="Creative"; Url="https://www.salon24.pl/u/{user}/"; FoundMarker="<span>Obserwujących</span>"; NotFoundMarker="<title>Salon24 - Blogi, wiadomości, opinie i komentarze" }
        @{ Name="Scammer.info"; Category="Misc"; Url="https://scammer.info/u/{user}.json"; FoundMarker="avatar_template"; NotFoundMarker="The requested URL or resource could not be found" }
        @{ Name="Scored"; Category="Social"; Url="https://scored.co/api/v2/user/about.json?user={user}"; FoundMarker="`"status`":true"; NotFoundMarker="`"status`":false" }
        @{ Name="ScoutWiki"; Category="Social"; Url="https://en.scoutwiki.org/User:{user}"; FoundMarker="NewPP limit report"; NotFoundMarker="is not registered" }
        @{ Name="Scratch"; Category="Code"; Url="https://api.scratch.mit.edu/accounts/checkusername/{user}/"; FoundMarker="`"msg`":`"username exists`""; NotFoundMarker="`"msg`":`"valid username`"" }
        @{ Name="Scribd (Document)"; Category="Hobby"; Url="https://www.scribd.com/search/query?query={user}&verbatim=true"; FoundMarker="`"compilationId`":`""; NotFoundMarker="`"compilationId`":null" }
        @{ Name="Searchengines"; Category="Hobby"; Url="https://searchengines.guru/ru/search?keyword=&author={user}&sortByDate=true"; FoundMarker="class=`"search-result__item`""; NotFoundMarker="class=`"nothing-found`"" }
        @{ Name="Seneporno"; Category="Xx nsfw xx"; Url="https://seneporno.com/user/{user}"; FoundMarker="Dernier Login"; NotFoundMarker="Unexpected error! Please contact us and tell us more how you got to this page!" }
        @{ Name="sentimente"; Category="Dating"; Url="https://www.sentimente.com/amp/{user}.html"; FoundMarker="Chat online with"; NotFoundMarker="HTTP Error code: 404. Resource not found" }
        @{ Name="SEOClerks"; Category="Social"; Url="https://www.seoclerks.com/user/{user}"; FoundMarker="<div class=`"user-info container`">"; NotFoundMarker="<title>SEO Marketplace" }
        @{ Name="Sepia Search (PeerTube)"; Category="Video"; Url="https://sepiasearch.org/api/v1/search/video-channels?search=%22{user}%22&start=0&count=10"; FoundMarker="`"data`":[{"; NotFoundMarker="`"data`":[]" }
        @{ Name="setlist.fm"; Category="Audio"; Url="https://www.setlist.fm/user/{user}"; FoundMarker="s setlist.fm | setlist.fm</title>"; NotFoundMarker="Sorry, the page you requested doesn't exist" }
        @{ Name="SFD"; Category="Fitness"; Url="https://www.sfd.pl/profile/{user}"; FoundMarker="Tematy użytkownika"; NotFoundMarker="Brak aktywnego profilu na forum" }
        @{ Name="Shesfreaky"; Category="Xx nsfw xx"; Url="https://www.shesfreaky.com/profile/{user}/"; FoundMarker="s Profile - ShesFreaky</title>"; NotFoundMarker="" }
        @{ Name="Shikimori"; Category="Social"; Url="https://shikimori.io/{user}"; FoundMarker="class=`"profile-head`""; NotFoundMarker="class=`"error-404`"" }
        @{ Name="shopify"; Category="Marketplace"; Url="https://{user}.myshopify.com"; FoundMarker="home"; NotFoundMarker="Sorry, this shop is currently unavailable." }
        @{ Name="Showup.tv"; Category="Xx nsfw xx"; Url="https://showup.tv/profile/{user}"; FoundMarker="O mnie"; NotFoundMarker="<title>Darmowe" }
        @{ Name="shutterstock"; Category="Images"; Url="https://www.shutterstock.com/g/{user}"; FoundMarker="| Shutterstock"; NotFoundMarker="Well, this is unexpected..." }
        @{ Name="SimplePlanes"; Category="Gaming"; Url="https://www.simpleplanes.com/u/{user}"; FoundMarker="<h5>joined"; NotFoundMarker="<title>SimplePlanes Airplanes</title>" }
        @{ Name="skeb"; Category="Creative"; Url="https://skeb.jp/@{user}"; FoundMarker=") | Skeb"; NotFoundMarker="Skeb - Request Box" }
        @{ Name="SlackHoles"; Category="Xx nsfw xx"; Url="https://slackholes.com/actor/{user}/"; FoundMarker="Pussy and Ass Sizes"; NotFoundMarker="It looks like nothing was found at this location" }
        @{ Name="Slant"; Category="Marketplace"; Url="https://www.slant.co/users/{user}?format=jsonp&callback=jsonLoaded"; FoundMarker="`"uuid`":"; NotFoundMarker="`"error`":404" }
        @{ Name="slides"; Category="Social"; Url="https://slides.com/{user}"; FoundMarker="Presentations by"; NotFoundMarker="You may have mistyped the address" }
        @{ Name="SmashRun"; Category="Fitness"; Url="https://smashrun.com/{user}/"; FoundMarker="Miles run overall"; NotFoundMarker="no Smashrunner with the username" }
        @{ Name="SmugMug"; Category="Images"; Url="https://{user}.smugmug.com"; FoundMarker="schema.org/Person"; NotFoundMarker="schema.org/Thing" }
        @{ Name="soc.citizen4.eu"; Category="Social"; Url="https://soc.citizen4.eu/profile/{user}/profile"; FoundMarker="@soc.citizen4.eu"; NotFoundMarker="Nie znaleziono" }
        @{ Name="social.bund.de"; Category="Social"; Url="https://social.bund.de/@{user}"; FoundMarker="@social.bund.de) - social.bund.de</title>"; NotFoundMarker="<title>The page you are looking for isn&#39;t here." }
        @{ Name="sofurry"; Category="Creative"; Url="https://{user}.sofurry.com"; FoundMarker="'s Profile | SoFurry"; NotFoundMarker="SoFurry - Error | SoFurry" }
        @{ Name="solo.to"; Category="Social"; Url="https://solo.to/{user}"; FoundMarker="create your own page"; NotFoundMarker="The page you're looking for isn't here." }
        @{ Name="Soup"; Category="Creative"; Url="https://www.soup.io/author/{user}"; FoundMarker="Author at Soup.io"; NotFoundMarker="Soup.io - News, Sports, Entertainment, TV, Tech, Gaming" }
        @{ Name="SPOJ"; Category="Code"; Url="https://www.spoj.com/users/{user}/"; FoundMarker="<h3>Activity over the last year</h3>"; NotFoundMarker="<strong>Innopolis Open 2018</strong>" }
        @{ Name="sporcle"; Category="Gaming"; Url="https://www.sporcle.com/user/{user}/people/"; FoundMarker="'s Sporcle Friends"; NotFoundMarker="This Sporcle user cannot be found." }
        @{ Name="Sports Tracker"; Category="Fitness"; Url="https://api.sports-tracker.com/apiserver/v1/user/name/{user}"; FoundMarker="`"uuid`":"; NotFoundMarker="`"code`":`"404`"" }
        @{ Name="StackOverflow"; Category="Code"; Url="https://api.stackexchange.com/2.3/users?order=desc&sort=name&inname={user}&site=stackoverflow"; FoundMarker="`"items`":[{"; NotFoundMarker="`"items`":[]" }
        @{ Name="stats.fm"; Category="Audio"; Url="https://api.stats.fm/api/v1/users/{user}"; FoundMarker="`"item`":{"; NotFoundMarker="`"status`":404" }
        @{ Name="Statuspage"; Category="Tech"; Url="https://{user}.statuspage.io/api/v2/status.json"; FoundMarker="updated_at"; NotFoundMarker="<html><body>You are being <a href=`"https://www.statuspage.io`">redirected</a>.<" }
        @{ Name="SteamGifts"; Category="Gaming"; Url="https://www.steamgifts.com/user/{user}"; FoundMarker="`"identifier`":"; NotFoundMarker="" }
        @{ Name="steller"; Category="Marketplace"; Url="https://steller.co/{user}"; FoundMarker="on Steller</title>"; NotFoundMarker="<title></title>" }
        @{ Name="StoryCorps"; Category="Creative"; Url="https://archive.storycorps.org/user/{user}/"; FoundMarker="archive author"; NotFoundMarker="We're sorry, but the page" }
        @{ Name="StreamElements"; Category="Finance"; Url="https://api.streamelements.com/kappa/v2/channels/{user}"; FoundMarker="`"providerId`""; NotFoundMarker="error" }
        @{ Name="StreamLabs"; Category="Finance"; Url="https://streamlabs.com/api/v6/user/{user}"; FoundMarker="`"id`":"; NotFoundMarker="<title>Unauthorized</title>" }
        @{ Name="Stripchat"; Category="Xx nsfw xx"; Url="https://stripchat.com/api/front/users/checkUsername?username={user}"; FoundMarker="`"error`":`"This username already exists`""; NotFoundMarker="[]" }
        @{ Name="Subscribestar"; Category="Xx nsfw xx"; Url="https://subscribestar.adult/{user}"; FoundMarker="CREATOR STATS"; NotFoundMarker="WE ARE SORRY, THE PAGE YOU REQUESTED CANNOT BE FOUND" }
        @{ Name="sukebei.nyaa.si"; Category="Xx nsfw xx"; Url="https://sukebei.nyaa.si/user/{user}"; FoundMarker="'s torrents"; NotFoundMarker="404 Not Found" }
        @{ Name="Suzuri"; Category="Professional"; Url="https://suzuri.jp/{user}"; FoundMarker="Items"; NotFoundMarker="Push Space-key" }
        @{ Name="szmer.info"; Category="Social"; Url="https://szmer.info/u/{user}"; FoundMarker="Joined"; NotFoundMarker="Code: Couldn't find that username or email." }
        @{ Name="tabletoptournament"; Category="Misc"; Url="https://www.tabletoptournaments.net/eu/player/{user}"; FoundMarker="- Player Profile | T³ - TableTop Tournaments"; NotFoundMarker="No player with the nickname" }
        @{ Name="TamTam"; Category="Social"; Url="https://tamtam.chat/{user}"; FoundMarker="deeplink=tamtam://chat/"; NotFoundMarker="ТамТам</title>" }
        @{ Name="Tanuki.pl"; Category="Hobby"; Url="https://tanuki.pl/profil/{user}"; FoundMarker="Dołączył"; NotFoundMarker="Nie ma takiego użytkownika" }
        @{ Name="TAPiTAG"; Category="Professional"; Url="https://account.tapitag.co/tapitag/api/v1/{user}"; FoundMarker="User details are Showing"; NotFoundMarker="The rf number is not valid" }
        @{ Name="Tappy"; Category="Professional"; Url="https://api.tappy.tech/api/profile/username/{user}"; FoundMarker="user_id"; NotFoundMarker="Profile of username Not Found" }
        @{ Name="Taringa"; Category="Social"; Url="https://www.taringa.net/{user}"; FoundMarker="en Taringa!</title>"; NotFoundMarker="Colectiva en Taringa!</title>" }
        @{ Name="taskrabbit"; Category="Professional"; Url="https://www.taskrabbit.com/profile/{user}/about"; FoundMarker="’s Profile"; NotFoundMarker="" }
        @{ Name="Teamtreehouse"; Category="Code"; Url="https://teamtreehouse.com/{user}"; FoundMarker="Member Since"; NotFoundMarker="Oops, Something went missing" }
        @{ Name="Teespring"; Category="Professional"; Url="https://commerce.teespring.com/v1/stores?slug={user}"; FoundMarker="sellerToken"; NotFoundMarker="{`"errors`":{`"store`":[`"not found`"]}}" }
        @{ Name="Teknik"; Category="Tech"; Url="https://user.teknik.io/{user}"; FoundMarker="Public Key"; NotFoundMarker="The user does not exist" }
        @{ Name="Teletype"; Category="Creative"; Url="https://teletype.in/@{user}"; FoundMarker="class=`"layout__content m_main blog`""; NotFoundMarker="class=`"error`"" }
        @{ Name="Tellonym"; Category="Social"; Url="https://api.tellonym.me/profiles/name/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"code`":`"NOT_FOUND`"" }
        @{ Name="TETR.IO"; Category="Gaming"; Url="https://ch.tetr.io/api/users/{user}"; FoundMarker="`"success`":true"; NotFoundMarker="`"success`":false" }
        @{ Name="TF2 Backpack Examiner"; Category="Gaming"; Url="https://www.tf2items.com/id/{user}"; FoundMarker="var profileId"; NotFoundMarker="" }
        @{ Name="The Gateway Pundit"; Category="Political"; Url="https://www.thegatewaypundit.com/author/{user}/"; FoundMarker="meta property=`"og:type`" content=`"profile`""; NotFoundMarker="<title>The Gateway Pundit * Conservative news and commentary" }
        @{ Name="theguardian"; Category="News"; Url="https://www.theguardian.com/profile/{user}"; FoundMarker="content=`"&#x3C;p&#x3E;"; NotFoundMarker="<title>Page Not Found | The Guardian</title>" }
        @{ Name="themeforest"; Category="Creative"; Url="https://themeforest.net/user/{user}"; FoundMarker="s profile on ThemeForest"; NotFoundMarker="Page Not Found | ThemeForest" }
        @{ Name="Thetattooforum"; Category="Creative"; Url="https://www.thetattooforum.com/members/{user}/"; FoundMarker="Insert This Gallery"; NotFoundMarker="We’re sorry" }
        @{ Name="thoughts"; Category="Hobby"; Url="https://thoughts.com/members/{user}/"; FoundMarker="<span class=`"activity"; NotFoundMarker="<title>Page not found" }
        @{ Name="Tilde.zone (Mastodon Instance)"; Category="Social"; Url="https://tilde.zone/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Tinder"; Category="Dating"; Url="https://tinder.com/@{user}"; FoundMarker=") | Tinder</title>"; NotFoundMarker="Tinder | Dating, Make Friends &amp; Meet New People" }
        @{ Name="TipeeeStream"; Category="Finance"; Url="https://www.tipeeestream.com/v3.0/pages/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"message`":`"Not found`"" }
        @{ Name="Tooting.ch (Mastodon Instance)"; Category="Social"; Url="https://tooting.ch/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Topcoder"; Category="Code"; Url="https://api.topcoder.com/v5/members/{user}"; FoundMarker="`"userId`":"; NotFoundMarker="`"message`":`"Member with handle:" }
        @{ Name="toyhou.se"; Category="Hobby"; Url="https://toyhou.se/{user}"; FoundMarker="display-user"; NotFoundMarker="We can't find that page!" }
        @{ Name="TradingView"; Category="Finance"; Url="https://www.tradingview.com/u/{user}/"; FoundMarker="class=`"js-user-profile`""; NotFoundMarker="class=`"tv-http-error-page__image tv-http-error-page__image--404`"" }
        @{ Name="TRAKTRAIN"; Category="Audio"; Url="https://traktrain.com/{user}"; FoundMarker="id=`"userId`""; NotFoundMarker="class=`"title-404`"" }
        @{ Name="Trello"; Category="Social"; Url="https://trello.com/1/Members/{user}"; FoundMarker="`"id`":"; NotFoundMarker="<h1>Oh no! 404!</h1>" }
        @{ Name="TruckersMP"; Category="Gaming"; Url="https://truckersmp.com/user/search?search={user}"; FoundMarker="class=`"team-v2`""; NotFoundMarker="<h4>Could not find any member using these credentials</h4>" }
        @{ Name="TruckersMP.Ru"; Category="Gaming"; Url="https://truckersmp.ru/{user}"; FoundMarker="class=`"b-user-page`""; NotFoundMarker="class=`"b-handler-error-404`"" }
        @{ Name="Tryst"; Category="Xx nsfw xx"; Url="https://tryst.link/escort/{user}"; FoundMarker="Caters to</div>"; NotFoundMarker="<title>Page not found" }
        @{ Name="tunefind"; Category="Audio"; Url="https://www.tunefind.com/api-request/account/profile?userName={user}"; FoundMarker="`"user-stats-engagement`":"; NotFoundMarker="`"code`":`"not_found`"" }
        @{ Name="Tweetapus"; Category="Social"; Url="https://tweetapus.tiag.workers.dev/@{user}.json"; FoundMarker="`"username`":"; NotFoundMarker="`"error`": `"User not found`"" }
        @{ Name="Twitcast"; Category="Social"; Url="https://frontendapi.twitcasting.tv/users/{user}"; FoundMarker="`"user`":{"; NotFoundMarker="`"message`":`"User Not Found`"" }
        @{ Name="Twitch"; Category="Gaming"; Url="https://twitchtracker.com/{user}"; FoundMarker="Overview</a>"; NotFoundMarker="<title>404 Page Not Found" }
        @{ Name="twpro"; Category="Social"; Url="https://twpro.jp/{user}/q-data.json"; FoundMarker=",200,`"/"; NotFoundMarker=",404,`"/" }
        @{ Name="Udemy"; Category="Tech"; Url="https://www.udemy.com/user/{user}/"; FoundMarker="| Udemy</title>"; NotFoundMarker="<title>Online Courses - Learn Anything, On Your Schedule | Udemy</title>" }
        @{ Name="UEF CONNECT"; Category="Professional"; Url="https://uefconnect.uef.fi/en/{user}/"; FoundMarker="profile-page-header__info"; NotFoundMarker="<title>Page not found - UEFConnect</title>" }
        @{ Name="Ultimate Guitar"; Category="Hobby"; Url="https://www.ultimate-guitar.com/u/{user}"; FoundMarker="| Ultimate-Guitar.Com</title>"; NotFoundMarker="Oops! We couldn't find that page." }
        @{ Name="Ultras Diary"; Category="Hobby"; Url="http://ultrasdiary.pl/u/{user}/"; FoundMarker="Mecze wyjazdowe:"; NotFoundMarker="Ile masz wyjazdów?" }
        @{ Name="Unlisted Videos"; Category="Archived"; Url="https://unlistedvideos.com/search.php?user={user}"; FoundMarker="Date submitted"; NotFoundMarker="content=`"`"/>" }
        @{ Name="USA Life"; Category="Social"; Url="https://usa.life/{user}"; FoundMarker="Please log in to like, share and comment"; NotFoundMarker="Sorry, page not found" }
        @{ Name="utip.io"; Category="Finance"; Url="https://utip.io/creator/profile/{user}"; FoundMarker="`"userName`""; NotFoundMarker="Not a valid web service key" }
        @{ Name="uwu.ai"; Category="Social"; Url="https://{user}.uwu.ai/"; FoundMarker="property=`"twitter:card`""; NotFoundMarker="Sorry, the requested page could not be found." }
        @{ Name="Uwumarket"; Category="Professional"; Url="https://uwumarket.us/collections/{user}"; FoundMarker="data-collection-filters"; NotFoundMarker="Page not found" }
        @{ Name="vapenews"; Category="Hobby"; Url="https://vapenews.ru/profile/{user}"; FoundMarker="<title inertia>Профиль</title></head>"; NotFoundMarker="<title>404</title>" }
        @{ Name="Venmo"; Category="Finance"; Url="https://account.venmo.com/u/{user}"; FoundMarker="profileInfo_username__"; NotFoundMarker="Sorry, the page you requested does not exist!" }
        @{ Name="Vero"; Category="Creative"; Url="https://vero.co/{user}"; FoundMarker="name=`"username"; NotFoundMarker="<h3>Not Found</h3>" }
        @{ Name="vibilagare"; Category="Misc"; Url="https://www.vibilagare.se/users/{user}"; FoundMarker="class=`"user-profile`""; NotFoundMarker="Sidan hittades inte |" }
        @{ Name="VIEWBUG"; Category="Hobby"; Url="https://www.viewbug.com/member/{user}"; FoundMarker="class=`"top-profile-membership`""; NotFoundMarker="id=`"missing-this`"" }
        @{ Name="Vine"; Category="Video"; Url="https://vine.co/api/users/profiles/vanity/{user}"; FoundMarker="userId"; NotFoundMarker="That record does not exist" }
        @{ Name="VIP-blog"; Category="Creative"; Url="https://{user}.vip-blog.com/"; FoundMarker="blog :"; NotFoundMarker="Blog inexistant" }
        @{ Name="VirusTotal"; Category="Misc"; Url="https://www.virustotal.com/ui/users/{user}"; FoundMarker="`"data`""; NotFoundMarker="`"code`": `"NotFoundError`"" }
        @{ Name="visnesscard"; Category="Professional"; Url="https://my.visnesscard.com/Home/GetCard/{user}"; FoundMarker="end_point"; NotFoundMarker="card_id`": 0" }
        @{ Name="Vivino"; Category="Marketplace"; Url="https://api.vivino.com/users/{user}"; FoundMarker="`"id`":"; NotFoundMarker="`"error`":{`"message`":`"Record not found`"}" }
        @{ Name="Vkl.world (Mastodon Instance)"; Category="Social"; Url="https://vkl.world/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Vmst.io (Mastodon Instance)"; Category="Social"; Url="https://vmst.io/api/v1/accounts/lookup?acct={user}"; FoundMarker="display_name"; NotFoundMarker="Record not found" }
        @{ Name="Voice123"; Category="Hobby"; Url="https://voice123.com/api/providers/search/{user}"; FoundMarker="user_id"; NotFoundMarker="[]" }
        @{ Name="Voices.com"; Category="Professional"; Url="https://www.voices.com/profile/{user}/"; FoundMarker="Last Online</h3>"; NotFoundMarker="Try going back to the previous page or see below for more options" }
        @{ Name="VseTop"; Category="Tech"; Url="https://vsetop.org/user/{user}/"; FoundMarker="class=`"userinfo`""; NotFoundMarker="<p>Пользователь с таким именем не найден.</p>" }
        @{ Name="W3Schools"; Category="Tech"; Url="https://pathfinder-api.kai.w3spaces.com/public-profile-api/{user}"; FoundMarker="`"createdAt`":"; NotFoundMarker="`"message`":`"Profile does not exists or not visible`"" }
        @{ Name="Warmerise"; Category="Gaming"; Url="https://warmerise.com/profile/{user}"; FoundMarker="<div id='profile_photo"; NotFoundMarker="<h2>Page Not Found" }
        @{ Name="warriorforum"; Category="Hobby"; Url="https://www.warriorforum.com/members/{user}.html"; FoundMarker="Last Activity:"; NotFoundMarker="Oops | Warrior Forum -" }
        @{ Name="WatchMeMore"; Category="Xx nsfw xx"; Url="https://watchmemore.com/{user}/"; FoundMarker="`"dateCreated`":"; NotFoundMarker="`"Account not exists" }
        @{ Name="Watchmyfeed"; Category="Xx nsfw xx"; Url="https://watchmyfeed.com/{user}"; FoundMarker="SEND ME A TIP"; NotFoundMarker="" }
        @{ Name="waytohey"; Category="Social"; Url="https://waytohey.com/{user}"; FoundMarker="Send message</span>"; NotFoundMarker="Unfortunately, this page doesn&#039;t exist." }
        @{ Name="Weblancer"; Category="Social"; Url="https://www.weblancer.net/users/{user}/"; FoundMarker="`"user`":"; NotFoundMarker="`"page`":`"/404`"" }
        @{ Name="Weblate"; Category="Hobby"; Url="https://hosted.weblate.org/user/{user}/"; FoundMarker="class=`"user-page text-center`""; NotFoundMarker="<h2>Page Not Found</h2>" }
        @{ Name="weebly"; Category="Misc"; Url="https://{user}.weebly.com/"; FoundMarker="<div id=`"navigation`">"; NotFoundMarker="<title>404 - Page Not Found" }
        @{ Name="wego"; Category="Political"; Url="https://wego.social/{user}"; FoundMarker="Following</span>"; NotFoundMarker="Sorry, page not found!" }
        @{ Name="weheartit"; Category="Social"; Url="https://weheartit.com/{user}"; FoundMarker="on We Heart It</title>"; NotFoundMarker="(404)</title>" }
        @{ Name="Weibo"; Category="Social"; Url="https://weibo.com/ajax/profile/info?custom={user}"; FoundMarker="`"user`":"; NotFoundMarker="<h2>400 Bad Request</h2>" }
        @{ Name="WeTransfer"; Category="Creative"; Url="https://wepresent.wetransfer.com/artists/{user}"; FoundMarker="name`":`"WePresent |"; NotFoundMarker="text-display-4`">404 error" }
        @{ Name="Wikidot"; Category="Social"; Url="https://www.wikidot.com/user:info/{user}"; FoundMarker="<h1 class=`"profile-title`">"; NotFoundMarker="<div class=`"error-block`">User does not exist.</div>" }
        @{ Name="Wikimapia"; Category="Social"; Url="https://wikimapia.org/user/register/?check=username&value={user}"; FoundMarker="`"ok`":false"; NotFoundMarker="`"ok`":true" }
        @{ Name="Wimkin-PublicProfile"; Category="Political"; Url="https://wimkin.com/{user}"; FoundMarker="is on WIMKIN"; NotFoundMarker="The page you are looking for cannot be found." }
        @{ Name="Wireclub"; Category="Social"; Url="https://www.wireclub.com/users/{user}"; FoundMarker="Chat With"; NotFoundMarker="People - Wireclub" }
        @{ Name="Wishlistr"; Category="Marketplace"; Url="https://www.wishlistr.com/sign-up/?rs=checkUserName&rsargs[]={user}"; FoundMarker="+:var res = `""; NotFoundMarker="+:var res = parseInt(0);" }
        @{ Name="wordnik"; Category="Gaming"; Url="https://www.wordnik.com/users/{user}"; FoundMarker="Welcome,"; NotFoundMarker="Wordnik: Page Not Found" }
        @{ Name="WordPress.com (Deleted)"; Category="Creative"; Url="https://public-api.wordpress.com/rest/v1.1/sites/{user}.wordpress.com"; FoundMarker="`"message`":`"API calls to this endpoint have been disabled.`""; NotFoundMarker="`"error`":`"unknown_blog`"" }
        @{ Name="WordPress.org (Forums)"; Category="Creative"; Url="https://login.wordpress.org/wp-json/wporg/v1/username-available/{user}"; FoundMarker="`"error`":`"That username is already in use."; NotFoundMarker="`"available`":true" }
        @{ Name="Wowhead"; Category="Gaming"; Url="https://www.wowhead.com/user={user}"; FoundMarker="Profile - Wowhead"; NotFoundMarker="Error - Wowhead" }
        @{ Name="Wykop"; Category="Social"; Url="https://wykop.pl/ludzie/{user}"; FoundMarker="<title>Profil:"; NotFoundMarker="Wystąpił błąd 404." }
        @{ Name="X"; Category="Social"; Url="https://api.x.com/i/users/username_available.json?username={user}"; FoundMarker="`"reason`":`"taken`""; NotFoundMarker="`"reason`":`"available`"" }
        @{ Name="Xakep.ru"; Category="Tech"; Url="https://xakep.ru/author/{user}/"; FoundMarker="authorBlock-avatar"; NotFoundMarker="Страница не найдена" }
        @{ Name="Xanga"; Category="Creative"; Url="https://{user}.xanga.com/"; FoundMarker="class=`"module module-weblog`""; NotFoundMarker="" }
        @{ Name="Xbox Gamertag"; Category="Gaming"; Url="https://www.xboxgamertag.com/search/{user}"; FoundMarker="Games Played"; NotFoundMarker="Gamertag doesn't exist" }
        @{ Name="xHamster"; Category="Xx nsfw xx"; Url="https://xhamster.com/users/{user}"; FoundMarker="and bio on xHamster"; NotFoundMarker="User not found</title>" }
        @{ Name="XNXX"; Category="Xx nsfw xx"; Url="https://www.xnxx.com/mobile/profile/{user}"; FoundMarker="<table id=`"profile`">"; NotFoundMarker="<title>Bad request" }
        @{ Name="XVideos"; Category="Xx nsfw xx"; Url="https://www.xvideos.com/profiles/{user}/feed/"; FoundMarker="`"result`":true"; NotFoundMarker="`"message`":`"Unknown user`"" }
        @{ Name="Yahoo! JAPAN Auction"; Category="Marketplace"; Url="https://auctions.yahoo.co.jp/follow/list/{user}"; FoundMarker="出品者"; NotFoundMarker="Yahoo! JAPAN IDが無効です。" }
        @{ Name="yapishu"; Category="Hobby"; Url="https://yapishu.net/user/{user}"; FoundMarker="for_profile"; NotFoundMarker="Not Found (#404)" }
        @{ Name="Yazawaj"; Category="Dating"; Url="https://www.yazawaj.com/profile/{user}"; FoundMarker="profile-description"; NotFoundMarker="<title>nodata" }
        @{ Name="YesWeHack"; Category="Tech"; Url="https://api.yeswehack.com/hunters/{user}"; FoundMarker="`"username`":"; NotFoundMarker="`"code`":404" }
        @{ Name="YouNow"; Category="Social"; Url="https://api.younow.com/php/api/broadcast/info/user={user}"; FoundMarker="`"userId`":"; NotFoundMarker="`"errorMsg`":`"No users found`"" }
        @{ Name="youpic"; Category="Hobby"; Url="https://youpic.com/photographer/{user}"; FoundMarker="<meta name=`"og:title`""; NotFoundMarker="<title>YouPic — Not Found</title>" }
        @{ Name="Zbiornik"; Category="Xx nsfw xx"; Url="https://mini.zbiornik.com/{user}"; FoundMarker="INFO"; NotFoundMarker="" }
        @{ Name="Zenn"; Category="Code"; Url="https://zenn.dev/{user}"; FoundMarker="<div class=`"UserHeader_profileMain__6Itxi`">"; NotFoundMarker="<div class=`"ErrorContent_status__2Ykoq`">404</div>" }
        @{ Name="Zepeto"; Category="Social"; Url="https://gw-napi.zepeto.io/profiles/{user}"; FoundMarker="zepetoId`":"; NotFoundMarker="errorCode`":" }
        @{ Name="zhihu"; Category="Social"; Url="https://api.zhihu.com/books/people/{user}/publications?offset=0&limit=5"; FoundMarker="`"is_start`": true"; NotFoundMarker="`"name`": `"NotFoundException`"" }
        @{ Name="Zillow"; Category="Marketplace"; Url="https://www.zillow.com/profile/{user}/"; FoundMarker="- Real Estate Agent"; NotFoundMarker="" }
        @{ Name="zmarsa.com"; Category="Xx nsfw xx"; Url="https://zmarsa.com/uzytkownik/{user}"; FoundMarker="Statystyki"; NotFoundMarker="<title>Error 404 - zMarsa.com<" }
        @{ Name="Znanija"; Category="Misc"; Url="https://znanija.com/graphql/ru?operationName=NickAvailability&query=query%20NickAvailability%28%24nick%3AString%21%29%7BnickAvailability%28nick%3A%24nick%29%7BisAvailable%7D%7D&variables=%7B%22nick%22%3A%22{user}%22%7D"; FoundMarker="`"isAvailable`":false"; NotFoundMarker="`"isAvailable`":true" }
        @{ Name="Zomato"; Category="Social"; Url="https://www.zomato.com/{user}/reviews"; FoundMarker="Activity</h4>"; NotFoundMarker="This is a 404 page and we think it's fairly clear" }
        @{ Name="zoomitir"; Category="Tech"; Url="https://www.zoomit.ir/user/{user}/"; FoundMarker=""; NotFoundMarker="<title>خطای ۴۰۴ - صفحه یافت نشد</title>" }
        @{ Name="Военное обозрение"; Category="Hobby"; Url="https://topwar.ru/user/{user}/"; FoundMarker="class=`"puser-info`""; NotFoundMarker="class=`"error-container`"" }
        @{ Name="Чатовка.net"; Category="Social"; Url="https://chatovka.net/search?user_nick=+{user}&user_sex_m=on&user_sex_f=on"; FoundMarker="href=`"/user/"; NotFoundMarker="По Вашему запросу люди не найдены." }
    )
    return @($raw | ForEach-Object { [pscustomobject]$_ })
}

function Test-SiteRowValidation {
    <#
    Pure validation logic over a site table: every entry must have a
    non-empty name, category, and URL containing a {user} (or ${user})
    placeholder; names must be unique. Returns an array of problem
    strings (empty = clean). Test-SiteTableValidation runs it over the
    built-in table and throws; the hygiene battery runs it over
    synthetic bad rows to prove the checks fire.
    #>
    param(
        [Parameter(Mandatory=$true)][array]$Sites
    )
    $problems = @()
    $seen = @{}
    foreach ($s in $Sites) {
        if ([string]::IsNullOrWhiteSpace($s.Name))     { $problems += "entry with empty name" }
        if ([string]::IsNullOrWhiteSpace($s.Category)) { $problems += "$($s.Name): empty category" }
        if ([string]::IsNullOrWhiteSpace($s.Url))      { $problems += "$($s.Name): empty URL" }
        elseif ($s.Url -notmatch '\{\$?user\}')        { $problems += "$($s.Name): URL lacks {user} placeholder" }
        if (-not [string]::IsNullOrWhiteSpace($s.Name)) {
            if ($seen.ContainsKey($s.Name)) { $problems += "duplicate site name: $($s.Name)" }
            else { $seen[$s.Name] = $true }
        }
    }
    return $problems
}

function Test-SiteTableValidation {
    <#
    Pre-flight validation of the site table: every entry must have a
    non-empty name, category, and URL containing a {user} (or ${user})
    placeholder; names must be unique. Returns a report object; throws
    on a hard defect so a scan never runs on a broken table.
    #>
    $sites = Get-SiteTable
    $problems = Test-SiteRowValidation -Sites $sites
    if ($problems.Count -gt 0) {
        throw ("Site table validation failed ({0} problems):`n- {1}" -f $problems.Count, ($problems -join "`n- "))
    }
    return [pscustomobject]@{
        Sites = $sites.Count
        Categories = @($sites | Select-Object -ExpandProperty Category -Unique).Count
    }
}

function Get-SiteCoverage {
    <#
    Reports the site-table coverage: total sites and per-category
    counts. Useful before a scan to see what a category filter covers.
    #>
    $sites = Get-SiteTable
    $byCat = @()
    foreach ($cat in ($sites | Select-Object -ExpandProperty Category -Unique | Sort-Object)) {
        $byCat += [pscustomobject]@{
            Category = $cat
            Sites    = @($sites | Where-Object { $_.Category -eq $cat }).Count
        }
    }
    return [pscustomobject]@{
        Total = $sites.Count
        ByCategory = $byCat
    }
}

function Test-LoginRedirectUrl {
    <#
    Pure predicate: does a redirect Location point at a login / sign-up /
    auth gate? A 3xx to a login page is a login wall, not evidence the
    account exists -- many sites bounce logged-out visitors to login even
    for REAL accounts (facebook.com/{user} is the classic), so it scores
    lower than an open redirect and is flagged as RedirectGated.
    The keyword must sit on a URL delimiter boundary so that e.g.
    ".../authors" or "author.example.com" never matches "auth".
    #>
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $rx = '(?i)(?:^|[/?#_.\-])(?:login|log-in|signin|sign-in|signup|sign-up|register|registration|auth|sso|session)(?:[/?#_.\-&=%]|$)'
    return ($Url -match $rx)
}

function Get-UsernameScore {
    <#
    Scores one site result 0-100. Negative scores mean "could not tell"
    (blocked / rate-limited / error) -- never a claim. The calibration
    probe (a guaranteed-nonexistent username on the same site) is the
    primary discriminator: a target that looks exactly like the site's
    own "not found" page scores near zero even on HTTP 200.
    #>
    param(
        [int]$TargetStatus,
        [long]$TargetLen,
        [int]$CalStatus,
        [long]$CalLen,
        [bool]$FoundMarkerHit,
        [bool]$NotFoundMarkerHit,
        [bool]$CalLimited = $false,
        [bool]$CalSkipped = $false,
        [string]$RedirectLocation = ""
    )
    if ($NotFoundMarkerHit) { return 0 }
    if ($TargetStatus -eq 404 -or $TargetStatus -eq 410) { return 0 }
    if ($TargetStatus -eq 403 -or $TargetStatus -eq 429) { return -1 }
    if ($TargetStatus -eq 301 -or $TargetStatus -eq 302 -or $TargetStatus -eq 307) {
        # a redirect to a login wall is non-discriminating: the site
        # hides the profile from logged-out visitors either way
        if (Test-LoginRedirectUrl -Url $RedirectLocation) { return 5 }
        return 20
    }
    if ($TargetStatus -ne 200) { return -2 }
    # HTTP 200: diverge from the site's own not-found baseline
    $score = 55
    if ($FoundMarkerHit) { $score += 30 }
    if ($CalLimited) {
        # calibration probe was rate-limited/blocked while the target
        # got 200: no baseline to compare against -- capped below
    }
    elseif ($CalStatus -eq 200 -and $CalLen -gt 0) {
        # site answers 200 even for bogus names (SPA soft-404s) --
        # only content divergence counts
        $div = [math]::Abs($TargetLen - $CalLen) / $CalLen
        if ($div -lt 0.03) { $score = 5 }
        elseif ($div -lt 0.15) { $score = 45 }
        else { $score = 70 }
    }
    elseif ($CalStatus -gt 0 -and $CalStatus -ne 200) {
        # bogus name did NOT get 200 -- target 200 is a real signal
        $score += 10
    }
    # No usable baseline at all (probe rate-limited/blocked OR failed
    # outright, e.g. DNS/TLS): the URL answered but existence is
    # unverified, so cap at medium. A deliberate -NoCalibration skip
    # keeps the legacy 55 path -- the operator chose to forgo the
    # baseline and owns that confidence.
    if (-not $CalSkipped -and ($CalLimited -or $CalStatus -lt 0) -and $score -gt 50) {
        $score = 50
    }
    if ($score -gt 100) { $score = 100 }
    return $score
}

function Get-ConfidenceLabel {
    param([int]$Score)
    if ($Score -lt 0)  { return "uncertain" }
    if ($Score -ge 70) { return "high" }
    if ($Score -ge 40) { return "medium" }
    if ($Score -ge 10) { return "weak" }
    return "none"
}

function Test-Username {
    <#
    .SYNOPSIS
    Enumerates a username across the site table with parallel HTTP
    checks and per-site calibration.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [string[]]$Categories = @(),
        [int]$MaxConcurrency = 10,
        [int]$TimeoutSec = 12,
        [int]$RetryLimit = 1,
        [int]$RetryDelaySec = 3,
        [switch]$NoCalibration
    )
    if ($Username -notmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw "Username '$Username' is not a safe handle (letters, digits, . _ - only, max 64 chars)."
    }
    # guardrails: a scan must never be told to do something silly
    if ($MaxConcurrency -lt 1) { $MaxConcurrency = 1 }
    if ($MaxConcurrency -gt 64) { $MaxConcurrency = 64 }
    if ($TimeoutSec -lt 5) { $TimeoutSec = 5 }
    if ($TimeoutSec -gt 120) { $TimeoutSec = 120 }
    if ($RetryLimit -lt 0) { $RetryLimit = 0 }
    if ($RetryLimit -gt 3) { $RetryLimit = 3 }
    Import-CoherenceCore
    Import-VaultModule
    $tableReport = Test-SiteTableValidation
    Write-Host ("[*] people-track: site table validated ({0} sites, {1} categories)" -f $tableReport.Sites, $tableReport.Categories)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch { }

    $sites = Get-SiteTable
    if ($Categories.Count -gt 0) {
        $sites = @($sites | Where-Object { $Categories -contains $_.Category })
    }
    if ($sites.Count -eq 0) { throw "No sites matched the category filter." }

    # calibration handle: guaranteed nonexistent, same shape every run
    $invalidUser = "bbx" + (-join ((48..57) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }))
    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
    $doCal = -not $NoCalibration.IsPresent

    Write-Host "[*] people-track: checking '$Username' on $($sites.Count) sites (calibration: $(if ($doCal) { 'on' } else { 'off' }), concurrency $MaxConcurrency, retries $RetryLimit)"

    $checkScript = @'
param($Site, $Username, $TimeoutSec, $DoCal, $InvalidUser, $UserAgent, $RetryLimit, $RetryDelaySec)
$out = [ordered]@{
    Name = $Site.Name; Category = $Site.Category; Url = ""
    TargetStatus = -9; TargetLen = 0; CalStatus = -9; CalLen = 0
    FoundMarkerHit = $false; NotFoundMarkerHit = $false
    BodyPreview = ""; Error = ""; ErrorClass = ""; Retried = $false
    RedirectLocation = ""
}
function Get-ErrorClass([string]$msg) {
    if ($msg -match 'NameResolutionFailure|no such host|DNS') { return "dns-failure" }
    if ($msg -match 'timed out|timeout|Task was canceled|operation timed out') { return "timeout" }
    if ($msg -match 'SSL|TLS|certificate|authentication failed') { return "tls" }
    if ($msg -match 'connection refused|No connection could be made|actively refused') { return "connection-refused" }
    if ($msg -match '429|Too Many Requests') { return "rate-limited" }
    if ($msg -match '403|Forbidden') { return "forbidden" }
    if ($msg -match 'proxy') { return "proxy" }
    return "unknown"
}
try {
    $targetUrl = $Site.Url -replace '\{\$?user\}', $Username
    $out.Url = $targetUrl
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $null = $client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", $UserAgent)
    $attempt = 0
    $done = $false
    while (-not $done) {
        $attempt++
        try {
            $resp = $client.GetAsync($targetUrl).Result
            $out.TargetStatus = [int]$resp.StatusCode
            # a successful response supersedes any earlier transient error:
            # keep Retried=true as the audit trail, but clear the error
            # fields so the scan's error rollup doesn't count a site that
            # ultimately answered
            $out.Error = ""
            $out.ErrorClass = ""
            if ($out.TargetStatus -eq 429 -and $attempt -le $RetryLimit) {
                # 429 is the server TELLING us how to behave: honor Retry-After
                # (capped at 30s) and retry inside the retry budget instead of
                # recording a failed check.
                $wait = $RetryDelaySec
                try {
                    if ($resp.Headers.Contains("Retry-After")) {
                        $ra = @($resp.Headers.GetValues("Retry-After"))[0]
                        $secs = 0
                        if ([int]::TryParse($ra, [ref]$secs)) {
                            if ($secs -lt 1) { $secs = 1 }
                            if ($secs -gt 30) { $secs = 30 }
                            $wait = $secs
                        }
                    }
                } catch { }
                $out.Retried = $true
                $out.Error = "HTTP 429 rate-limited; honored Retry-After, waited ${wait}s"
                $out.ErrorClass = "rate-limited"
                Start-Sleep -Seconds $wait
                continue
            }
            $bytes = $resp.Content.ReadAsByteArrayAsync().Result
            if ($bytes -ne $null) {
                $out.TargetLen = $bytes.Length
                $n = [Math]::Min($bytes.Length, 65536)
                $out.BodyPreview = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $n)
            }
            if ($out.TargetStatus -ge 300 -and $out.TargetStatus -lt 400) {
                try {
                    $loc = $resp.Headers.Location
                    if ($loc -ne $null) { $out.RedirectLocation = $loc.ToString() }
                } catch { }
            }
            $done = $true
        } catch {
            $msg = $_.Exception.Message
            if ($_.Exception.InnerException -ne $null) { $msg += " | " + $_.Exception.InnerException.Message }
            $out.Error = $msg
            $out.ErrorClass = Get-ErrorClass $msg
            # retry once on transient failures: 429/503 or raw timeouts
            $transient = ($out.ErrorClass -eq "rate-limited" -or $out.ErrorClass -eq "timeout" -or $msg -match '503|ServiceUnavailable')
            if ($transient -and $attempt -le $RetryLimit) {
                $out.Retried = $true
                Start-Sleep -Seconds $RetryDelaySec
            } else { $done = $true }
        }
    }
    if ($DoCal) {
        try {
            $calUrl = $Site.Url -replace '\{\$?user\}', $InvalidUser
            $resp2 = $client.GetAsync($calUrl).Result
            $out.CalStatus = [int]$resp2.StatusCode
            $b2 = $resp2.Content.ReadAsByteArrayAsync().Result
            if ($b2 -ne $null) { $out.CalLen = $b2.Length }
        } catch {
            $cmsg = $_.Exception.Message
            if ($_.Exception.InnerException -ne $null) { $cmsg += " | " + $_.Exception.InnerException.Message }
            $cclass = Get-ErrorClass $cmsg
            if ($cclass -eq "rate-limited" -or $cclass -eq "forbidden") { $out.CalStatus = -10 } # calibration limited
            else { $out.CalStatus = -9 }
        }
    }
    $client.Dispose()
} catch {
    $out.Error = $_.Exception.Message
}
[pscustomobject]$out
'@

    $pool = $null
    $pend = @()
    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrency)
        $pool.Open()
        foreach ($site in $sites) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($checkScript)
            [void]$ps.AddParameter("Site", $site)
            [void]$ps.AddParameter("Username", $Username)
            [void]$ps.AddParameter("TimeoutSec", $TimeoutSec)
            [void]$ps.AddParameter("DoCal", $doCal)
            [void]$ps.AddParameter("InvalidUser", $invalidUser)
            [void]$ps.AddParameter("UserAgent", $ua)
            [void]$ps.AddParameter("RetryLimit", $RetryLimit)
            [void]$ps.AddParameter("RetryDelaySec", $RetryDelaySec)
            $handle = $ps.BeginInvoke()
            $pend += [pscustomobject]@{ PS = $ps; Handle = $handle; Site = $site }
        }
        Write-Host "[*] dispatched $($pend.Count) checks, collecting..."
        $results = @()
        $waitMs = ($TimeoutSec + 45) * 1000
        foreach ($p in $pend) {
            $raw = $null
            try {
                $done = $p.Handle.AsyncWaitHandle.WaitOne($waitMs)
                if ($done) {
                    $coll = $p.PS.EndInvoke($p.Handle)
                    if ($coll -ne $null -and $coll.Count -gt 0) { $raw = $coll[0] }
                } else {
                    Write-Host "[!] timeout waiting for $($p.Site.Name)"
                }
            } catch {
                Write-Host "[!] $($p.Site.Name): $($_.Exception.Message)"
            } finally {
                $p.PS.Dispose()
            }
            if ($raw -eq $null) {
                $raw = [pscustomobject]@{
                    Name = $p.Site.Name; Category = $p.Site.Category
                    Url = ($p.Site.Url -replace '\{\$?user\}', $Username)
                    TargetStatus = -2; TargetLen = 0; CalStatus = -9; CalLen = 0
                    FoundMarkerHit = $false; NotFoundMarkerHit = $false
                    BodyPreview = ""; Error = "runspace produced no result"
                    ErrorClass = "runspace"; Retried = $false
                    RedirectLocation = ""
                }
            }
            # content-match markers (bonus evidence, never the sole signal)
            $fm = $false; $nm = $false
            try {
                if (-not [string]::IsNullOrEmpty($p.Site.FoundMarker) -and
                    $raw.BodyPreview.IndexOf($p.Site.FoundMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $fm = $true }
                if (-not [string]::IsNullOrEmpty($p.Site.NotFoundMarker) -and
                    $raw.BodyPreview.IndexOf($p.Site.NotFoundMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $nm = $true }
            } catch { }
            $score = Get-UsernameScore -TargetStatus $raw.TargetStatus -TargetLen $raw.TargetLen `
                -CalStatus $raw.CalStatus -CalLen $raw.CalLen `
                -FoundMarkerHit $fm -NotFoundMarkerHit $nm `
                -CalLimited ($raw.CalStatus -eq -10) `
                -CalSkipped (-not $doCal) `
                -RedirectLocation $raw.RedirectLocation
            $gated = ($raw.TargetStatus -ge 300 -and $raw.TargetStatus -lt 400 -and `
                (Test-LoginRedirectUrl -Url $raw.RedirectLocation))
            $results += [pscustomobject]@{
                Site       = $raw.Name
                Category   = $raw.Category
                Url        = $raw.Url
                Status     = $raw.TargetStatus
                CalStatus  = $raw.CalStatus
                Score      = $score
                Confidence = Get-ConfidenceLabel -Score $score
                Error      = $raw.Error
                ErrorClass = $raw.ErrorClass
                Retried    = [bool]$raw.Retried
                RedirectLocation = $raw.RedirectLocation
                RedirectGated = $gated
            }
        }
    } finally {
        if ($pool -ne $null) { $pool.Close(); $pool.Dispose() }
    }

    $high = @($results | Where-Object { $_.Confidence -eq "high" }).Count
    $retried = @($results | Where-Object { $_.Retried }).Count
    $gated = @($results | Where-Object { $_.RedirectGated -eq $true }).Count
    $errClasses = @($results | Where-Object { -not [string]::IsNullOrEmpty($_.ErrorClass) } |
        Group-Object ErrorClass | ForEach-Object { "$($_.Name)x$($_.Count)" })
    Write-Host ("[*] done: {0} high-confidence hits out of {1} sites checked (retried: {2}, login-gated: {3}{4})" -f `
        $high, $results.Count, $retried, $gated, `
        $(if ($errClasses.Count -gt 0) { '; errors: ' + ($errClasses -join ', ') } else { '' }))
    New-PeopleLog -Action "scan" -Username $Username -Data @{
        sites     = $results.Count
        high      = $high
        medium    = @($results | Where-Object { $_.Confidence -eq "medium" }).Count
        weak      = @($results | Where-Object { $_.Confidence -eq "weak" }).Count
        uncertain = @($results | Where-Object { $_.Confidence -eq "uncertain" }).Count
    }
    return $results
}

function Get-Dossier {
    <#
    Builds the scored dossier from Test-Username results: counts per
    confidence band, exposure score, top hits, and -- when the
    coherence core is loaded -- a verifiable receipt over the
    high-confidence evidence items.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][array]$Results,
        $Breaches = $null
    )
    Import-CoherenceCore
    $total = $Results.Count
    $high   = @($Results | Where-Object { $_.Confidence -eq "high" })
    $medium = @($Results | Where-Object { $_.Confidence -eq "medium" })
    $weak   = @($Results | Where-Object { $_.Confidence -eq "weak" })
    $none   = @($Results | Where-Object { $_.Confidence -eq "none" })
    $unc    = @($Results | Where-Object { $_.Confidence -eq "uncertain" })

    $exposure = 0
    if ($total -gt 0) {
        $exposure = [math]::Round(100 * ($high.Count + 0.6 * $medium.Count + 0.25 * $weak.Count) / $total, 1)
    }
    # per-category exposure breakdown: shows WHERE the footprint is
    # heaviest so the remediation plan attacks the worst category first
    $catExp = @()
    foreach ($cat in (@($Results | Select-Object -ExpandProperty Category -Unique) | Sort-Object)) {
        $inCat = @($Results | Where-Object { $_.Category -eq $cat })
        $catExp += [pscustomobject]@{
            Category  = $cat
            Sites     = $inCat.Count
            High      = @($inCat | Where-Object { $_.Confidence -eq "high" }).Count
            Medium    = @($inCat | Where-Object { $_.Confidence -eq "medium" }).Count
            Weak      = @($inCat | Where-Object { $_.Confidence -eq "weak" }).Count
            Uncertain = @($inCat | Where-Object { $_.Confidence -eq "uncertain" }).Count
        }
    }
    $verdict = "no accounts detected"
    if ($exposure -ge 50) { $verdict = "wide exposure" }
    elseif ($exposure -ge 20) { $verdict = "moderate exposure" }
    elseif ($exposure -gt 0) { $verdict = "limited exposure" }

    $receipt = $null
    if ($script:CoherenceLoaded) {
        try {
            $items = @()
            $n = 0
            foreach ($h in $high) {
                $n++
                $items += New-EvidenceItem -id ("pt-{0}-{1}" -f $Username, $n) -type "username-hit" `
                    -source ("people-track:" + $h.Site) `
                    -data @{ site = $h.Site; url = $h.Url; score = $h.Score; confidence = $h.Confidence }
            }
            $hashes = @($items | ForEach-Object { $_.sha256 })
            $receipt = New-Receipt -conclusion ("exposure-scan:" + $Username) -evidenceHashes $hashes
        } catch {
            Write-Host "[!] coherence receipt failed: $($_.Exception.Message)"
        }
    }

    $dossier = [pscustomobject]@{
        Username     = $Username
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        SitesChecked = $total
        Counts       = [pscustomobject]@{
            high = $high.Count; medium = $medium.Count; weak = $weak.Count
            none = $none.Count; uncertain = $unc.Count
        }
        ExposureScore = $exposure
        CategoryExposure = $catExp
        Verdict       = $verdict
        HighHits      = @($high | ForEach-Object { [pscustomobject]@{ Site = $_.Site; Category = $_.Category; Url = $_.Url; Score = $_.Score; RedirectGated = [bool]$_.RedirectGated } })
        MediumHits    = @($medium | ForEach-Object { [pscustomobject]@{ Site = $_.Site; Category = $_.Category; Url = $_.Url; Score = $_.Score; RedirectGated = [bool]$_.RedirectGated } })
        WeakHits      = @($weak | ForEach-Object { [pscustomobject]@{ Site = $_.Site; Category = $_.Category; Url = $_.Url; Score = $_.Score; RedirectGated = [bool]$_.RedirectGated } })
        Uncertain     = @($unc | ForEach-Object { [pscustomobject]@{ Site = $_.Site; Category = $_.Category; Url = $_.Url; RedirectLocation = $_.RedirectLocation; Note = $_.Error; ErrorClass = $_.ErrorClass } })
        Breaches      = $Breaches
        Receipt       = $receipt
    }
    Write-Host ("[*] dossier for '{0}': {1} (exposure {2}%)" -f $Username, $verdict, $exposure)
    New-PeopleLog -Action "dossier" -Username $Username -Data @{
        verdict = $verdict; exposure = $exposure; high = $high.Count; sites = $total
    }
    return $dossier
}

function Get-HibpBreach {
    <#
    HIBP v3 breachedaccount check. The API key is read from a file you
    supply (-KeyFile); it is never hardcoded, never echoed. Without a
    key the function warns and returns $null -- the scan proceeds.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [string]$KeyFile = ""
    )
    if ($Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Not a valid email address: $Email" }
    if ([string]::IsNullOrWhiteSpace($KeyFile) -or -not (Test-Path $KeyFile)) {
        Write-Host "[!] no HIBP key file supplied -- skipping breach check (get a free key at haveibeenpwned.com/API/v3, save it to a file)"
        return $null
    }
    $key = (Get-Content -Path $KeyFile -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($key)) { Write-Host "[!] key file is empty -- skipping"; return $null }
    $enc = [uri]::EscapeDataString($Email)
    $url = "https://haveibeenpwned.com/api/v3/breachedaccount/$enc`?truncateResponse=false"
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch { }
        $headers = @{ "hibp-api-key" = $key; "User-Agent" = "Falsum-PeopleTrack" }
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 20
        $names = @($resp | ForEach-Object { $_.Name })
        Write-Host ("[*] HIBP: {0} breach(es) for {1}: {2}" -f $names.Count, $Email, ($names -join ", "))
        return $resp
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "404") {
            Write-Host "[*] HIBP: no breaches found for $Email"
            return @()
        }
        Write-Host "[!] HIBP request failed: $msg"
        return $null
    }
}

function Get-RemediationTable {
    <#
    The fix side of the law: per-category hardening steps for every
    account the scan finds. Concrete settings to change, not advice
    to "be careful".
    #>
    return @{
        "Code" = @(
            "Remove real name and personal email from git commit history (git log shows author emails); rewrite history or rotate the exposed address",
            "Sweep public repos for committed secrets, tokens, and config files; rotate anything that was ever public",
            "Enable 2FA on the account; generate a fresh SSH key and delete old ones",
            "Delete unused accounts so the handle stops resolving"
        )
        "Social" = @(
            "Set the profile to private / friends-only",
            "Disable search-engine indexing of the profile (in the site's privacy settings)",
            "Remove phone number, birthday, hometown, and employer from public fields",
            "Audit old posts and photos; untag yourself where you can",
            "Review connected third-party apps and revoke what you do not use"
        )
        "Video" = @(
            "Set the channel to private where the platform allows it",
            "Strip location metadata from uploads before posting",
            "Disable embedding / downloads if you do not need them",
            "Review comments and video descriptions for doxxing details"
        )
        "Audio" = @(
            "Remove real name from the public profile",
            "Check track descriptions and artwork for personal details"
        )
        "Gaming" = @(
            "Set the profile to private; hide real name, inventory, and friends list",
            "Disable public profile comments if the platform allows it",
            "Unlink the account from public leaderboards where possible"
        )
        "Writing" = @(
            "Remove personal bio details (email, location, employer) from the public profile",
            "Delete or privatize old posts that contain PII",
            "Check that the account's contact email is not exposed in the page source"
        )
        "Design" = @(
            "Remove real name and location if you do not need them for business",
            "Audit portfolio pieces for client or personal PII in descriptions"
        )
        "Marketplace" = @(
            "Remove home address and phone from public listings; use a PO box or relay",
            "Delete old sold listings that show personal details",
            "Use a dedicated email for selling, not your primary one"
        )
        "Finance" = @(
            "Never publish donation/support links tied to your real identity unless you mean to",
            "Check the page for exposed real name, bank details, or payout emails"
        )
        "Professional" = @(
            "Audit the public bio; replace phone/email with a contact form or dedicated address",
            "Review old answers and posts for employer or project leaks"
        )
        "Media" = @(
            "Set the profile to private",
            "Remove location data from public uploads and reviews"
        )
        "Misc" = @(
            "Audit the account for exposed PII; enable 2FA; delete the account if unused"
        )
    }
}

function New-RemediationPlan {
    <#
    Turns a dossier into an actionable markdown checklist: per-hit
    priorities (P1 high, P2 medium, P3 weak) with the exact hardening
    steps, plus the global cleanup sequence. This is the fix the
    detection ships with.
    #>
    param(
        [Parameter(Mandatory=$true)]$Dossier,
        [Parameter(Mandatory=$true)][string]$OutputPath
    )
    $table = Get-RemediationTable
    $lines = @()
    $lines += "# Exposure Remediation Plan -- $($Dossier.Username)"
    $lines += ""
    $lines += "Generated (UTC): $($Dossier.TimestampUtc)"
    $lines += "Exposure verdict: $($Dossier.Verdict) (score $($Dossier.ExposureScore)%)"
    $lines += ""
    $lines += "## Per-account actions (highest priority first)"
    $lines += ""
    $bands = @(
        @{ Hits = $Dossier.HighHits;   Prio = "P1"; Band = "high" }
        @{ Hits = $Dossier.MediumHits; Prio = "P2"; Band = "medium" }
        @{ Hits = $Dossier.WeakHits;   Prio = "P3"; Band = "weak" }
    )
    foreach ($b in $bands) {
        foreach ($h in $b.Hits) {
            $lines += "### [$($b.Prio)] $($h.Site) ($($h.Category), confidence $($b.Band), score $($h.Score))"
            $lines += "- Profile URL: $($h.Url)"
            $steps = $table[$h.Category]
            if ($steps -eq $null) { $steps = $table["Misc"] }
            foreach ($s in $steps) { $lines += "- [ ] $s" }
            $lines += ""
        }
    }
    if ($Dossier.Uncertain.Count -gt 0) {
        $lines += "## Needs a second look (blocked or rate-limited during scan)"
        $lines += ""
        foreach ($u in $Dossier.Uncertain) {
            $lines += "- [ ] Re-check manually: $($u.Site) -- $($u.Url) (scan note: $($u.Note))"
        }
        $lines += ""
    }
    if ($Dossier.Breaches -ne $null -and $Dossier.Breaches.Count -gt 0) {
        $lines += "## Breached email accounts -- rotate now"
        $lines += ""
        foreach ($br in $Dossier.Breaches) {
            $lines += "- [ ] $($br.Name): change the password, enable 2FA, check for reused passwords"
        }
        $lines += ""
    }
    $lines += "## Global cleanup sequence"
    $lines += ""
    $lines += "- [ ] 1. Stop reusing one handle everywhere -- one handle is one searchable identity"
    $lines += "- [ ] 2. Breach check: run module 08 (Falsum-BreachClean) on every email tied to this handle"
    $lines += "- [ ] 3. Data brokers: run module 09 (Falsum-BrokerEradicator) -- brokers relist, schedule the monthly re-fire"
    $lines += "- [ ] 4. Rotate passwords on every account found above; unique password per account"
    $lines += "- [ ] 5. Enable 2FA on every account that offers it"
    $lines += "- [ ] 6. Re-run this scan in 30 days and diff the dossiers with Compare-Dossier to verify the cleanup worked"
    $lines += "- [ ] 7. Check handle variants with Get-UsernameVariants and scan each one -- attackers find gregg2 when you only hide gregg"
    $lines += ""
    $text = $lines -join "`r`n"
    $dir = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $text, [System.Text.Encoding]::UTF8)
    Write-Host "[*] remediation plan written: $OutputPath"
    New-PeopleLog -Action "remediation-plan" -Username $Dossier.Username -Data @{
        path = $OutputPath; hits = ($Dossier.HighHits.Count + $Dossier.MediumHits.Count + $Dossier.WeakHits.Count)
    }
    return $OutputPath
}

function Format-DossierHitLine {
    <#
    One hit line for the text dossier: score, site, category, URL, and a
    "(login-gated)" suffix when the score came from a login-wall
    redirect -- the reader must know that hit is unverified by design.
    #>
    param(
        [Parameter(Mandatory=$true)]$Hit
    )
    $s = ("  [{0}] {1} ({2}) {3}" -f $Hit.Score, $Hit.Site, $Hit.Category, $Hit.Url)
    if ($Hit.RedirectGated -eq $true) { $s += " (login-gated)" }
    return $s
}

function Export-Dossier {
    <#
    Writes the dossier as JSON + human-readable text, SHA-256-hashes
    both, writes the remediation plan, and vault-logs the export.
    Returns the output paths.
    #>
    param(
        [Parameter(Mandatory=$true)]$Dossier,
        [Parameter(Mandatory=$true)][string]$OutputDir
    )
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $base = Join-Path $OutputDir ("{0}-{1}" -f $Dossier.Username, $stamp)
    $jsonPath = "$base-dossier.json"
    $txtPath  = "$base-dossier.txt"
    $mdPath   = "$base-remediation.md"

    try {
        $Dossier | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
        $tl = @()
        $tl += "USERNAME DOSSIER: $($Dossier.Username)"
        $tl += "Generated (UTC): $($Dossier.TimestampUtc)"
        $tl += "Verdict: $($Dossier.Verdict) | Exposure score: $($Dossier.ExposureScore)%"
        $tl += "Sites checked: $($Dossier.SitesChecked) | high=$($Dossier.Counts.high) medium=$($Dossier.Counts.medium) weak=$($Dossier.Counts.weak) none=$($Dossier.Counts.none) uncertain=$($Dossier.Counts.uncertain)"
        $tl += ""
        $tl += "== EXPOSURE BY CATEGORY =="
        foreach ($c in $Dossier.CategoryExposure) {
            $tl += ("  {0}: {1} sites | high={2} medium={3} weak={4} uncertain={5}" -f $c.Category, $c.Sites, $c.High, $c.Medium, $c.Weak, $c.Uncertain)
        }
        $tl += ""
        $tl += "== HIGH CONFIDENCE =="
        foreach ($h in $Dossier.HighHits) { $tl += (Format-DossierHitLine -Hit $h) }
        $tl += "== MEDIUM CONFIDENCE =="
        foreach ($h in $Dossier.MediumHits) { $tl += (Format-DossierHitLine -Hit $h) }
        $tl += "== WEAK =="
        foreach ($h in $Dossier.WeakHits) { $tl += (Format-DossierHitLine -Hit $h) }
        if ($Dossier.Uncertain.Count -gt 0) {
            $tl += "== UNCERTAIN (re-check manually) =="
            foreach ($u in $Dossier.Uncertain) {
                $redir = ""
                if (-not [string]::IsNullOrEmpty($u.RedirectLocation)) { $redir = " -> " + $u.RedirectLocation }
                $tl += ("  {0} ({1}) {2}{3}" -f $u.Site, $u.Category, $u.Url, $redir)
            }
        }
        $withClass = @($Dossier.Uncertain | Where-Object { -not [string]::IsNullOrEmpty($_.ErrorClass) })
        if ($withClass.Count -gt 0) {
            $tl += "== UNCERTAIN error classes =="
            foreach ($u in ($withClass | Group-Object ErrorClass | Sort-Object Count -Descending)) {
                $tl += ("  {0}: {1} ({2})" -f $u.Name, $u.Count, (($u.Group | ForEach-Object { $_.Site }) -join ", "))
            }
        }
        if ($Dossier.Breaches -ne $null) {
            $tl += "== BREACHES =="
            if ($Dossier.Breaches.Count -eq 0) { $tl += "  none found" }
            else { foreach ($b in $Dossier.Breaches) { $tl += ("  {0} ({1})" -f $b.Name, $b.BreachDate) } }
        }
        if ($Dossier.Receipt -ne $null) { $tl += ("Receipt: " + $Dossier.Receipt.receipt) }
        ($tl -join "`r`n") | Set-Content -Path $txtPath -Encoding UTF8

        $h1 = (Get-FileHash -Path $jsonPath -Algorithm SHA256).Hash
        $h2 = (Get-FileHash -Path $txtPath -Algorithm SHA256).Hash
        Write-Host "[*] dossier exported: $jsonPath (SHA-256 $h1)"
        Write-Host "[*] dossier exported: $txtPath (SHA-256 $h2)"

        New-RemediationPlan -Dossier $Dossier -OutputPath $mdPath | Out-Null
        $h3 = (Get-FileHash -Path $mdPath -Algorithm SHA256).Hash
        Write-Host "[*] remediation plan hashed: SHA-256 $h3"

        New-PeopleLog -Action "export" -Username $Dossier.Username -Data @{
            json = $jsonPath; json_sha256 = $h1
            txt  = $txtPath;  txt_sha256  = $h2
            plan = $mdPath;   plan_sha256 = $h3
        }
        return [pscustomobject]@{ Json = $jsonPath; Text = $txtPath; Plan = $mdPath }
    } catch {
        Write-Host "[!] export failed: $($_.Exception.Message)"
        throw
    }
}

function Get-UsernameVariants {
    <#
    Generates common handle mutations of a username: case-folded,
    separator-stripped, suffixed (1/01/2/123/x/official/real/hq),
    prefixed (the/iam/real_/official_), and leetspeak. One handle is
    one searchable identity -- but people reuse handles WITH tweaks,
    and so do attackers looking for them. Every variant returned
    passes the safe-handle check, so it can be scanned directly.
    Pure function: no network, deterministic.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username
    )
    $variants = @()
    $u = $Username.ToLowerInvariant()
    if ($u -ne $Username) { $variants += $u }
    $stripped = $u -replace '[._-]', ''
    if ($stripped -ne $u -and $stripped.Length -ge 2) { $variants += $stripped }
    foreach ($s in @("1", "01", "2", "123", "x", "_", "_x", "official", "real", "hq")) {
        $variants += ($u + $s)
    }
    foreach ($p in @("the", "iam", "real_", "official_")) {
        $variants += ($p + $u)
    }
    $leet = $u.Replace('a','4').Replace('e','3').Replace('o','0').Replace('i','1').Replace('s','5')
    if ($leet -ne $u) { $variants += $leet }
    $seen = @{}
    $out = @()
    foreach ($v in $variants) {
        if ($v -match '^[A-Za-z0-9._-]{1,64}$' -and -not $seen.ContainsKey($v)) {
            $seen[$v] = $true
            $out += $v
        }
    }
    return @($out)
}

function Compare-Dossier {
    <#
    Diffs two exported dossier JSONs (from Export-Dossier): sites that
    APPEARED, DISAPPEARED, or moved confidence bands between scans, plus
    the exposure-score delta. This is the verification side of the
    remediation plan's "re-scan in 30 days" step: the cleanup either
    worked or it didn't, and this says which. Writes a text + JSON
    report, SHA-256-hashes both, and vault-logs the comparison.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$OldPath,
        [Parameter(Mandatory=$true)][string]$NewPath,
        [string]$OutputPath = ""
    )
    Import-VaultModule
    if (-not (Test-Path $OldPath)) { throw "Old dossier not found: $OldPath" }
    if (-not (Test-Path $NewPath)) { throw "New dossier not found: $NewPath" }
    $old = Get-Content -Path $OldPath -Raw | ConvertFrom-Json
    $new = Get-Content -Path $NewPath -Raw | ConvertFrom-Json
    if ($old.Username -ne $new.Username) {
        Write-Host ("[!] dossier usernames differ ('{0}' vs '{1}') -- diffing anyway, check you picked the right files" -f $old.Username, $new.Username)
    }

    $order = @{ "weak" = 0; "medium" = 1; "high" = 2 }
    $oldMap = @{}
    foreach ($b in @(@{ Prop = "HighHits"; Band = "high" }, @{ Prop = "MediumHits"; Band = "medium" }, @{ Prop = "WeakHits"; Band = "weak" })) {
        $hits = $old.($b.Prop)
        if ($hits -eq $null) { continue }
        foreach ($h in @($hits)) {
            $key = [string]$h.Site
            if (-not $oldMap.ContainsKey($key)) {
                $oldMap[$key] = [pscustomobject]@{ Site = $key; Category = [string]$h.Category; Url = [string]$h.Url; Band = $b.Band; Score = [int]$h.Score }
            }
        }
    }
    $newMap = @{}
    foreach ($b in @(@{ Prop = "HighHits"; Band = "high" }, @{ Prop = "MediumHits"; Band = "medium" }, @{ Prop = "WeakHits"; Band = "weak" })) {
        $hits = $new.($b.Prop)
        if ($hits -eq $null) { continue }
        foreach ($h in @($hits)) {
            $key = [string]$h.Site
            if (-not $newMap.ContainsKey($key)) {
                $newMap[$key] = [pscustomobject]@{ Site = $key; Category = [string]$h.Category; Url = [string]$h.Url; Band = $b.Band; Score = [int]$h.Score }
            }
        }
    }

    $appeared = @(); $removed = @(); $upgraded = @(); $downgraded = @()
    $steady = 0
    foreach ($site in $newMap.Keys) {
        $n = $newMap[$site]
        if (-not $oldMap.ContainsKey($site)) { $appeared += $n }
        else {
            $o = $oldMap[$site]
            if ($order[$n.Band] -gt $order[$o.Band]) {
                $upgraded += [pscustomobject]@{ Site = $site; From = $o.Band; To = $n.Band; OldScore = $o.Score; NewScore = $n.Score }
            }
            elseif ($order[$n.Band] -lt $order[$o.Band]) {
                $downgraded += [pscustomobject]@{ Site = $site; From = $o.Band; To = $n.Band; OldScore = $o.Score; NewScore = $n.Score }
            }
            else { $steady++ }
        }
    }
    foreach ($site in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($site)) { $removed += $oldMap[$site] }
    }

    $oldExp = [double]$old.ExposureScore
    $newExp = [double]$new.ExposureScore
    $delta = [math]::Round($newExp - $oldExp, 1)
    $verdictDelta = "unchanged"
    if ($delta -lt 0) { $verdictDelta = "improved" }
    elseif ($delta -gt 0) { $verdictDelta = "worsened" }

    $lines = @()
    $lines += "DOSSIER DIFF: $($new.Username)"
    $lines += "Old scan: $($old.TimestampUtc) | New scan: $($new.TimestampUtc)"
    $lines += "Exposure: $oldExp% -> $newExp% (delta ${delta}pp, $verdictDelta)"
    $lines += ""
    if ($appeared.Count -gt 0) {
        $lines += "== APPEARED (new accounts found, not seen in old scan) =="
        foreach ($a in ($appeared | Sort-Object Band, Site)) {
            $lines += ("  [{0}] {1} ({2}) score {3} -- {4}" -f $a.Band, $a.Site, $a.Category, $a.Score, $a.Url)
        }
        $lines += ""
    }
    if ($removed.Count -gt 0) {
        $lines += "== REMOVED (cleaned up or gone since old scan) =="
        foreach ($r in ($removed | Sort-Object Site)) {
            $lines += ("  [{0}] {1} ({2}) was score {3}" -f $r.Band, $r.Site, $r.Category, $r.Score)
        }
        $lines += ""
    }
    if ($upgraded.Count -gt 0) {
        $lines += "== CONFIDENCE UPGRADED (worse than before) =="
        foreach ($g in ($upgraded | Sort-Object Site)) {
            $lines += ("  {0}: {1} -> {2} (score {3} -> {4})" -f $g.Site, $g.From, $g.To, $g.OldScore, $g.NewScore)
        }
        $lines += ""
    }
    if ($downgraded.Count -gt 0) {
        $lines += "== CONFIDENCE DOWNGRADED (better than before) =="
        foreach ($d in ($downgraded | Sort-Object Site)) {
            $lines += ("  {0}: {1} -> {2} (score {3} -> {4})" -f $d.Site, $d.From, $d.To, $d.OldScore, $d.NewScore)
        }
        $lines += ""
    }
    $lines += "Unchanged hits: $steady"
    $lines += ""
    if ($appeared.Count -eq 0 -and $upgraded.Count -eq 0 -and $delta -le 0) {
        $lines += "VERDICT: cleanup held or improved -- no new exposure since the old scan."
    }
    else {
        $lines += "VERDICT: exposure grew or new accounts appeared -- run the remediation plan on the appeared/upgraded rows."
    }

    $diff = [pscustomobject]@{
        Username      = $new.Username
        OldScanUtc    = $old.TimestampUtc
        NewScanUtc    = $new.TimestampUtc
        OldExposure   = $oldExp
        NewExposure   = $newExp
        ExposureDelta = $delta
        VerdictDelta  = $verdictDelta
        Appeared      = @($appeared)
        Removed       = @($removed)
        Upgraded      = @($upgraded)
        Downgraded    = @($downgraded)
        SteadyHits    = $steady
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $dir = Split-Path -Parent $NewPath
        if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "." }
        $OutputPath = Join-Path $dir ("{0}-dossier-diff.txt" -f $new.Username)
    }
    $jsonOut = [System.IO.Path]::ChangeExtension($OutputPath, ".json")
    $dir2 = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrEmpty($dir2) -and -not (Test-Path $dir2)) {
        New-Item -ItemType Directory -Path $dir2 -Force | Out-Null
    }
    ($lines -join "`r`n") | Set-Content -Path $OutputPath -Encoding UTF8
    $diff | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonOut -Encoding UTF8
    $h1 = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash
    $h2 = (Get-FileHash -Path $jsonOut -Algorithm SHA256).Hash
    Write-Host "[*] dossier diff: $OutputPath (SHA-256 $h1)"
    Write-Host "[*] dossier diff json: $jsonOut (SHA-256 $h2)"
    New-PeopleLog -Action "dossier-diff" -Username $new.Username -Data @{
        old = $OldPath; new = $NewPath
        exposure_old = $oldExp; exposure_new = $newExp; delta = $delta
        appeared = $appeared.Count; removed = $removed.Count
        upgraded = $upgraded.Count; downgraded = $downgraded.Count
        txt = $OutputPath; txt_sha256 = $h1; json = $jsonOut; json_sha256 = $h2
    }
    return $diff
}

function Invoke-PeopleTrack {
    <#
    The whole pipeline in one call: scan -> optional HIBP breach check
    -> dossier -> export -> remediation plan. Prints a plain-language
    summary at the end.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [string]$Email = "",
        [Parameter(Mandatory=$true)][string]$OutputDir,
        [string]$HibpKeyFile = "",
        [string[]]$Categories = @(),
        [int]$MaxConcurrency = 10,
        [int]$TimeoutSec = 12,
        [int]$RetryLimit = 1,
        [switch]$NoCalibration,
        [string]$VaultPath = ""
    )
    if (-not [string]::IsNullOrWhiteSpace($VaultPath)) { $script:VaultPath = $VaultPath }
    Write-Host "=== people-track: $Username ==="
    $results = Test-Username -Username $Username -Categories $Categories -MaxConcurrency $MaxConcurrency `
        -TimeoutSec $TimeoutSec -RetryLimit $RetryLimit -NoCalibration:$NoCalibration
    $breaches = $null
    if (-not [string]::IsNullOrWhiteSpace($Email)) {
        $breaches = Get-HibpBreach -Email $Email -KeyFile $HibpKeyFile
    }
    $dossier = Get-Dossier -Username $Username -Results $results -Breaches $breaches
    $paths = Export-Dossier -Dossier $dossier -OutputDir $OutputDir
    Write-Host ""
    Write-Host "SUMMARY for '$Username': $($dossier.Verdict) -- exposure score $($dossier.ExposureScore)%"
    Write-Host "  High-confidence accounts: $($dossier.Counts.high) | Medium: $($dossier.Counts.medium) | Weak: $($dossier.Counts.weak)"
    if ($breaches -ne $null -and $breaches.Count -gt 0) {
        Write-Host "  Breaches on ${Email}: $($breaches.Count) -- rotate those passwords now"
    }
    Write-Host "  Remediation plan: $($paths.Plan)"
    Write-Host "  Dossier: $($paths.Text)"
    return $dossier
}

function Test-PeopleTrackHygiene {
    <#
    Offline self-test battery: scoring math, confidence bands, row
    validation, handle variants, and site-table sanity. Pure logic, no
    network. Returns $true when every check passes. Results are built
    from scriptblock OUTPUT (not child-scope variable writes), so a
    pass/fail can never silently report zero checks.
    #>
    $add = {
        param([string]$Name, [bool]$Passed, [string]$Detail)
        [pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = [string]$Detail }
    }
    $res = @()

    # ---- Get-UsernameScore ----
    $sc = @(
        @{ N = "score-404-is-none";          H = @{ TargetStatus=404; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 0 },
        @{ N = "score-notfound-marker-none"; H = @{ TargetStatus=200; TargetLen=900; CalStatus=200; CalLen=900;  FoundMarkerHit=$false; NotFoundMarkerHit=$true  }; E = 0 },
        @{ N = "score-403-uncertain";        H = @{ TargetStatus=403; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = -1 },
        @{ N = "score-429-uncertain";        H = @{ TargetStatus=429; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = -1 },
        @{ N = "score-500-error";            H = @{ TargetStatus=500; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = -2 },
        @{ N = "score-301-redirect";         H = @{ TargetStatus=301; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 20 },
        @{ N = "score-301-no-location";      H = @{ TargetStatus=301; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false; RedirectLocation="" }; E = 20 },
        @{ N = "score-302-login-gate";       H = @{ TargetStatus=302; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false; RedirectLocation="https://www.facebook.com/login/" }; E = 5 },
        @{ N = "score-302-login-query";      H = @{ TargetStatus=302; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false; RedirectLocation="/signin?next=/gregg2" }; E = 5 },
        @{ N = "score-302-sso-gate";         H = @{ TargetStatus=307; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false; RedirectLocation="https://sso.example.com/auth" }; E = 5 },
        @{ N = "score-301-open-redirect";    H = @{ TargetStatus=301; TargetLen=0;    CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false; RedirectLocation="https://example.com/users/gregg2" }; E = 20 },
        @{ N = "score-soft404-identical";    H = @{ TargetStatus=200; TargetLen=1000; CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 5 },
        @{ N = "score-soft404-near";         H = @{ TargetStatus=200; TargetLen=1100; CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 45 },
        @{ N = "score-soft404-divergent";    H = @{ TargetStatus=200; TargetLen=1500; CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 70 },
        @{ N = "score-soft404-boundary";     H = @{ TargetStatus=200; TargetLen=1030; CalStatus=200; CalLen=1000; FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 45 },
        @{ N = "score-cal-bogus-404";        H = @{ TargetStatus=200; TargetLen=1000; CalStatus=404; CalLen=500;  FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 65 },
        @{ N = "score-cal-limited-cap";      H = @{ TargetStatus=200; TargetLen=900;  CalStatus=-10; CalLen=0;   FoundMarkerHit=$false; NotFoundMarkerHit=$false; CalLimited=$true }; E = 50 },
        @{ N = "score-cal-failed-cap";       H = @{ TargetStatus=200; TargetLen=900;  CalStatus=-9;  CalLen=0;   FoundMarkerHit=$false; NotFoundMarkerHit=$false }; E = 50 },
        @{ N = "score-cal-skipped-kept";     H = @{ TargetStatus=200; TargetLen=900;  CalStatus=-9;  CalLen=0;   FoundMarkerHit=$false; NotFoundMarkerHit=$false; CalSkipped=$true }; E = 55 },
        @{ N = "score-marker-divergent";     H = @{ TargetStatus=200; TargetLen=1500; CalStatus=200; CalLen=1000; FoundMarkerHit=$true;  NotFoundMarkerHit=$false }; E = 70 },
        @{ N = "score-marker-cal404";        H = @{ TargetStatus=200; TargetLen=1000; CalStatus=404; CalLen=500;  FoundMarkerHit=$true;  NotFoundMarkerHit=$false }; E = 95 },
        @{ N = "score-calfailed-marker-cap"; H = @{ TargetStatus=200; TargetLen=900;  CalStatus=-9;  CalLen=0;   FoundMarkerHit=$true;  NotFoundMarkerHit=$false }; E = 50 }
    )
    foreach ($c in $sc) {
        $h = $c.H
        $got = Get-UsernameScore @h
        $res += & $add $c.N ($got -eq $c.E) ("expected $($c.E), got $got")
    }

    # ---- Get-ConfidenceLabel ----
    $cl = @(
        @{ N = "label-uncertain";  S = -1;  E = "uncertain" },
        @{ N = "label-none-0";     S = 0;   E = "none" },
        @{ N = "label-none-9";     S = 9;   E = "none" },
        @{ N = "label-weak-10";    S = 10;  E = "weak" },
        @{ N = "label-weak-39";    S = 39;  E = "weak" },
        @{ N = "label-medium-40";  S = 40;  E = "medium" },
        @{ N = "label-medium-69";  S = 69;  E = "medium" },
        @{ N = "label-high-70";    S = 70;  E = "high" },
        @{ N = "label-high-100";   S = 100; E = "high" }
    )
    foreach ($c in $cl) {
        $got = Get-ConfidenceLabel -Score $c.S
        $res += & $add $c.N ($got -eq $c.E) ("expected $($c.E), got $got")
    }

    # ---- Test-LoginRedirectUrl ----
    $lr = @(
        @{ N = "login-fb-login";      U = "https://www.facebook.com/login/";          E = $true },
        @{ N = "login-flow";          U = "https://x.com/i/flow/login";               E = $true },
        @{ N = "login-relative";      U = "/login";                                  E = $true },
        @{ N = "login-signin-query";  U = "/signin?next=/gregg2";                    E = $true },
        @{ N = "login-sso";           U = "https://sso.example.com/auth";            E = $true },
        @{ N = "login-signup";        U = "https://example.com/signup?ref=profile";  E = $true },
        @{ N = "login-register";      U = "https://example.com/user/register";       E = $true },
        @{ N = "login-authors-page";  U = "https://example.com/authors";             E = $false },
        @{ N = "login-author-host";   U = "https://author.example.com/x";            E = $false },
        @{ N = "login-profile-page";  U = "https://example.com/users/gregg2";        E = $false },
        @{ N = "login-empty";         U = "";                                        E = $false }
    )
    foreach ($c in $lr) {
        $got = Test-LoginRedirectUrl -Url $c.U
        $res += & $add $c.N ($got -eq $c.E) ("expected $($c.E), got $got")
    }

    # ---- Format-DossierHitLine ----
    $hl1 = Format-DossierHitLine -Hit ([pscustomobject]@{ Score=70; Site="GitHub"; Category="Code"; Url="https://github.com/gregg2"; RedirectGated=$false })
    $res += & $add "hitline-plain" ($hl1 -eq "  [70] GitHub (Code) https://github.com/gregg2") $hl1
    $hl2 = Format-DossierHitLine -Hit ([pscustomobject]@{ Score=5; Site="Facebook"; Category="Social"; Url="https://www.facebook.com/gregg2"; RedirectGated=$true })
    $res += & $add "hitline-gated" ($hl2 -eq "  [5] Facebook (Social) https://www.facebook.com/gregg2 (login-gated)") $hl2

    # ---- Test-SiteRowValidation on synthetic bad rows ----
    $cleanProbs = @(Test-SiteRowValidation -Sites (Get-SiteTable))
    $res += & $add "rows-builtin-table-clean" ($cleanProbs.Count -eq 0) ("problems=$($cleanProbs.Count)")
    $mk = { param($n,$c,$u) [pscustomobject]@{ Name=$n; Category=$c; Url=$u } }
    $dup = @(Test-SiteRowValidation -Sites @((& $mk "GitHub" "Code" "https://github.com/{user}"), (& $mk "GitHub" "Code" "https://github.com/{user}")))
    $res += & $add "rows-duplicate-fires" (@($dup | Where-Object { $_ -match "duplicate" }).Count -gt 0) ($dup -join "; ")
    $noph = @(Test-SiteRowValidation -Sites @((& $mk "NoPH" "Code" "https://example.com/")))
    $res += & $add "rows-noplaceholder-fires" (@($noph | Where-Object { $_ -match "lacks" }).Count -gt 0) ($noph -join "; ")
    $noname = @(Test-SiteRowValidation -Sites @((& $mk "" "Code" "https://example.com/{user}")))
    $res += & $add "rows-emptyname-fires" (@($noname | Where-Object { $_ -match "empty name" }).Count -gt 0) ($noname -join "; ")
    $nourl = @(Test-SiteRowValidation -Sites @((& $mk "NoURL" "Code" "")))
    $res += & $add "rows-emptyurl-fires" (@($nourl | Where-Object { $_ -match "empty URL" }).Count -gt 0) ($nourl -join "; ")

    # ---- Get-UsernameVariants ----
    $v1 = Get-UsernameVariants -Username "gregg2"
    $v2 = Get-UsernameVariants -Username "gregg2"
    $res += & $add "variants-deterministic" (($v1 -join ",") -eq ($v2 -join ",")) "two calls differed"
    $badVar = @($v1 | Where-Object { $_ -notmatch '^[A-Za-z0-9._-]{1,64}$' })
    $res += & $add "variants-safe-chars" ($badVar.Count -eq 0) ("bad: " + ($badVar -join ","))
    $res += & $add "variants-suffix" ($v1 -contains "gregg21") "missing gregg21"
    $res += & $add "variants-prefix" ($v1 -contains "thegregg2") "missing thegregg2"
    $res += & $add "variants-unique" ($v1.Count -eq (@($v1 | Select-Object -Unique).Count)) "duplicates present"

    # ---- site table sanity ----
    $sites = Get-SiteTable
    $res += & $add "table-count" ($sites.Count -ge 200) ("count=$($sites.Count)")
    $res += & $add "table-names-unique" ($sites.Count -eq (@($sites | Select-Object -ExpandProperty Name -Unique).Count)) "duplicate names"
    $noPH = @($sites | Where-Object { $_.Url -notmatch '\{\$?user\}' })
    $res += & $add "table-all-placeholder" ($noPH.Count -eq 0) ("missing: " + ($noPH.Name -join ","))

    $fails = @($res | Where-Object { -not $_.Passed })
    Write-Host ("[*] people-track hygiene: {0}/{1} checks passed" -f ($res.Count - $fails.Count), $res.Count)
    foreach ($f in $fails) {
        Write-Host ("    FAIL: {0} ({1})" -f $f.Name, $f.Detail) -ForegroundColor Red
    }
    return ($fails.Count -eq 0)
}
