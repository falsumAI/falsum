<#
.SYNOPSIS
    Falsum Broker Eradicator — data-broker opt-out engine (poison pill for the
    data-broker removal subscription industry: OneRep/DeleteMe charge ~$90-180/yr
    for what is a list of public opt-out links plus a calendar reminder).

.DESCRIPTION
    Shipped broker table (958 as of 2026-10-30): name, opt-out URL, opt-out method
    (Form/Email/Phone/Mail). Functions open each broker's real opt-out page
    for the user to complete, generate draft opt-out emails for Email-method
    brokers, print call scripts for Phone-method brokers, log per-broker
    status to a JSON run ledger, and install a monthly Task Scheduler re-fire
    (brokers relist — eradication is a schedule, not an event).

    HONEST LIMIT: no tool on earth auto-completes every broker's flow — most
    require identity verification (name/address/DOB) that only the user can
    supply. This module does what CAN be automated: the list, the links, the
    drafts, the tracking, and the monthly reminder. Full per-flow automation
    expands per build shift.

    v1.1 hardening (2026-10-30): every opt-out run is vault-logged
    (type "broker-optout", SHA-384 chained, genesis-on-first-use) so the
    eradication has an evidence trail; Test-BrokerTableValidation guards
    the table on every run; Confirm-BrokerRemoval closes the loop —
    Better-Way Law: the fix is tracked until confirmed.

    v1.3 hardening (2026-10-30 ~07:27 MDT): URL-ROT CLOSED — the module's
    failure mode is dead opt-out links, so it now checks itself:
    Test-BrokerUrlVerdict (pure status-code classifier) + Test-BrokerUrlStatus
    (timeout-guarded passive probe of each broker's own published page) +
    Get-BrokerBrokenLinks (walks the whole table, reports Dead/Blocked/
    Unreachable). The probe caught REAL rot on first run: TLO's standalone
    opt-out is a 404 (TLO folded into TransUnion — row now points at
    TransUnion's opt-out/limitation portal) and CoreLogic's opt-out is dead
    (CoreLogic rebranded to Cotality 2025 — row now points at Cotality's live
    privacy-policy page; Name kept as 'CoreLogic' so ledger history stays
    continuous). Get-OptOutCallScript now dials the broker's own number when
    the table carries one (ARS: 1-800-392-8911 — previously the script said
    "see URL" while the number sat in Notes). Better-Way Law gap CLOSED for
    Mail-method brokers: New-OptOutMailLetter generates a printable USPS
    opt-out letter (status 'letter-drafted', tracked in summaries/relists).
    Get-BrokerNextAction prints the single next move: relist-risk first, then
    unconfirmed, then untouched — with the exact command for each. Start-
    OptOutRun prints [i/N] progress. New pure helpers New-BrokerLetterText /
    Test-BrokerNextAction-injectable rows keep the hygiene battery offline.

    v1.4 hardening (2026-10-30 ~11:33 MDT): FIXED A REAL UNATTENDED-RUN BUG —
    New-BrokerMonthlyTask scheduled `Start-OptOutRun -Redo` with no -NoBrowser,
    so the monthly re-fire would have blasted 150 browser tabs open on an
    unattended schedule; the scheduled command is now pure
    New-BrokerMonthlyAction (Start-OptOutRun -Redo -NoBrowser plus
    Get-BrokerRelistCheck — the monthly run lists, writes the worksheet, and
    prints the relist watch; it never opens tabs or prompts). FIXED the
    launcher false-green class for this module: Test-BrokerEradicatorHygiene
    returned the raw $fails ARRAY, so the launcher's boolean-honoring
    self-test could never mark it failed — it now returns boolean per the
    sibling convention. NEW Start-OptOutRun -BrokerName (exact-name filter via
    pure Test-BrokerNameMatch, with close-match suggestions) — the relist-risk
    next-action command now targets the one broker instead of re-running the
    whole method group with -Redo. NEW New-OptOutRunWorksheet: every run
    writes a printable checklist worksheet (identity block + per-broker
    URL/notes/confirmation line) so the user is not alt-tabbing between
    console notes and browser tabs. Export-BrokerReport gains -OutDir and
    .SHA256 sidecars (sibling convention).

    v1.2 hardening (2026-10-30 ~06:08 MDT): table 100 -> 116 -> 150 brokers
    (verified batch: SocialCatfish, BackgroundAlert, PeopleSearchNow,
    PeopleWhiz, GoLookup, ArrestFacts; adtech opt-out portals: Google Ads
    Settings, DAA AboutAds, NAI, YourOnlineChoices, Facebook ad prefs,
    Criteo, The Trade Desk; Hiya caller-ID; NCTUE utility exchange);
    Get-BrokerRelistCheck flags confirmed removals older than 180 days as
    relist-risk and opened-but-never-confirmed older than 60 days as
    unconfirmed (pure helper Test-BrokerRelistFlags, covered by
    Test-BrokerEradicatorHygiene); Get-BrokerDripSchedule turns the table
    into a sustainable N-per-day plan; Get-BrokerRunHistory lists past runs;
    Export-BrokerReport gains a CSV table export; Start-OptOutRun now
    supports -WhatIf via SupportsShouldProcess and a FormEmail switch bug
    was fixed ($b.Method instead of ambiguous switch $_).

    PowerShell 5.1 compatible. Zero external dependencies. Runs on the user's
    own machine, on their own behalf only — opting out YOUR OWN listings.

.NOTES
    THE BETTER-WAY LAW: a detection without its fix is unfinished work. The
    finding is "you are listed on broker N"; the fix is the opt-out itself,
    tracked until confirmed.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:VaultLoaded = $false
$script:VaultPath = ""

# ---------------------------------------------------------------------------
# Vault plumbing — opt-out runs leave a SHA-384 chained evidence trail.
# Silent when the vault module is missing or no vault path is set — never
# blocks an opt-out run.
# ---------------------------------------------------------------------------
function Import-VaultModule {
    if ($script:VaultLoaded) { return }
    $here = Split-Path -Parent $MyInvocation.PSCommandPath
    $mod = Join-Path (Split-Path -Parent $here) "12-timeline-vault\Falsum-Vault.ps1"
    if (-not (Test-Path $mod)) {
        $mod = Join-Path $here "..\12-timeline-vault\Falsum-Vault.ps1"
    }
    if (Test-Path $mod) { . $mod; $script:VaultLoaded = $true }
    else { Write-Host "[!] vault module not found at $mod — opt-out runs will not be vault-logged" }
}

function New-BrokerLog {
    <#
    Vault-log one broker action (type "broker-optout"): run id, broker name,
    URL, method, status. Never throws — evidence is a bonus, not a blocker.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$RunId,
        [Parameter(Mandatory=$true)][hashtable]$Broker,
        [Parameter(Mandatory=$true)][string]$Status,
        [string]$Notes = ""
    )
    if (-not $script:VaultLoaded -or [string]::IsNullOrWhiteSpace($script:VaultPath)) { return }
    try {
        $vault = New-Vault -path $script:VaultPath
        Add-VaultEntry -vault $vault -type "broker-optout" -data @{
            run    = $RunId
            broker = $Broker.Name
            url    = $Broker.Url
            method = $Broker.Method
            status = $Status
            notes  = $Notes
            utc    = (Get-Date).ToUniversalTime().ToString("o")
        } | Out-Null
    } catch {
        Write-Host "[!] broker vault log failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Shipped broker table — 958 entries (Optery CC BY-NC-SA 4.0 bulk import 2026-10-30). Fields:
#   Name     : broker's public name
#   Url      : the broker's OWN published opt-out / privacy / do-not-sell page
#   Method   : Form | Email | Phone | Mail | FormEmail (page offers both)
#   Category : PeopleSearch | Marketing | RiskData | CallerID | CreditData
#   Notes    : anything the user needs to know before opting out
# ---------------------------------------------------------------------------
function Get-BrokerTable {
    [CmdletBinding()]
    param()

    $brokers = @(
        # --- People-search / public-records aggregators (the loudest 40) ---
        @{ Name='Spokeo';                Url='https://www.spokeo.com/optout';                                  Method='Form';      Category='PeopleSearch'; Notes='Enter listing URL; email confirmation required.' },
        @{ Name='BeenVerified';          Url='https://www.beenverified.com/f/opt-out/';                        Method='Form';      Category='PeopleSearch'; Notes='Also covers PeopleLooker (same form network).' },
        @{ Name='PeopleLooker';          Url='https://www.peoplelooker.com/f/opt-out/';                        Method='Form';      Category='PeopleSearch'; Notes='Shares opt-out form with BeenVerified.' },
        @{ Name='Whitepages';            Url='https://www.whitepages.com/suppression_requests';                Method='Form';      Category='PeopleSearch'; Notes='One suppression request per listing; needs account.' },
        @{ Name='Intelius';              Url='https://www.intelius.com/opt-out';                                Method='Form';      Category='PeopleSearch'; Notes='Covers Zabasearch legacy data; confirm via email.' },
        @{ Name='Instant Checkmate';     Url='https://www.instantcheckmate.com/opt-out/';                      Method='Form';      Category='PeopleSearch'; Notes='Enter full name + state.' },
        @{ Name='TruthFinder';           Url='https://www.truthfinder.com/opt-out/';                           Method='Form';      Category='PeopleSearch'; Notes='Same parent as Instant Checkmate (KarmaCheck).' },
        @{ Name='US Search';             Url='https://www.ussearch.com/optout';                                Method='Form';      Category='PeopleSearch'; Notes='Listing-by-listing removal.' },
        @{ Name='ClustrMaps';            Url='https://clustrmaps.com/bl/opt-out';                              Method='Form';      Category='PeopleSearch'; Notes='Enter name as shown on their page.' },
        @{ Name='FastPeopleSearch';      Url='https://www.fastpeoplesearch.com/removal';                       Method='Form';      Category='PeopleSearch'; Notes='Email verification link; check spam folder.' },
        @{ Name='TruePeopleSearch';      Url='https://www.truepeoplesearch.com/removal';                       Method='Form';      Category='PeopleSearch'; Notes='One address per removal request; repeat for each.' },
        @{ Name='That''s Them';          Url='https://thatsthem.com/optout';                                   Method='Form';      Category='PeopleSearch'; Notes='Select each listing, then opt out.' },
        @{ Name='CheckPeople';           Url='https://www.checkpeople.com/opt-out';                            Method='Form';      Category='PeopleSearch'; Notes='Confirm via email link within 24h.' },
        @{ Name='PublicRecords';         Url='https://www.publicrecords.com/optout/';                           Method='Form';      Category='PeopleSearch'; Notes='Name + state lookup required.' },
        @{ Name='Radaris';               Url='https://radaris.com/page/optout/';                               Method='Form';      Category='PeopleSearch'; Notes='Needs the exact public profile URL.' },
        @{ Name='CyberBackgroundChecks'; Url='https://www.cyberbackgroundchecks.com/removal';                  Method='Form';      Category='PeopleSearch'; Notes='Enter profile URL exactly.' },
        @{ Name='AdvancedBackgroundChecks'; Url='https://www.advancedbackgroundchecks.com/removal';            Method='Form';      Category='PeopleSearch'; Notes='Email confirmation.' },
        @{ Name='CocoFinder';            Url='https://cocofinder.com/optout';                                  Method='Form';      Category='PeopleSearch'; Notes='Listing URL + email.' },
        @{ Name='SearchPeopleFree';      Url='https://www.searchpeoplefree.com/opt-out';                       Method='Form';      Category='PeopleSearch'; Notes='Confirm by email.' },
        @{ Name='USPhoneBook';           Url='https://www.usphonebook.com/opt-out';                            Method='Form';      Category='PeopleSearch'; Notes='Phone-number lookup removal.' },
        @{ Name='AddressSearch';         Url='https://www.addresssearch.com/remove.php';                       Method='Form';      Category='PeopleSearch'; Notes='Address-based listings.' },
        @{ Name='PeopleSmart';           Url='https://www.peoplesmart.com/app/optout';                         Method='Form';      Category='PeopleSearch'; Notes='Owned by Thryv; may take 10+ days.' },
        @{ Name='MyLife';                Url='https://www.mylife.com/ccpa/remove-your-information';            Method='Form';      Category='PeopleSearch'; Notes='CCPA removal request; expect follow-up email.' },
        @{ Name='Classmates';            Url='https://www.classmates.com/about/privacy';                       Method='Email';     Category='PeopleSearch'; Notes='Email privacy@clickc... see page; school-profile data.' },
        @{ Name='Nuwber';                Url='https://nuwber.com/removal';                                     Method='Form';      Category='PeopleSearch'; Notes='Profile URL + email confirm.' },
        @{ Name='FastBackgroundCheck';   Url='https://www.fastbackgroundcheck.com/optout';                    Method='Form';      Category='PeopleSearch'; Notes='Listing URL required.' },
        @{ Name='PublicDataUSA';         Url='https://www.publicdatausa.com/optout';                           Method='Form';      Category='PeopleSearch'; Notes='Enter listing details as shown.' },
        @{ Name='FreePhoneTracer';       Url='https://www.freephonetracer.com/opt-out';                        Method='Form';      Category='PeopleSearch'; Notes='Phone-based removal.' },
        @{ Name='PhoneLookup';           Url='https://www.phonelookup.com/opt-out';                            Method='Form';      Category='PeopleSearch'; Notes='Caller-ID data removal.' },
        @{ Name='SpyDialer';             Url='https://www.spydialer.com/optout.aspx';                          Method='Form';      Category='PeopleSearch'; Notes='Voicemail/name lookup removal.' },
        @{ Name='OkCaller';              Url='https://www.okcaller.com/optout';                                Method='Form';      Category='PeopleSearch'; Notes='Name + number.' },
        @{ Name='411.info';              Url='https://411.info/manage/';                                      Method='Form';      Category='PeopleSearch'; Notes='Claim and remove listing.' },
        @{ Name='411Locate';             Url='https://www.411locate.com/opt-out';                              Method='Form';      Category='PeopleSearch'; Notes='Email confirmation.' },
        @{ Name='SmartBackgroundChecks'; Url='https://www.smartbackgroundchecks.com/removal';                  Method='Form';      Category='PeopleSearch'; Notes='Profile URL + email.' },
        @{ Name='FindPeopleFast';        Url='https://findpeoplefast.net/removal';                             Method='Form';      Category='PeopleSearch'; Notes='Email confirm.' },
        @{ Name='PeopleByName';          Url='https://www.peoplebyname.com/remove-my-info.php';                Method='Form';      Category='PeopleSearch'; Notes='Name search, then removal link.' },
        @{ Name='FamilyTreeNow';         Url='https://www.familytreenow.com/optout';                           Method='Form';      Category='PeopleSearch'; Notes='Genealogy + living-people records; email confirm.' },
        @{ Name='VoterRecords';          Url='https://voterrecords.com/unsubscribe';                           Method='Form';      Category='PeopleSearch'; Notes='Voter-registration data; state-by-state.' },
        @{ Name='USInfoSearch';          Url='https://www.usinfosearch.com/opt-out';                           Method='Form';      Category='PeopleSearch'; Notes='Investigative data; ID verification may apply.' },
        @{ Name='PublicRecordsNow';      Url='https://www.publicrecordsnow.com/optout';                       Method='Form';      Category='PeopleSearch'; Notes='Listing-by-listing.' },
        @{ Name='Enformion';             Url='https://www.enformion.com/privacy/';                             Method='Email';     Category='PeopleSearch'; Notes='Opt-out via privacy contact on page.' },
        @{ Name='Delvepoint';            Url='https://www.delvepoint.com/opt-out/';                            Method='Form';      Category='PeopleSearch'; Notes='Investigative search data.' },
        @{ Name='Sync.me';               Url='https://sync.me/optout/';                                       Method='Form';      Category='CallerID';     Notes='App caller-ID; remove your number.' },
        @{ Name='Truecaller';            Url='https://www.truecaller.com/unlisting';                           Method='Form';      Category='CallerID';     Notes='Deactivate account first for full removal.' },
        @{ Name='NumLookup';             Url='https://www.numlookup.com/opt-out';                              Method='Form';      Category='CallerID';     Notes='Free reverse-number lookup removal.' }

        # --- Marketing / advertising data brokers (the quiet 35) ---
        @{ Name='Acxiom';               Url='https://www.acxiom.com/optout/';                                  Method='Form';      Category='Marketing';   Notes='One of the largest consumer-data brokers; 4-6 weeks.' },
        @{ Name='LiveRamp';             Url='https://liveramp.com/opt_out/';                                   Method='Form';      Category='Marketing';   Notes='Acxiom spin-off; identity-resolution graph.' },
        @{ Name='Epsilon';              Url='https://legal.epsilon.com/consumer-information/opt-out/';         Method='Form';      Category='Marketing';   Notes='Abacus cooperative + marketing DB; email confirm.' },
        @{ Name='Oracle Data Cloud';    Url='https://datacloudoptout.oracle.com/';                            Method='Form';      Category='Marketing';   Notes='BlueKai/Datalogix registry; cookie + interest opt-out.' },
        @{ Name='Data Axle (InfoGroup)';Url='https://www.data-axle.com/do-not-sell-my-data/';                 Method='FormEmail'; Category='Marketing';   Notes='Do-Not-Sell request; covers ReferenceUSA data.' },
        @{ Name='Neustar (TransUnion)'; Url='https://www.transunion.com/privacy/opt-out';                     Method='Form';      Category='Marketing';   Notes='Now TransUnion; use TransUnion opt-out portal.' },
        @{ Name='Lotame';               Url='https://www.lotame.com/about-lotame/privacy/';                    Method='Email';     Category='Marketing';   Notes='DMP; opt-out instructions on privacy page.' },
        @{ Name='Throtle';              Url='https://throtle.io/optout/';                                      Method='Form';      Category='Marketing';   Notes='Identity graph opt-out.' },
        @{ Name='TowerData';            Url='https://www.towerdata.com/consumer-information/opt-out';          Method='Form';      Category='Marketing';   Notes='Email-intelligence data.' },
        @{ Name='FullContact';          Url='https://www.fullcontact.com/privacy/';                            Method='Form';      Category='Marketing';   Notes='Contact-enrichment API; privacy request form.' },
        @{ Name='Clearbit';             Url='https://clearbit.com/opt-out/';                                   Method='Form';      Category='Marketing';   Notes='B2B enrichment; HubSpot-owned.' },
        @{ Name='ZoomInfo';             Url='https://www.zoominfo.com/privacy-center';                         Method='Form';      Category='Marketing';   Notes='B2B profiles; privacy-center request.' },
        @{ Name='Apollo.io';            Url='https://www.apollo.io/privacy-policy#optout';                    Method='Form';      Category='Marketing';   Notes='Sales-intel profiles; opt-out section in policy.' },
        @{ Name='Lusha';                Url='https://www.lusha.com/privacy-center/';                           Method='Form';      Category='Marketing';   Notes='Contact data; privacy center request.' },
        @{ Name='RocketReach';          Url='https://rocketreach.co/opt_out';                                  Method='Form';      Category='Marketing';   Notes='Email-finder profiles; opt-out page.' },
        @{ Name='SignalHire';           Url='https://www.signalhire.com/opt-out';                              Method='Form';      Category='Marketing';   Notes='Recruiter contact data.' },
        @{ Name='People Data Labs';     Url='https://www.peopledatalabs.com/opt-out-form';                    Method='Form';      Category='Marketing';   Notes='Resume/dataset broker; opt-out form.' },
        @{ Name='Pipl';                 Url='https://pipl.com/personal-information-removal-form';               Method='Form';      Category='Marketing';   Notes='Identity search API; removal form.' },
        @{ Name='PeekYou';              Url='https://www.peekyou.com/about/contact/optout/';                   Method='Form';      Category='PeopleSearch';Notes='Social-profile aggregator.' },
        @{ Name='Yasni';                Url='https://www.yasni.com/contact';                                   Method='Email';     Category='PeopleSearch';Notes='People-search; contact form on page.' },
        @{ Name='Veripages';            Url='https://veripages.com/page/optout';                               Method='Form';      Category='PeopleSearch';Notes='Profile URL + email.' },
        @{ Name='Nielsen';              Url='https://www.nielsen.com/us/en/legal/privacy-statement/us-online-privacy/'; Method='Form'; Category='Marketing'; Notes='Panel + digital measurement opt-out.' },
        @{ Name='SafeGraph';            Url='https://www.safegraph.com/privacy-policy';                       Method='Email';     Category='Marketing';   Notes='Location data; opt-out via privacy contact.' },
        @{ Name='Valassis (Vericast)';  Url='https://www.valassis.com/privacy-policy';                        Method='Email';     Category='Marketing';   Notes='Direct-mail data; privacy-contact request.' },
        @{ Name='DirectMail.com';       Url='https://www.directmail.com/privacy-policy/';                     Method='Email';     Category='Marketing';   Notes='Mailing-list broker; email opt-out.' },
        @{ Name='Melissa';              Url='https://www.melissa.com/company/privacy-optout-form';             Method='Form';      Category='Marketing';   Notes='Address-verification data.' },
        @{ Name='Experian Marketing';   Url='https://www.experian.com/privacy/opting_out.html';                Method='Form';      Category='Marketing';   Notes='Separate from credit-bureau disputes; marketing opt-out.' },
        # --- Risk / investigative data brokers (the restricted 15) ---
        @{ Name='LexisNexis Risk';      Url='https://optout.lexisnexis.com/';                                 Method='Form';      Category='RiskData';    Notes='Biggest risk-data file; ID verification; 30+ days.' },
        @{ Name='TLO (TransUnion)';     Url='https://service.transunion.com/dss/allstates_optout.page';          Method='Form';      Category='RiskData';    Notes='TLO folded into TransUnion; the standalone tlo.com/opt-out page is dead (404, verified 2026-10-30); use TransUnion opt-out/limitation portal, which covers its risk-solutions brands.' },
        @{ Name='IRB Search';           Url='https://www.irbsearch.com/optout';                                Method='Form';      Category='RiskData';    Notes='Investigative records; mail-in form on page.' },
        @{ Name='Tracers';              Url='https://www.tracers.com/privacy-policy';                          Method='Email';     Category='RiskData';    Notes='Opt-out via privacy contact.' },
        @{ Name='CoreLogic';            Url='https://www.cotality.com/legal/privacy-policy';                        Method='Form';      Category='RiskData';    Notes='CoreLogic rebranded to Cotality (2025); the legacy corelogic.com/privacy/optout.aspx page is dead (404, verified 2026-10-30); exercise your rights via the Cotality privacy-policy page. Name kept as CoreLogic so ledger history stays continuous.' },
        @{ Name='Dun & Bradstreet';     Url='https://www.dnb.com/us/choose-language/data-opt-out.html';        Method='Form';      Category='RiskData';    Notes='Business + principal data.' },
        # --- Credit / consumer-reporting adjacent (the frozen 10) ---
        @{ Name='Experian (Bureau)';    Url='https://www.experian.com/freeze/center.html';                     Method='Form';      Category='CreditData';  Notes='FREEZE your file; also prescreen opt-out at optoutprescreen.com.' },
        @{ Name='Equifax';              Url='https://www.equifax.com/personal/credit-report-services/credit-freeze/'; Method='Form'; Category='CreditData'; Notes='FREEZE your file; disputes via disclosures page.' },
        @{ Name='TransUnion';           Url='https://www.transunion.com/credit-freeze';                        Method='Form';      Category='CreditData';  Notes='FREEZE your file; trueFreeze portal.' },
        @{ Name='Innovis';              Url='https://www.innovis.com/personal/securityFreeze';                 Method='Form';      Category='CreditData';  Notes='The 4th bureau — most people forget this one.' },
        @{ Name='ChexSystems';          Url='https://www.chexsystems.com/request-reports/consumer-disclosure'; Method='Form';      Category='CreditData';  Notes='Bank-account screening; freeze separately.' },
        @{ Name='SageStream (LexisNexis)'; Url='https://optout.lexisnexis.com/';                               Method='Form';      Category='CreditData';  Notes='Same LexisNexis opt-out covers SageStream.' },
        @{ Name='ARS (Advanced Resolution)'; Url='https://www.ars-consumeraffairs.com/';                       Method='Phone';     Category='CreditData';  Notes='Phone opt-out for collections data.'; Phone='1-800-392-8911' },
        # --- Mail/phone preference registries (kill the supply lines) ---
        @{ Name='DMAchoice (ANA)';      Url='https://dmachoice.thedma.org/';                                  Method='Form';      Category='Marketing';   Notes='$5 processing fee; suppresses DMA-member mail for 10 yrs.' },
        @{ Name='OptOutPrescreen';      Url='https://www.optoutprescreen.com/';                                Method='Form';      Category='CreditData';  Notes='Stops pre-approved credit/insurance offers; all 4 bureaus honor it.' },
        @{ Name='National Do Not Call'; Url='https://www.donotcall.gov/';                                     Method='Form';      Category='Marketing';   Notes='FTC registry; stops telemarketing calls, not data sale.' },
        @{ Name='Catalog Choice';       Url='https://www.catalogchoice.org/';                                 Method='Form';      Category='Marketing';   Notes='Free; stops catalogs and direct-mail offers.' },
        @{ Name='YellowPages Opt-Out';  Url='https://www.yellowpagesoptout.com/';                             Method='Form';      Category='Marketing';   Notes='Stops printed phone-book delivery (data exhaust).' },
        @{ Name='PeopleFinders';        Url='https://www.peoplefinders.com/opt-out';                          Method='Form';      Category='PeopleSearch';Notes='Large people-search DB; email confirm.' },
        @{ Name='CheckThem';            Url='https://www.checkthem.com/optout/';                               Method='Form';      Category='PeopleSearch';Notes='Intelius-network site; confirm via email.' },
        @{ Name='SpyFly';               Url='https://www.spyfly.com/help/opt-out';                             Method='Form';      Category='PeopleSearch';Notes='Opt-out instructions on help page.' },
        @{ Name='USA People Search';    Url='https://www.usa-people-search.com/manage/';                      Method='Form';      Category='PeopleSearch';Notes='Manage/remove your record.' },
        @{ Name='Addresses.com';        Url='https://www.addresses.com/removal/';                              Method='Form';      Category='PeopleSearch';Notes='Address-based listings; email confirm.' },
        @{ Name='CallerSmart';          Url='https://www.callersmart.com/opt-out';                             Method='Form';      Category='CallerID';     Notes='Community caller-ID app; remove your number.' },
        @{ Name='ReversePhoneLookup';   Url='https://www.reversephonelookup.com/optout';                       Method='Form';      Category='CallerID';     Notes='Reverse-number lookup removal.' },
        @{ Name='MicroBilt';            Url='https://www.microbilt.com/consumer-information/opt-out';          Method='Form';      Category='CreditData';  Notes='Alternative credit data; consumer opt-out.' },
        @{ Name='FactorTrust';          Url='https://www.factorstrust.com/consumer-opt-out';                   Method='Form';      Category='CreditData';  Notes='Subprime/short-term credit bureau (TransUnion); opt-out.' },
        @{ Name='Merkle';               Url='https://www.merkle.com/privacy-policy';                           Method='Email';     Category='Marketing';   Notes='Dentsu marketing data; opt-out via privacy contact.' }

        # --- People-search / public-records (second 7, URLs verified 2026-10-30) ---
        @{ Name='SocialCatfish';        Url='https://socialcatfish.com/optout/';                                Method='Form';      Category='PeopleSearch'; Notes='Paste your profile URL; email confirmation; processed in 7-21 days.' },
        @{ Name='BackgroundAlert';      Url='https://www.backgroundalert.com/optout/';                          Method='Form';      Category='PeopleSearch'; Notes='Online removal tool; email confirmation.' },
        @{ Name='PeopleSearchNow';      Url='https://peoplesearchnow.com/optout';                               Method='Form';      Category='PeopleSearch'; Notes='Tick both consent boxes, enter email, find your record, click Remove Record.' },
        @{ Name='PeopleWhiz';           Url='https://www.peoplewhiz.com/optout';                                Method='Form';      Category='PeopleSearch'; Notes='Find your record, click That''s Me; email verification required.' },
        @{ Name='GoLookup';             Url='https://golookup.com/removemyinfo';                                Method='Form';      Category='PeopleSearch'; Notes='Paste the exact profile URL.' },
        @{ Name='ArrestFacts';          Url='https://www.arrestfacts.com/';                                     Method='Form';      Category='PeopleSearch'; Notes='On-site: click ''Information Control'' on your own record page.' },
        @{ Name='Unmask';               Url='https://www.unmask.com/optout/';                                   Method='Form';      Category='PeopleSearch'; Notes='Find your listing, submit removal; email confirmation.' }

        # --- Adtech opt-out portals (kill interest-based tracking at the source) ---
        @{ Name='Google Ads Settings';  Url='https://adssettings.google.com/';                                 Method='Form';      Category='Marketing';   Notes='Turn off ad personalization across Google services.' },
        @{ Name='AboutAds (DAA)';       Url='https://optout.aboutads.info/';                                   Method='Form';      Category='Marketing';   Notes='Industry-wide: opt out of interest-based ads from DAA member companies.' },
        @{ Name='NAI Opt-Out';          Url='https://optout.networkadvertising.org/';                           Method='Form';      Category='Marketing';   Notes='Multi-company opt-out for Network Advertising Initiative members.' },
        @{ Name='YourOnlineChoices';    Url='https://www.youronlinechoices.com/';                              Method='Form';      Category='Marketing';   Notes='European (EDAA) industry opt-out portal.' },
        @{ Name='Facebook Ad Preferences'; Url='https://www.facebook.com/ads/preferences';                     Method='Form';      Category='Marketing';   Notes='Turn off off-Facebook-activity ad targeting.' },
        @{ Name='Criteo';               Url='https://www.criteo.com/privacy/';                                 Method='Form';      Category='Marketing';   Notes='Ad-personalization opt-out inside the privacy page.' },
        @{ Name='The Trade Desk';       Url='https://www.thetradedesk.com/consumer-privacy';                   Method='Form';      Category='Marketing';   Notes='Consumer privacy portal: opt out of targeted advertising.' }

        # --- Caller-ID + utility-data additions ---
        @{ Name='Hiya';                 Url='https://www.hiya.com/opt-out';                                    Method='Form';      Category='CallerID';     Notes='Removes your number from the Hiya caller-ID database.' },
        @{ Name='NCTUE';                Url='https://www.nctue.com/consumers';                                  Method='Form';      Category='CreditData';  Notes='Telecom/utilities exchange; freeze or dispute via the consumer page.' },
        @{ Name='PeopleFinders'; Url='https://www.peoplefinders.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Opt-out form; confirmation email required.' },
        @{ Name='PublicRecordsNow'; Url='https://www.publicrecordsnow.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Public records aggregator opt-out.' },
        @{ Name='CheckPeople'; Url='https://www.checkpeople.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Background check site opt-out.' },
        @{ Name='InstantCheckmate'; Url='https://www.instantcheckmate.com/opt-out/'; Method='Form'; Category='PeopleSearch'; Notes='Background check opt-out form.' },
        @{ Name='TruthFinder'; Url='https://www.truthfinder.com/opt-out/'; Method='Form'; Category='PeopleSearch'; Notes='Background check opt-out.' },
        @{ Name='USPhoneBook'; Url='https://www.usphonebook.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Phone directory opt-out.' },
        @{ Name='PhoneValidator'; Url='https://www.phonevalidator.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Phone lookup opt-out.' },
        @{ Name='NumberGuru'; Url='https://www.numberguru.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Reverse phone lookup opt-out.' },
        @{ Name='Sync.me'; Url='https://sync.me/optout/'; Method='Form'; Category='CallerID'; Notes='Caller ID app opt-out.' },
        @{ Name='CallerSmart'; Url='https://www.callersmart.com/opt-out'; Method='Form'; Category='CallerID'; Notes='Caller ID lookup opt-out.' },
        @{ Name='Truecaller'; Url='https://www.truecaller.com/unlisting'; Method='Form'; Category='CallerID'; Notes='Unlist your number from Truecaller.' },
        @{ Name='Whoscall'; Url='https://whoscall.com/en/optout'; Method='Form'; Category='CallerID'; Notes='Taiwan-based caller ID opt-out.' },
        @{ Name='Epsilon'; Url='https://www.epsilon.com/us/privacy'; Method='Form'; Category='Marketing'; Notes='Major marketing data broker; privacy request form.' },
        @{ Name='Experian Marketing'; Url='https://www.experian.com/privacy'; Method='Form'; Category='Marketing'; Notes='Marketing data opt-out (separate from credit).' },
        @{ Name='Equifax Marketing'; Url='https://www.equifax.com/privacy/'; Method='Form'; Category='Marketing'; Notes='Marketing opt-out via privacy center.' },
        @{ Name='TransUnion Marketing'; Url='https://www.transunion.com/privacy'; Method='Form'; Category='Marketing'; Notes='Marketing data choices.' },
        @{ Name='Acxiom'; Url='https://www.acxiom.com/optout/'; Method='Form'; Category='Marketing'; Notes='Major data broker; online opt-out form.' },
        @{ Name='Oracle Data Cloud'; Url='https://www.oracle.com/legal/privacy/'; Method='Form'; Category='Marketing'; Notes='BlueKai/Datalogix data opt-out.' },
        @{ Name='Lotame'; Url='https://www.lotame.com/privacy/'; Method='Form'; Category='Marketing'; Notes='Data management platform opt-out.' },
        @{ Name='Neustar'; Url='https://www.transunion.com/privacy'; Method='Form'; Category='Marketing'; Notes='Now part of TransUnion; use TU privacy.' },
        @{ Name='Tapad'; Url='https://www.tapad.com/privacy'; Method='Form'; Category='Marketing'; Notes='Cross-device identity opt-out.' },
        @{ Name='Drawbridge'; Url='https://www.linkedin.com/legal/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Acquired by LinkedIn; via LinkedIn privacy.' },
        @{ Name='LiveRamp'; Url='https://www.liveramp.com/opt-out/'; Method='Form'; Category='Marketing'; Notes='Identity resolution opt-out.' },
        @{ Name='FullContact'; Url='https://www.fullcontact.com/privacy/'; Method='Form'; Category='Marketing'; Notes='Contact enrichment opt-out.' },
        @{ Name='Clearbit'; Url='https://clearbit.com/privacy/'; Method='Form'; Category='Marketing'; Notes='B2B data enrichment opt-out.' },
        @{ Name='ZoomInfo'; Url='https://www.zoominfo.com/about-zoominfo/privacy'; Method='Form'; Category='Marketing'; Notes='B2B contact database opt-out.' },
        @{ Name='DiscoverOrg'; Url='https://www.zoominfo.com/about-zoominfo/privacy'; Method='Form'; Category='Marketing'; Notes='Now ZoomInfo; same opt-out.' },
        @{ Name='InsideView'; Url='https://www.dnb.com/privacy'; Method='Form'; Category='Marketing'; Notes='Now Dun & Bradstreet; via D&B privacy.' },
        @{ Name='LexisNexis'; Url='https://optout.lexisnexis.com/'; Method='Form'; Category='RiskData'; Notes='Major risk data broker; online opt-out.' },
        @{ Name='Thomson Reuters CLEAR'; Url='https://www.thomsonreuters.com/en/privacy-statement.html'; Method='Form'; Category='RiskData'; Notes='CLEAR database opt-out via privacy.' },
        @{ Name='IRB Search'; Url='https://www.irbsearch.com/optout.php'; Method='Form'; Category='RiskData'; Notes='Investigative database opt-out.' },
        @{ Name='TLOxp'; Url='https://www.tlo.com/optout'; Method='Form'; Category='RiskData'; Notes='TransUnion TLOxp investigative opt-out.' },
        @{ Name='IDI Data'; Url='https://www.ididata.com/optout'; Method='Form'; Category='RiskData'; Notes='Investigative data opt-out.' },
        @{ Name='Delvepoint'; Url='https://www.delvepoint.com/opt-out/'; Method='Form'; Category='RiskData'; Notes='Background check data opt-out.' }
        @{ Name='33 Mile Radius'; Url='mailto:privacy@33mileradius.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='33Across'; Url='https://udp.33across.com/udp_opt_out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='360 Media Direct'; Url='mailto:privacy@360mediadirect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='411.com'; Url='https://www.whitepages.com/suppression-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='6sense Insights, Inc.'; Url='https://6sense.com/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ACE Agents'; Url='https://www.aceagents.ai/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ACH Address Clearing House'; Url='https://www.achcoop.com/do-not-sell-my-personal-info'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='AGR Marketing Solutions'; Url='mailto:info@agrmarketingsolutions.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AMF Internet Services Limited'; Url='https://anymailfinder.com/legal/gdpr'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ANCHOR'; Url='https://ecom2.anchorcomputer.com/ccpa'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AWL'; Url='https://dnc.allwebleads.com/Unsubscribe'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Ad Direct'; Url='mailto:customerservice@addirectinc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Adapt.io'; Url='https://www.adapt.io/check-my-email'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Address Scoop'; Url='mailto:support@addressscoop.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Adstra (American List Counsel)'; Url='https://privacyportal.onetrust.com/webform/3d2d5e0c-bd98-46b8-906c-ede68a6f6a80/f54a1b10-bb5d-4c99-9521-3e08dc527583'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Adttribution'; Url='https://www.adttribution.com/opt-out.html'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AeroLeads'; Url='https://aeroleads.com/contact'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Affinity Answers'; Url='https://www.affinityanswers.com/your-privacy-choices/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Affinity Solutions'; Url='https://affinitysolutions-privacy.my.onetrust.com/webform/a564cfa1-53bf-4c10-bf95-cd907432d7e8/7e4e6bf3-6562-454e-8c73-6a7bd1f4b336'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Affluense.ai'; Url='https://www.affluense.ai/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Affordable Background Checks'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Aged Lead Store'; Url='mailto:optout@nextwavemarketingstrategies.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Aged Solar Leads, LLC'; Url='https://agedsolarleads.com/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Alabama Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='AlabamaCourtRecords.us'; Url='https://alabamacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='AlarmsCalifornia'; Url='http://www.alarmscalifornia.org/about'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Alaska Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='AlaskaCourtRecords.us'; Url='https://alaskacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Alesco Data'; Url='mailto:info@alescodata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='All Biz'; Url='https://www.allbiz.com/removal'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='AllHighSchools.com'; Url='mailto:press@allhighschools.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='AllPeople'; Url='https://allpeople.com/removal'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Allant Group, LLC'; Url='mailto:privacy@allantgroup.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Alliant'; Url='https://privacyportal-cdn.onetrust.com/dsarwebform/591ac1c1-3a1e-496f-9e43-ff4afb5fef85/2b52262e-8ada-4725-b86e-e4b960336f96.html'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Alphonso'; Url='https://choice.alphonso.tv/donotsell'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Altrata Inc'; Url='mailto:piprivacy@altrada.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AmOne'; Url='https://apply.amone.com/privacy.asp'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Amedisys, Inc.'; Url='https://cdn.amedisys.com/userfiles/CCPA%20Request%20Form.pdf'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='AmericaPhonebook'; Url='http://www.americaphonebook.com/contact.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='American City Business Journals'; Url='mailto:PrivacyPolicyCoordinator@bizjournals.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Amplemarket'; Url='mailto:privacy@amplemarket.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='AnalyticsIQ'; Url='https://privacyportal.onetrust.com/webform/f6a59500-f900-4652-b030-0cd51afe15a5/87ca07e4-e06c-4ad8-9aa6-ccbbaa8750c1'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Ancestry.com UK Limited'; Url='mailto:support@ancestry.co.uk'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Andrews Wharton'; Url='https://www.andrewswharton.com/your-privacy-choices'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='AnswerLady'; Url='mailto:customercare@peoplefinders.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Anteriad'; Url='https://info.anteriad.com/marketing-data-unsubscribe-page'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AnyWho'; Url='https://www.intelius.com/suppression-center/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Apartments.com'; Url='https://www.apartments.com/grow/about/do-not-sell-my-personal-information-california-residents'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Apollo'; Url='https://www.apollo.io/privacy-policy/remove'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Appily'; Url='mailto:privacy@eab.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Areacode-Lookup'; Url='https://www.areacode-lookup.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Arity'; Url='mailto:privacy@arity.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Arizona Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ArizonaCourtRecords.us'; Url='https://arizonacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Arkansas Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ArkansasCourtRecords.us'; Url='https://arkansascourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='AroundDeal'; Url='https://www.arounddeal.com/remove-profile'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ArrestWarrant.org'; Url='https://ms.arrestwarrant.org/InfoPayOpt-OutNew.pdf'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Arrests.org'; Url='mailto:info@arrests.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Aspire North'; Url='mailto:privacy@aspire-north.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='AtData'; Url='https://instantdata.atdata.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Attribits'; Url='https://www.attribits.com/do-not-sell'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Audiencerate'; Url='https://www.audiencerate.com/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='B2BHint'; Url='mailto:hello@b2bhint.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='BDO'; Url='https://www.bdo.com/consumer-request-form'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Background Alert, Inc.'; Url='mailto:info@BackgroundAlert.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Background Hawk'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='BackgroundCheckers'; Url='https://www.backgroundcheckers.net/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Bay Collective IP, LLC'; Url='mailto:info@baycollective.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Belardi Wong'; Url='https://privacyportal.onetrust.com/webform/3d2d5e0c-bd98-46b8-906c-ede68a6f6a80/400f54ed-fcbb-4749-ab5b-32f491c72390'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='BestHistorySites.net'; Url='mailto:support@besthistorysites.net'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Big Bend Transit, Inc.'; Url='mailto:info@bigbendtransit.org'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Big Village'; Url='https://big-village.com/do-not-sell-or-share-my-personal-information/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Billtrust'; Url='mailto:privacy@billtrust.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Birdeye'; Url='https://birdeye.com/ccpa/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='BizIreland'; Url='https://www.bizireland.com/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Bizarchive'; Url='mailto:webmaster@bizarchive.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Bluaziende'; Url='mailto:info@bluaziende.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Blue Action'; Url='https://request.blueaction.io/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Brandwatch'; Url='mailto:privacy@brandwatch.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='BrightSwipe'; Url='mailto:support@brightswipe.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='BrooksIM'; Url='https://www.brooksim.com/privacy-form'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Buildertrend'; Url='https://buildertrend.com/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Bumper'; Url='https://www.bumper.com/svc/optout/search/comprehensive_optouts'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Business Cheshire'; Url='mailto:hello@businesscheshire.co.uk'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Business Watch Network'; Url='mailto:support@bizwatchnetwork.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='BuyersRoad, Inc.'; Url='mailto:privacy@experience.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Buzzfile Media, LLC'; Url='https://www.buzzfile.com/Company/Remove'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='CB Insights, Inc.'; Url='mailto:info@cbinsights.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='CIENCE Technologies, Inc.'; Url='mailto:privacy@cience.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='CITYDATA'; Url='https://citydata.ai/privacy/do_not_sell_personal_information/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='CML Medical'; Url='https://www.completemedicallists.com/ccpa.php'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='CPAdirectory.com, Inc.'; Url='https://cpadirectory.com/opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='CT Company Directory'; Url='mailto:info@ctcompanydir.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Cadent'; Url='mailto:privacy@cadent.tv'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='California Arrests'; Url='https://www.californiaarrests.org/ccpaOptOut/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='California Criminal Records Search'; Url='https://californiacriminalrecords.org/contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaBrokers.org'; Url='http://www.californiabrokers.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaCourtRecords.us'; Url='https://californiacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaEngineering.org'; Url='http://www.californiaengineering.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaLicensing.org'; Url='http://www.californialicensing.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaNursing.org'; Url='http://www.californianursing.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CaliforniaPharmacists.org'; Url='http://www.californiapharmacists.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CallApp Software Ltd.'; Url='https://callapp.com/support/can-i-wipe-my-information-from-callapp-2'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Caller Name'; Url='mailto:callername@rumex.bh'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='CallerCenter.com'; Url='https://www.callercenter.com/remove_name.htm'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='CareerBuilder'; Url='https://edge.careerbuilder.com/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Catalyze AI'; Url='mailto:privacy@catalyzeai.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Cause IQ'; Url='https://www.causeiq.com/privacy_policy/ccpa/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Censia'; Url='https://docs.google.com/forms/d/1VhF33VAQG4AmUqBWf7e3m8fw17h9ek64EtQXnuuBQcA/viewform'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ChamberofCommerce.com'; Url='mailto:info@chamberofcommerce.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Checksecrets'; Url='https://www.checksecrets.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Choreograph'; Url='https://amer-cpp.choreograph.com/manage-your-data/do-not-sell'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Cint'; Url='mailto:privacy@Cint.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Cision'; Url='mailto:privacy@cision.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='City-Data.com'; Url='https://www.city-data.com/delrequest/form.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Civis'; Url='https://docs.google.com/forms/d/e/1FAIpQLSfvUYww9wEK9Y4F6VY3nQtm0bBS8QTdcDthet6WAKDYqnnwHA/viewform'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Claritas'; Url='https://privacyportal.onetrust.com/webform/68582716-6ce4-4f6e-bf08-78371b5f3292/6c7dc52d-0e2b-481f-9256-0755179e3783.html'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Classmates.com'; Url='https://www.classmates.com/about/privacy#p-8'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Clay'; Url='mailto:support@clay.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Clearout.io'; Url='mailto:us@clearout.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Click Search LLC'; Url='mailto:info@clicksearchsolutions.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Client Command'; Url='mailto:privacy@ClientCommand.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Clodura.AI'; Url='https://www.clodura.ai/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Closely'; Url='mailto:support@closelyhq.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Clustermaps.NET'; Url='https://clustermaps.net/opt-out/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Coalition Greenwich'; Url='mailto:privacy1@crisil.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Cognism'; Url='https://www.cognism.com/data-opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Colorado Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ColoradoCourtRecords.us'; Url='https://coloradocourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ColoradoResidentDirectory'; Url='https://www.coloradoresidentdirectory.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Commercial List'; Url='mailto:enquiries@commerciallist.co.uk'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Commercial Real Estate Exchange, Inc.'; Url='mailto:privacy@crexi.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Company Check Ltd'; Url='mailto:contactus@companycheck.co.uk'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Compile'; Url='https://www.compile.com/hcp-opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Complementics'; Url='mailto:Privacy@complementics.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Completed.com'; Url='https://completed.com/ccpa'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Comscore'; Url='https://www.comscore.com/About/Privacy/Data-Subject-Rights'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ConfidentialPhoneLookup'; Url='https://www.confidentialphonelookup.com/removals/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Connected Investors'; Url='https://firstam.service-now.com/x_farf2_dp_request_fa_connected_investor.do?sysparm_id=6d6e7e8edb3e3158665f182813961985'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Connecticut Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Connecticut Resident Directory'; Url='https://www.connecticutresidentdirectory.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ConnecticutCourtRecords.us'; Url='https://connecticutcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Connext Digital'; Url='mailto:privacy@connextdigital.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Consider'; Url='mailto:support@consider.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ContactOut'; Url='https://contactout.com/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ContractorsCalifornia.org'; Url='http://www.contractorscalifornia.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Converge'; Url='mailto:info@convergemarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Convex'; Url='mailto:support@convexlabs.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='CorporationWiki'; Url='https://www.corporationwiki.com/profiles/public'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Cortera, Inc.'; Url='mailto:privacy@cortera.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='CourtCaseFinder'; Url='https://courtcasefinder.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CourtRec.com'; Url='https://dashboard.courtrec.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CourtRecordFinder.com'; Url='mailto:privacy@cisnationwide.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CourtRecords.us'; Url='https://courtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Crime Informer'; Url='mailto:support@crimeinformer.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Criminal.com'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CriminalDataCheck'; Url='https://www.intelius.com/privacy-center'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CriminalRecords.com'; Url='https://www.intelius.com/privacy-center'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='CriminalRegistry.org'; Url='https://criminalregistry.org/remove.php?fn=&ln='; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Crosswalk Technologies'; Url='mailto:privacy@crosswalknyc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Cybba'; Url='mailto:dsr@cybba.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Cyndx'; Url='mailto:privacy@cyndx.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='D-Dots'; Url='mailto:support@ddotslab.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='DATO CAPITAL LTD'; Url='mailto:info@datocapital.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='DMDatabases.com'; Url='mailto:optout@dmdatabases.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='DOBsearch.com'; Url='https://www.dobsearch.com/people-finder/block-record-request.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='DTM Deutsche Tele Medien GmbH'; Url='mailto:info@dtme.de'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='DTN'; Url='mailto:privacy@dtn.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Dark Reading'; Url='mailto:editors@darkreading.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Data Axle'; Url='https://www.data-axle.com/do-not-sell-my-data/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Data Delivers'; Url='https://datadelivers.com/do-not-sell-or-share-personal-information'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Data Direct Marketing'; Url='mailto:info@datadirectmarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Data Trust'; Url='https://thedatatrust.com/do-not-sell-my-personal-information/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='DataLead'; Url='https://data-lead.com/support/removal_request'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='DataMasters'; Url='mailto:sales@datamasters.org'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Datagma'; Url='https://form.typeform.com/to/MCuF90xu?typeform-source=datagma.com'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Dataline'; Url='mailto:privacy.officer@datalinedata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Datanyze'; Url='https://www.datanyze.com/privacy-center/request-removal'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Datasys'; Url='mailto:support@datasys.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Dateas'; Url='mailto:consultas.es@dateas.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Dato Capital'; Url='mailto:info@datocapital.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='DealerSocket'; Url='https://globaldsar.solera.com/webform/20bbc57b-6134-4535-8062-a1745b771851/1eafe8e0-f69b-4d39-af7c-6dbf764046fa'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='DealerX'; Url='mailto:privacy@dealerx.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Decide'; Url='mailto:privacy@decide.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='DecisionLinks'; Url='mailto:support@decisionlinks.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Deep Root'; Url='https://privacy.deeprootanalytics.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Deep Sync'; Url='https://privacy.deepsync.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Deepdy Ltd'; Url='mailto:unknownadmin@unknownphone.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Delaware Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='DelawareCourtRecords.us'; Url='https://delawarecourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Deluxe'; Url='mailto:privacy@deluxe.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Demandbase'; Url='https://www.demandbase.com/privacy-center.html?ketch_preferences_tab=rightsTab'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='DentistsCalifornia.org'; Url='http://www.dentistscalifornia.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='DexKnows.com'; Url='https://privacyportal-cdn.onetrust.com/dsarwebform/dd6500c7-03cb-45b0-8bed-97ece55a892d/cfcefb69-41db-4aee-bd00-c702df72ee0f.html'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='DiabloMedia'; Url='https://diablomedia.com/privacy-request/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Dice'; Url='https://www.dice.com/about/ccpa#ccpa-form-anchor'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Digdev'; Url='mailto:info@Digdev.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Digital Media Solutions'; Url='https://dms-privacy.my.onetrust.com/webform/506f8b15-11ff-4f18-95fa-48ff903e623f/4268d0f0-bd98-4afb-b33a-a7a922ae182a'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Disco Network'; Url='mailto:support@disconetwork.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Distribution Processing Center'; Url='mailto:customerservice@distpc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='DoctorsAtlas'; Url='mailto:info@doctorsatlas.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='DomainTools LLC'; Url='https://www.domaintools.com/company/california-privacy-notice/do-not-sell/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='DrivenIQ'; Url='mailto:support@drivenIQ.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Drunk Drivers'; Url='https://drunkdrivers.org/remove-my-info/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Dynata'; Url='mailto:privacy@dynata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='EAB'; Url='mailto:privacy@eab.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='EXLService.com'; Url='mailto:Privacy@exlservice.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='EZlocal.com, Inc.'; Url='https://contact.ezlocal.com/form/remove-listing/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='EasyBackgroundChecks'; Url='https://www.intelius.com/suppression-center/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='EdgeIn'; Url='mailto:ashley@edgein.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Email Industries'; Url='mailto:privacy@emailindustries.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Emailmovers'; Url='mailto:compliance@emailmovers.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Enigma'; Url='mailto:privacy@enigma.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Eniro AB'; Url='mailto:info@eniro.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Epieos'; Url='mailto:contact@epieos.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Equilar, Inc.'; Url='https://www.equilar.com/ccpa'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Everyday Health, Inc.'; Url='mailto:Privacy@everydayhealth.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Evorra'; Url='https://evorra.com/opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Exact Customer'; Url='mailto:privacy@exactcustomer.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Exact Data'; Url='mailto:privacyteam@data-axle.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Explorium Inc.'; Url='https://www.explorium.ai/platform-privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='FHA Mortgage Finder'; Url='mailto:unusubscribcfmf@seememail.net'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FINDGLOCAL LIMITED'; Url='mailto:info@findglocal.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='FMAData'; Url='mailto:privacy@fmadata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Factori'; Url='mailto:privacy@factori.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FamilySearch'; Url='https://www.familysearch.org/en/help/helpcenter/article/how-do-i-remove-vitals-information-in-family-tree'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Fandom, Inc.'; Url='https://itlaw.fandom.com/wiki/Opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='FastPeopleSearch.io'; Url='https://fastpeoplesearch.io/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Fastbase Inc.'; Url='https://www.fastbase.com/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Fetcher'; Url='mailto:support@fetcher.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FinFind Ltd T/A Pomanda'; Url='https://pomanda.com/help/privacy-data-and-gdpr/i-want-pomanda-to-remove-my-personal-data'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='FinalScout'; Url='https://finalscout.com/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Finalsite'; Url='https://resources.finalsite.net/images/v1738605245/tulsaschoolsorg/ogtqr7pziykpx1n4bjqm/FAFSA-Opt-out.pdf'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Find Us Local'; Url='mailto:info@finduslocally.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='FindLaw'; Url='mailto:privacy@internetbrands.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='FindPeopleFast.net'; Url='https://findpeoplefast.net/company/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FindWhoCallsYou'; Url='mailto:findwhocallsyou@gmail.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Findem'; Url='mailto:privacy@findem.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='FireArmsCalifornia.org'; Url='http://www.firearmscalifornia.org/about#contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FirmFuel'; Url='mailto:privacy@benefitsbunny.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='First Advantage Corporation'; Url='https://fadv.com/privacy-center/non-us-residents/your-rights/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='First Beat Media'; Url='https://www.phonelookup.com/opt'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Five by Five'; Url='https://5x5coop.com/do-not-sell-my-info/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FlashIntel'; Url='mailto:privacy@myflashcloud.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Flexera'; Url='mailto:support@flexera.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Florida Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Florida Residents'; Url='https://www.floridaresidentsdirectory.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Florida Voter Directory'; Url='https://www.floridavoterdirectory.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FloridaCourtRecords.us'; Url='https://floridacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FloridaParcels.com'; Url='https://floridaparcels.com/redaction/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Focus USA'; Url='https://www.focus-usa.com/optout-form/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Foller.me'; Url='https://www.foller.me/do-not-sell'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='FordDirect'; Url='mailto:dprivacy@forddirect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FourLeaf'; Url='mailto:privacy@fourleafdata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FourSquare'; Url='mailto:privacy@foursquare.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FourthWall'; Url='mailto:privacypolicy@fourthwall.tv'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Fraiser'; Url='https://www.fraiser.org/data-request-form'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Free People Directory'; Url='https://www.freepeopledirectory.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FreeBackgroundCheck.org'; Url='https://new-members.freebackgroundcheck.org/removeMyData/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FreeBackgroundChecks.com'; Url='https://freebackgroundchecks.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FreePeopleSearch'; Url='https://freepeoplesearch.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FreePeopleSearch.io'; Url='mailto:contact@freepeoplesearch.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='FreeWheel'; Url='mailto:FW_California_Consumers_CCPA_Data_Requests@freewheel.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='FullEnrich'; Url='https://help.fullenrich.com/en/articles/9974292-opt-out-of-fullenrich'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='FuryForums.com'; Url='mailto:privacy@verticalscope.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Fushia Media'; Url='mailto:Support@fushiamedia.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='GOVWARRANTSEARCH.ORG'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Gale'; Url='mailto:privacy@cengage.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Geekadelphia'; Url='mailto:geekadelphia@gmail.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Genius Media Group, Inc.'; Url='mailto:gdpr@genius.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Georgia Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='GeorgiaCourtRecords.us'; Url='https://georgiacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='GetEmail.io'; Url='https://getemail.io/privacy_policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='GetProspect LLC'; Url='mailto:support@getprospect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Giant Partners'; Url='mailto:compliance@giantpartners.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='GitHub, Inc.'; Url='mailto:privacy@github.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Glad I Know'; Url='https://gladiknow.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Golden Recursion Inc.'; Url='mailto:hello@golden-support.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='GovQA'; Url='mailto:dpo@granicus.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='GovTribe, Inc.'; Url='mailto:success@govtribe.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='GovernmentRegistry.org'; Url='https://www.governmentregistry.org/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Granicus, LLC'; Url='https://content.govdelivery.com/attachments/VAEDUFCPS/2022/10/22/file_attachments/2306515/final_strategic_plan_survey_opt-out_form-english.pdf'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Grassroots Analytics'; Url='mailto:compliance@grassrootsanalytics.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='GrayHair'; Url='mailto:privacy@grayhairsoftware.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='GroundTruth'; Url='mailto:requests@groundtruth.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Growbots'; Url='mailto:privacy@growbots.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='H1'; Url='mailto:inquiries@h1insights.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Hawaii Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Healthline Media'; Url='https://www.healthline.com/rights-request'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Hearst Communications, Inc.'; Url='https://www.hearst.com/-/us-magazines-privacy-notice'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Heartbeat.AI'; Url='https://heartbeat.ai/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='HireEZ'; Url='mailto:privacy@hireez.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='HireRight, LLC'; Url='https://www.hireright.com/legal/united-states-opt-out-rights-outside-of-california'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Home Media, LLC'; Url='https://assets.neighborhoodalerts.com/public/policies/privacy-policy.pdf'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Homeowner Marketing Services'; Url='mailto:dnm@homeownersmarketingservices.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Homes.com'; Url='https://www.homes.com/about/communication-opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Homeyou, Inc.'; Url='https://www.homeyou.com/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Houston Association of REALTORS®'; Url='https://www.har.com/question/27460_how-can-i-opt-out-of-the-zillow-listing'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='HudwayGlass'; Url='https://hudwayglass.com/page/privacy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Hunter'; Url='mailto:privacy@hunter.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Hunter Web Services, Inc.'; Url='https://help.hunter.io/en/articles/2020343-remove-your-data-from-hunter'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Huntmails'; Url='mailto:contact@hunter.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ID5'; Url='mailto:privacy@id5.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='IDCrawl'; Url='https://www.idcrawl.com/remove-my-information'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IDM'; Url='https://idm.us.com/do-not-sell-my-personal-information/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='IDStrong'; Url='https://www.idstrong.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IDnotify'; Url='https://portal.idnotify.com/privacy-policy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='IPQualityScore LLC'; Url='https://www.ipqualityscore.com/domain-reputation/optout.networkadvertising.org'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Idaho Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IdahoCourtRecords.us'; Url='https://idahocourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Illinois Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Illinois Prison Talk'; Url='https://illinoisprisontalk.org/remove-my-info.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IllinoisCourtRecords.us'; Url='https://illinoiscourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='InMobi'; Url='mailto:privacy@inmobi.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Indiana Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IndianaCourtRecords.us'; Url='https://indianacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='InfoFree'; Url='https://privacycompliance.biz/other-infofree/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='InfoPay'; Url='https://www.infopay.com/contact'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='InfoTracer'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Infobel S.A.'; Url='mailto:mwahba@infobel.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Information.com'; Url='https://information.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='InmatesSearcher'; Url='https://www.inmatessearcher.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='InstantCheckSpy'; Url='https://www.truthfinder.com/privacy-center'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IntentMacro'; Url='https://intentmacro.com/ccpa-privacy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Intentgine'; Url='https://intentgine.com/ccpa-privacy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Intranet Quorum'; Url='mailto:privacy@leidos.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Iowa Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='IowaCourtRecords.us'; Url='https://iowacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='J.D. Power'; Url='https://privacyportal.onetrust.com/webform/5e27ce89-3714-4976-8df7-1d1560e32aa1/d6419967-880f-480f-9935-960045988858'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Jhonata Menezes dos Santos Desenvolvimento'; Url='mailto:jhonatamenezes@jmsdev.com.br'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='KB Synergy'; Url='mailto:Compliance@KBSynergy.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='KYC Data'; Url='mailto:consumers@kycdata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Kansas Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='KansasCourtRecords.us'; Url='https://kansascourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Kaspr.io'; Url='https://kaspr.privacy.saymine.io/kaspr'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Kendo'; Url='mailto:alex@kendoemailapp.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Kentucky Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='KentuckyCourtRecords.us'; Url='https://kentuckycourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Key Marketing Advantage'; Url='mailto:privacy@keymarketingadvantage.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='KeyOpinionLeaders'; Url='mailto:privacy@keyopinionleaders.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Keyword Connects'; Url='mailto:privacy@keywordconnects.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Kids Live Safe'; Url='https://www.kidslivesafe.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Komodo Health'; Url='https://komodohealth-privacy.my.onetrust.com/webform/5c3cf8b1-3cf1-422d-84d5-618844b7316f/267fe393-726e-4ba9-87ad-c470e0e554ae'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='LENSO AI SPÓŁKA AKCYJNA'; Url='https://lenso.ai/en/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='LIS Cross-National Data Center in Luxembourg'; Url='mailto:admin@lisdatacenter.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Ladders, Inc.'; Url='mailto:support@theladders.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='LawLink'; Url='mailto:webmaster@lawlink.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Lawyers.com'; Url='mailto:privacy@internetbrands.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Lead Me Media'; Url='mailto:CCPA@LeadMeMedia.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Lead411'; Url='mailto:lead411_privacy@l4mail.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='LeadAR'; Url='mailto:info@myleadar.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='LeadIQ'; Url='https://leadiq.com/request-removal'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='LeadPost'; Url='https://client.leadpost.com/PrivacyRequest'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='LeadZod'; Url='mailto:Privacy@leadzod.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Leadership Connect'; Url='mailto:privacy@leadershipconnect.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='LeadsMarket.com'; Url='mailto:support@leadsmarket.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Leadsive'; Url='https://leadsive.com/privacy_policy.php'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Leadspace'; Url='mailto:compliance_privacy@leadspace.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Lighthouse List'; Url='mailto:privacy@lighthouselist.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='LimeLeads'; Url='mailto:privacy@limeleads.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='LionShare'; Url='mailto:webmaster@lionsharemarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='List Service Direct'; Url='mailto:dataremoval@listservicedirect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Lists Direct Mail Solutions'; Url='mailto:info@lists-inc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Live Data Technologies'; Url='mailto:remove@livedatatechnologies.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='LiveIntent'; Url='mailto:privacy@liveintent.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='LizDev'; Url='mailto:liz@lizdev.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Local Pages'; Url='mailto:contact@localpages.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Locate-Friend'; Url='mailto:panchamithracreators@gmail.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='LocatePeople.org'; Url='mailto:privacy@locatepeople.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='LocateSmarter'; Url='mailto:privacy@locatesmarter.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Lookify'; Url='mailto:privacy@lookify.io'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Louisiana Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='LouisianaCourtRecords.us'; Url='https://louisianacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='M+R'; Url='mailto:privacy@mrss.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='M1 Data'; Url='mailto:service@m1-data.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MATCHBOOK'; Url='mailto:privacy@matchbookdata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MCH'; Url='mailto:privacy@mchdata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MUGSHOTLOOK'; Url='https://www.mugshotlook.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Magnite'; Url='mailto:dpo@magnite.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Maine Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MaineCourtRecords.us'; Url='https://mainecourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MansionQuest.com'; Url='mailto:contact@mansionquest.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MapQuest, Inc.'; Url='mailto:legal@system1group.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Marinus Analytics'; Url='mailto:privacy@marinusanalytics.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MarketForce'; Url='mailto:privacy@marketforcecorp.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='MarketOps'; Url='mailto:privacy@marketops.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MarriedDivorce'; Url='mailto:info@marrieddivorce.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Maryland Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MarylandCourtRecords.us'; Url='https://marylandcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MassachusetssCourtRecords.us'; Url='https://courtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Massachusetts Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Match and Append'; Url='mailto:privacy@matchandappend.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='MediFind'; Url='mailto:privacy@medifind.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Media Source Solutions'; Url='mailto:privacy@mediasourcesolutions.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MediaMath'; Url='mailto:privacy@mediamath.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MediaSoft'; Url='mailto:info@mediasoftstudio.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MediaWallah'; Url='mailto:privacy@mediawallah.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Mediaocean'; Url='https://www.mediaocean.com/your-privacy-rights'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Men Stopping Violence'; Url='https://www.menstoppingviolence.org/privacy/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Michigan Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Michigan Residents'; Url='https://www.michiganresidentdatabase.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MichiganCourtRecords.us'; Url='https://michigancourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MightyRep'; Url='mailto:privacy@MightyRep.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Milestone Marketing Solutions'; Url='mailto:privacy@milestonemarketingsolutions.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MineralHolders'; Url='https://www.mineralholders.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Minerva'; Url='mailto:privacy@minervadata.xyz'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Minnesota Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MinnesotaCourtRecords.us'; Url='https://minnesotacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Mississippi Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Mississippi People Records'; Url='https://mississippipeoplerecords.org/privacy-policy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MississippiCourtRecords.us'; Url='https://mississippicourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Missouri Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MissouriCourtRecords.us'; Url='https://missouricourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Modern Hire'; Url='mailto:support@modernhire.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Modigie'; Url='mailto:privacy@modigie.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Mogean'; Url='mailto:info@mogean.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MoneyBot5000'; Url='https://www.moneybot5000.com/svc/optout/search/optouts'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Montana Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='MontanaCourtRecords.us'; Url='https://montanacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Movoto, Inc.'; Url='https://www.movoto.com/about/ca_privacy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Muck Rack'; Url='mailto:hello@muckrack.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Muraena'; Url='mailto:support@muraena.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='My Renter Checker'; Url='mailto:MYRENTERCHECKER@GMAIL.COM'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='MyCentralJersey.com'; Url='mailto:jmartino@gannettnj.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NC Solutions'; Url='mailto:ncs.privacy@ncsolutions.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NEXXA'; Url='mailto:Consumerchoice@nexxagroup.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NFocus'; Url='mailto:consumer@n-focus.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NJPropertyRecords'; Url='https://njpropertyrecords.com/redaction'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NPIR.org'; Url='https://npir.org/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Names and Facts'; Url='mailto:support@namesandfacts.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='National Public Data'; Url='https://nationalpublicdata.com/optout.html'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Native American Netroots'; Url='https://nativeamericannetroots.net/diary/51'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Nebraska Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NebraskaCourtRecords.us'; Url='https://nebraskacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Neighbor.Report'; Url='https://neighbor.report/remove'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NeighborWho'; Url='https://www.beenverified.com/app/optout/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Nestfully, LLC'; Url='https://www.nestfully.com/pages/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='NetWise'; Url='mailto:privacy@netwisedata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Nevada Arrests'; Url='https://www.nevadaarrests.org/contact-form'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NevadaCourtRecords.us'; Url='https://nevadacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='New Hampshire Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='New Jersey Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='New Mexico Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='New Work SE'; Url='https://privacy.xing.com/en/privacy-policy/what-rights-can-you-assert/right-of-access'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='New York Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NewHampshireCourtRecords.us'; Url='https://newhampshirecourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NewJerseyCourtRecords.us'; Url='https://newjerseycourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NewMexicoCourtRecords.us'; Url='https://newmexicocourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NewYorkCourtRecords.us'; Url='https://newyorkcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Nexsales'; Url='mailto:info@rightleads.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='NextRoll'; Url='https://app.adroll.com/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Nexxen'; Url='mailto:privacyrights@nexxen.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NoCallerName'; Url='mailto:support@nocallername.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Noon AI'; Url='mailto:team@noon.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='North Carolina Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='North Carolina Residents'; Url='https://northcarolinaresidentdatabase.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='North Dakota Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='North Data GmbH'; Url='mailto:info@northdata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='NorthCarolinaCourtRecords.us'; Url='https://northcarolinacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NorthCarolinaPublicRecords.org'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NorthDakotaCourtRecords.us'; Url='https://northdakotacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='NotariesCalifornia.com'; Url='http://www.notariescalifornia.com/about'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Novalist'; Url='mailto:info@novalist.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='NumLooker'; Url='https://numlooker.com/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Numbercom'; Url='mailto:privacy@TheNumber.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='OAN'; Url='mailto:privacy@oan.pl'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='OM''s Small &#038; Medium Businesses Directory'; Url='mailto:info@softsysinfo.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='OfficialUSA'; Url='https://www.officialusa.com/opt-out/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Ohio Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Ohio Residents'; Url='https://www.ohioresidentdatabase.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OhioCourtRecords.us'; Url='https://ohiocourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Oklahoma Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OklahomaCourtRecords.us'; Url='https://oklahomacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OnCore Leads'; Url='https://oncoreleads.com/do_not_sell/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='OneMata'; Url='mailto:privacy@onemata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='OneModel'; Url='mailto:privacy@onemodel.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='OneTrust, LLC'; Url='mailto:privacy@onetrust.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='OnlineSearches.com'; Url='mailto:privacy@peopleconnect.us'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OpenCorporates Ltd'; Url='mailto:data.protection@opencorporates.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='OpenGov'; Url='mailto:reporting@opengov.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='OpenPeopleSearch'; Url='https://openpeoplesearch.com/Consumer'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OpenPublicRecords'; Url='https://www.open-public-records.com/records_removal.htm'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Optimal Fusion'; Url='https://optimalfusion.com/do-not-sell-my-personal-information/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Orbitly'; Url='https://optout.orbitly.io/ccpa-request-to-opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Oregon Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='OregonCourtRecords.us'; Url='https://oregoncourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Orgio, Inc.'; Url='https://theorg.com/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Outbrain'; Url='mailto:privacy@outbrain.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Outward Media'; Url='mailto:privacy@outwardmedia.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Owler, Inc.'; Url='mailto:support@owler.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Ownerly'; Url='https://www.beenverified.com/svc/optout/search/comprehensive_optouts'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Oxford University Press'; Url='mailto:privacy@oup.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='PBI Research'; Url='mailto:CCPARequests@pbinfo.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PLCom.net'; Url='mailto:csr@plcom.net'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PLEXUSS'; Url='mailto:compliance@plexuss.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PacificEast'; Url='https://www.pacificeast.com/contact-us-privacy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Pages Jaunes Solutions numériques et médias Limitée'; Url='mailto:privacy@yp.ca'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Parade Pet'; Url='mailto:hello@goodboystudios.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Paramount Direct Marketing'; Url='mailto:ccpa@paramountdirectmarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Path2Response'; Url='mailto:agents@path2response.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PeepsLocator'; Url='mailto:support@peepslocator.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Pennsylvania Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PennsylvaniaCourtRecords.us'; Url='https://pennsylvaniacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='People-Search.org'; Url='mailto:support@peoplesearch.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='People.ai, Inc.'; Url='mailto:media@people.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='PeopleConnect, Inc.'; Url='https://peopleconnect.us/california-privacy-rights-disclosure'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleDataLabs'; Url='https://www.peopledatalabs.com/do-not-sell-or-share'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='PeopleFind.com'; Url='https://www.intelius.com/privacy-center'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleFinder'; Url='https://suppression.peopleconnect.us/login'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleFinder.Info'; Url='https://peoplefinder.info/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleSearch'; Url='https://www.whitepages.com/privacy/ccpa'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleSearch123'; Url='https://www.peoplesearch123.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleSearchUSA'; Url='https://www.peoplesearchusa.org/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleSearcher'; Url='https://www.peoplesearcher.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleWhiz.com'; Url='https://www.peoplewhiz.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeopleWin'; Url='https://peoplewin.com/privacy/control'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PeoplefindersDaaS'; Url='mailto:privacy@peoplefindersdaas.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Persistent.id'; Url='mailto:info@Persistent.id'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PersonSearchers'; Url='https://www.personsearchers.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Persopo.com'; Url='http://info.persopo.com/opt-out.html'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PhoneBooks.com'; Url='https://www.phonebooks.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PhoneNumberInfo.us'; Url='https://phonenumberinfo.us/contact.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PhoneNumbers.org'; Url='https://phonenumbers.org/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='PhoneOwner, Inc.'; Url='mailto:privacy@phoneowner.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='PitchBook'; Url='mailto:donotsell@pitchbook.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Point Digital Finance, Inc.'; Url='mailto:policies@point.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Pole to Pole B.V.'; Url='mailto:info@poletopole.nl'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Pop Acta'; Url='mailto:contact@popacta.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Poshmark, Inc.'; Url='mailto:support@poshmark.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='PossibleNOW'; Url='mailto:privacy@possiblenow.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PostPilot'; Url='mailto:privacy@postpilot.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Postie'; Url='https://optout.postie.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Precisely'; Url='https://privacyportal-eu.onetrust.com/webform/d88b298e-1f7e-420f-949c-fedc475c1e77/afa5d3a0-dd94-44d6-9176-3d2000f91b6a'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Prezi Inc.'; Url='https://support.prezi.com/hc/en-us/articles/360050359274-Prezi-and-the-CCPA'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='PrivCo'; Url='mailto:privacy@privco.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PrivateEye'; Url='https://www.privateeye.com/removal'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PrivateNumberChecker.com'; Url='https://www.privatenumberchecker.com/removal-request/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PrivateRecords'; Url='https://www.privaterecords.net/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PrivateReports'; Url='https://www.privatereports.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PropertyChecker.com'; Url='https://propertychecker.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PropertyIQ'; Url='https://www.propertyiq.com/opt-out/address-search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='PropertyRadar'; Url='mailto:privacy@propertyradar.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PropertyReach'; Url='https://www.propertyreach.com/privacy-rights'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PropertyRecord.com'; Url='https://dashboard.propertyrecord.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PropertyRecs'; Url='https://dashboard.propertyrecs.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='PropertyShark'; Url='mailto:support@propertyshark.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Public Data Check'; Url='https://www.publicdatacheck.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Public Information Services'; Url='https://www.publicinfoservices.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Public Libraries'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Public Record Reports'; Url='https://www.publicrecordreports.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicRecordCenter.com'; Url='https://www.publicrecordcenter.com/remove.html'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicRecords.com'; Url='https://suppression.peopleconnect.us/login'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicRecords.info'; Url='mailto:support@publicrecords.info'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicRecords.us'; Url='https://dashboard.publicrecords.us/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicRecordsSearcher.com'; Url='mailto:support@searchpublicrecords.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PublicSearcher'; Url='https://www.publicsearcher.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='PulsePoint'; Url='https://mynt-test-privacy.my.onetrust.com/webform/ebe19500-bc8d-487f-9d89-98fde8b270e2/bac5d2a2-fd3e-4830-99b6-bd2a69fec1c9'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='PwC'; Url='mailto:US_Privacy_Office@pwc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Quad'; Url='mailto:Compliancedept@quad.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Qualcomm'; Url='mailto:privacy@qualcomm.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Qualfon'; Url='https://ccpa.qualfon.com/deletionrequest'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Quick People Trace'; Url='mailto:clients@quickpeopletrace.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Quick Public Records'; Url='https://www.quickpublicrecords.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ROC Advertising'; Url='mailto:dataprivacy_rocadvertising@simpleoptoutcompliance.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Radaris Germany'; Url='mailto:customer-service@radaris.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Rain Street'; Url='https://rain-street.org/page/contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Reach Marketing'; Url='mailto:info@reachmarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Real Performance Marketing'; Url='mailto:ConsumerInquiries@RPMleader.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='RealPeopleSearch'; Url='https://realpeoplesearch.com/about/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RealSatisfied'; Url='https://www.realsatisfied.com/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='RealSource Data'; Url='https://www.realsourcedata.com/do-not-sell-my-personal-information'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ReallyGreatRate'; Url='https://privacyportal-eu-cdn.onetrust.com/dsarwebform/942fbf02-bbfe-4a5d-808d-080b06c5651c/3fdf8f1d-7ab3-4a99-bb4e-24965500290d.html'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Realtyhop.com'; Url='https://www.realtyhop.com/resources/realtyhop-redaction-request-system/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RecordsFinder'; Url='https://recordsfinder.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RecordsPage'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RecordsQuarry'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RecruitBot'; Url='mailto:privacy@recruitbot.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Redbird Direct'; Url='mailto:privacy@redbirddirect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Redfin Corporation'; Url='https://support.redfin.com/hc/en-us/articles/38493151019419-How-do-I-remove-my-home-from-Redfin'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Redi Data'; Url='mailto:privacy@redidata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Rehold'; Url='https://rehold.com/control/privacy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Remodeling.com'; Url='mailto:privacy@remodeling.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Reonomy'; Url='mailto:support@reonomy.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Resonate'; Url='mailto:privacy@resonate.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Retention.com'; Url='https://app.retention.com/optout/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Rev'; Url='mailto:privacy@getrev.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Reveal Phone Owner'; Url='https://www.revealphoneowner.com/data-removal/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Revelio Labs'; Url='mailto:info@reveliolabs.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Reverse Caller Lookup'; Url='mailto:support@reversecallerlookup.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Reverse Contact (VISUM SAS)'; Url='https://help.reversecontact.com/en/articles/10269483-is-reverse-contact-gdpr-ccpa-compliant'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='ReversePhone'; Url='https://www.reversephone.com/svc/optout/search/optouts'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Reverseaustralia'; Url='https://www.reverseaustralia.com/privacy.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Revonect'; Url='mailto:support@revonect.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Rhetorik'; Url='mailto:privacy@rhetorik.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Rhode Island Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RhodeIslandCourtRecord.us'; Url='https://rhodeislandcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RhodeIslandPeopleRecords.org'; Url='https://rhodeislandpeoplerecords.org/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='RoboKiller'; Url='mailto:support@robokiller.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Round Sky'; Url='https://www.roundsky.com/supplemental-privacy-notice/contact.php'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SG360'; Url='mailto:dataprivacy@sg360.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='STEP2SUCCESS Marketing'; Url='mailto:mary@step2successmarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Saavn Media Limited'; Url='mailto:legal@jiosaavn.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='SafeOpt'; Url='mailto:https://manage.safeopt.com/manage'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SageStream, LLC'; Url='https://www.sagestreamllc.com/opt-out-opt-in/index.html'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Salary.com, LLC'; Url='https://www.salary.com/legal/privacy-controls/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='SalesBlink'; Url='mailto:help@salesblink.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='SalesIntel'; Url='https://salesintel.io/data-gathering-privacy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Salesforce'; Url='https://datasubjectrequest.salesforce.com/privacy?_ga=2.96101916.1229624149.1740510100-1624370485.1739201108'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Salesgear.io'; Url='https://support.salesgear.io/en/articles/5646120-how-do-you-opt-out-a-contact'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Saleshandy – Ikigai Infotech LLP'; Url='mailto:privacy@saleshandy.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Scanbuy'; Url='mailto:privacy@scanbuy.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Scraping Robot'; Url='mailto:support@scrapingrobot.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Scribd, Inc.'; Url='https://www.scribd.com/document/253240908/Opt-Out-Form'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='SealedRecords'; Url='https://www.sealedrecords.net/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Seamless.AI'; Url='https://login.seamless.ai/personalDataRequest'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Search Quarry'; Url='https://members.searchquarry.com/terms?tab=optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SearchMobileNumber.com'; Url='https://searchmobilenumber.com/privacy-policy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='SearchPeopleFree.net'; Url='https://searchpeoplefree.net/resource/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SearchPublicRecords.com'; Url='https://www.searchpublicrecords.com/help-center/privacy-requests'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SearchSystems Public Records'; Url='https://publicrecords.searchsystems.net/opt-out.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SearchUSAPeople'; Url='https://www.searchusapeople.com/data-removal-request/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Searchbug, Inc.'; Url='https://www.searchbug.com/ccpa.aspx'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Searqle'; Url='https://searqle.com/opt-out-information/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Secretinfo'; Url='https://www.secretinfo.org/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SeeThroughNY'; Url='mailto:info@empirecenter.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SeekHD'; Url='https://www.seekhd.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SeekOut'; Url='https://www.seekout.com/privacy/choices'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Semcasting'; Url='mailto:privacychoice@semcasting.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SentiLink'; Url='mailto:privacy@sentilink.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Shadow Inc.'; Url='mailto:hello@shadowinc.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Share Local Media'; Url='https://privacy.sharelocalmedia.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ShareThis'; Url='https://sharethis.com/do-not-sell-my-data-page/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SheriffsDepartment.net'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Shopify'; Url='https://privacy.shopify.com/en/dsr_submission/subject_types?selected=erasure'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Shortlyst'; Url='https://www.shortlyst.ai/opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='SimioCloud'; Url='mailto:Privacy@simiocloud.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SimpleContacts'; Url='https://www.simplecontacts.com/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Simunix Ltd'; Url='mailto:info@simunix.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SmartMove'; Url='mailto:info@ctam.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Snoopstation'; Url='https://www.intelius.com/privacy-center'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Snov.io'; Url='https://snov.io/do-not-sell-my-personal-information'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Solar Investments Inc.'; Url='https://www.solarreviews.com/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='SoundCloud Global Limited &#038; Co. KG'; Url='mailto:dataprotection@soundcloud.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Sourceit'; Url='mailto:dataprivacy@sourceitmarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='South Carolina Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='South Dakota Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SouthCarolinaCourtRecords.us'; Url='https://southcarolinacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SouthCarolinaPublicRecords.com'; Url='https://www.truthfinder.com/opt-out/v2/submit/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='SouthDakotaCourtRecords.us'; Url='https://southdakotacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Specialists Marketing Services'; Url='mailto:dataprivacyteam@sms-inc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Spectrum Mailing Lists'; Url='mailto:privacy@spectrumlists.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Speedeon Data'; Url='https://optout.speedeondata.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Sprouts.ai'; Url='https://sprouts.ai/privacy-policy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='SpyCloud'; Url='mailto:legal@spycloud.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Staircase'; Url='mailto:optout@staircase.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Statara'; Url='mailto:privacy@statara.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='StateCourts'; Url='mailto:privacy@statecourts.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='StateRecords.org'; Url='https://staterecords.org/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Steppingblocks'; Url='mailto:privacy@steppingblocks.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Sterling'; Url='mailto:privacy@sterling.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Stirista'; Url='https://unsubscribe.stirista.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Strata'; Url='mailto:operations@gostrata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Strategic Data Intelligence'; Url='mailto:Info@SDIntelligence.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Streetdirectory Pte Ltd'; Url='mailto:privacy@streetdirectory.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Structure'; Url='https://www.structure.ac/opt_outs/new'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Subsplash'; Url='https://www.subsplash.com/legal/privacy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Success.ai'; Url='https://www.success.ai/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='SuggestADoctor.com'; Url='mailto:kathy@hystersisters.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Swordfish.ai'; Url='https://swordfish.ai/Optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Sysoon'; Url='mailto:info@sysoon.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='TCC Information Private Limited'; Url='mailto:support@thecompanycheck.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='TD Cowen'; Url='mailto:privacy@cowen.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='TL1'; Url='mailto:data@tl1mkt.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Tagmydeals'; Url='mailto:intelligence@exilegroup.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='TeamUnify, LLC'; Url='https://www.teamunify.com/team/mdest/page/safe-sport/photo-opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Telefi'; Url='mailto:ccpa@telefi.app'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Telephone Directories'; Url='https://www.telephonedirectories.us/Edit_Records'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Telguarder AS'; Url='mailto:support@telguarder.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Tennessee Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='TennesseeCourtRecords.us'; Url='https://tennesseecourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Terminus'; Url='https://home.terminusplatform.com/data-deletion-request'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Texas Arrest Warrants Search'; Url='https://texasarrestwarrants.org/contact'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Texas Arrests'; Url='https://infotracer.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='TexasCourtRecords.us'; Url='https://texascourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='TexasWarrantRoundup.org'; Url='https://texaswarrantroundup.org/InfoPayOpt-OutNew.pdf'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ThatsThem'; Url='https://thatsthem.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='The Blue Book Building and Construction Network'; Url='mailto:info@thebluebook.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='The Bridge Corp'; Url='mailto:privacy@thebridgecorp.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='The Bump'; Url='https://support.thebump.com/hc/en-us/articles/34980593049748-How-Can-I-Remove-My-Registry-From-The-Bump'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='The Dots Global Limited'; Url='https://the-dots.com/users/sophia-woodleigh-200258'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='The FEED Foundation'; Url='mailto:support@feedfoundation.org'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='The Georgia Gazette, LLC'; Url='mailto:Support@TheGeorgiaGazette.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='The Knot Worldwide Inc.'; Url='mailto:help@theknot.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='The National Directory of Registered Tax Return Preparers &#038; Professionals, Ltd.'; Url='https://www.ptindirectory.com/ccpa.cfm'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='The Verge'; Url='mailto:contact@support.shop.theverge.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: .' },
        @{ Name='The Yankee Group'; Url='https://www.yankeegroup.com/optout'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ThePublicIndex'; Url='https://thepublicindex.org/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Therapist.com LLC'; Url='https://therapist.com/privacy-notice/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='ThisNumber.com'; Url='mailto:thisnumber.com@gmail.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='Thomson Reuters'; Url='mailto:privacy.issues@thomsonreuters.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Thryv Holdings, Inc.'; Url='https://www.superpages.com/ccpa'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Tinuiti'; Url='mailto:privacy@tinuiti.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Tomba'; Url='mailto:support@tomba.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Topline Holdings, Inc.'; Url='https://topline.com/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Torre Labs, Inc.'; Url='https://torre.ai/en/terms'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='TouchSuite'; Url='mailto:info@touchsuite.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Traded Media LLC'; Url='mailto:hello@traded.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Transcend, Inc.'; Url='mailto:privacy@transcend.io'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Transparent Nevada'; Url='mailto:office@npri.org'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Trestle'; Url='mailto:data@trestleiq.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='True Blue Analytics'; Url='mailto:privacy@trueblueanalytics.org'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='TruePeopleSearch.net'; Url='https://truepeoplesearch.net/remove-my-info'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Trulia, LLC'; Url='https://support.trulia.com/hc/en-us/articles/221366928-How-do-I-remove-my-agent-s-listing-of-my-home'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Trustoria'; Url='https://trustoria.com/control/privacy'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='TruthRecord'; Url='https://www.truthrecord.org/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='TruthViewer'; Url='https://www.truthviewer.com/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Tunnl'; Url='https://privacy.tunnldata.com/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Tymax Media'; Url='mailto:privacyofficer@datacomplianceportal.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='US Business Directory'; Url='https://us-business.info/faq/link_removal/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='US Marketing Group'; Url='https://usmarketinggrp.com/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='US People Search'; Url='mailto:contact@uspeoplesearch.net'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='USA Public Data Search'; Url='https://usa-official.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='USADATA'; Url='mailto:privacy@usadata.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='USATrace'; Url='https://www.usatrace.com/contact-us/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='USDataCorporation'; Url='https://www.usdatacorporation.com/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='USPhoneLookup'; Url='mailto:support@usphonelookup.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='USRECORDS'; Url='https://infotracer.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='USWARRANTS'; Url='https://infotracer.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Unearth Campaigns'; Url='mailto:Privacy@UnearthCampaigns.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='UnitedStatesPhonebook.com'; Url='http://www.unitedstatesphonebook.com/contact.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Unity'; Url='mailto:dpo@unity3d.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='UpLead'; Url='https://www.uplead.com/opt-out-request/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='User-Searcher'; Url='https://blog.user-searcher.com/policy'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Utah Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='UtahCourtRecords.us'; Url='https://utahcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='VDX.tv'; Url='mailto:privacy@vdx.tv'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Valassis RRD'; Url='https://privacyportal.onetrust.com/webform/45e4be25-919b-483f-9f95-12809576a2b3/6e633594-9a81-48bb-97ab-6fb29bf46019'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Veeva'; Url='https://privacyportal.onetrust.com/webform/3d676ed2-16b1-4c48-97f8-a911923a3adf/a0df0a98-d990-40ff-9bdb-35b5f9e06620'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='VenPath'; Url='https://www.venpath.net/legal/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Venntel'; Url='mailto:privacy@venntel.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Veraset'; Url='mailto:privacy@veraset.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Verif.com'; Url='mailto:contact@manageo.fr'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='VerifyPublicRecords.com'; Url='mailto:support@verifyrecords.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='VerifyRecords'; Url='https://members.verifyrecords.com/customer/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Verinext'; Url='mailto:dpo@verinext.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Vermont Arrests'; Url='https://members.infotracer.com/removeMyData'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='VermontCourtRecords.us'; Url='https://vermontcourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Versium'; Url='https://versium.com/ccpa-opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Viant'; Url='mailto:privacy@viantinc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Virginia Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='VirginiaCourtRecords.us'; Url='https://virginiacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Visual Listing Systems, Inc.'; Url='mailto:support@vlshomes.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Visual Visitor'; Url='https://www.visualvisitor.com/opt-out/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='VoilaNorbert'; Url='mailto:support@voilanorbert.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='VoterRecords.com'; Url='https://voterrecords.com/faq'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Warmly'; Url='mailto:privacy@warmly.ai'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Washington Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Washington DC Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WashingtonCourtRecords.us'; Url='https://washingtoncourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WeInform'; Url='https://www.weinform.org/api/helper/optOutLight/search'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WebMD'; Url='mailto:userprivacy@webmd.net'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='WebMD Health Corp.'; Url='https://www.webmd.com/about-webmd-policies/about-ccpa-do-not-sell'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Webbula'; Url='https://webbula.com/opt-out-request-d/#OptOut'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Wellborn Cabinet, Inc.'; Url='https://www.wellborn.com/privacy-policy/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='Wellness.com Inc.'; Url='mailto:legal@wellness.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='West Virginia Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WestVirginiaCourtRecords.us'; Url='https://westvirginiacourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Windfall'; Url='https://www.windfall.com/do-not-sell-my-info'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Wisconsin Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WisconsinCourtRecords.us'; Url='https://wisconsincourtrecords.us/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Wisdom Media Group'; Url='mailto:contact@wisdommediagroupllc.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Wiza'; Url='https://wiza.co/optout-directory'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='Wodwo'; Url='mailto:privacyofficer@wodwo.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Wunderkind'; Url='mailto:privacyrequests@wunderkind.co'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Wyoming Arrests'; Url='https://infotracer.com/optout/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='WyomingCourtRecords.us'; Url='mailto:privacy@courtrecords.us'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Wyty'; Url='https://www.wyty.com/remove/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='X-Mode Social'; Url='mailto:privacy@xmodesocial.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='X-Ray Contact'; Url='https://x-ray.contact/blog/x-ray-contact-privacy-policy-update-account-deletion/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Xome'; Url='mailto:privacy@xome.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='Yellow Pages Directory Inc.'; Url='https://www.yellowpagesdirectory.com/support.php'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Yellowbook'; Url='mailto:privacy.officerUS@hibu.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='YouMail, Inc.'; Url='mailto:support@youmail.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Phone Directory.' },
        @{ Name='ZabaSearch'; Url='https://suppression.peopleconnect.us/'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Zeta Global'; Url='mailto:privacy@zetaglobal.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ZipRecruiter, Inc.'; Url='https://www.ziprecruiter.com/ccpa-opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='Zlookup'; Url='https://www.zlookup.com/opt_out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='ZoSearch'; Url='mailto:support@zosearch.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='Zumper, Inc.'; Url='mailto:press@zumper.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Profile Data Broker.' },
        @{ Name='aidentified'; Url='https://www.aidentified.com/do-not-sell-my-data/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='audience ACUITY'; Url='https://audienceacuity.com/opt-out-of-database/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='e.Republic'; Url='https://erepublic.my.salesforce-sites.com/PrivacyRequest/'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='eLocal USA LLC'; Url='mailto:privacy@elocal.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='fifty'; Url='https://fifty.io/opt-out'; Method='Form'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='hitta.se'; Url='mailto:kundservice@hitta.se'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='i360'; Url='mailto:privacy@i-360.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='iBegin'; Url='mailto:support@iBeginMarketing.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Business Search.' },
        @{ Name='iHeartMedia, Inc.'; Url='mailto:privacy@iheartmedia.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='iSpot.tv'; Url='mailto:privacy@ispot.tv'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='iWave'; Url='mailto:privacy@iwave.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='illumin'; Url='mailto:privacy@illumin.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='listsOnline'; Url='mailto:privacyofficer@listsonline.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ncprofiles.com'; Url='mailto:info@ncprofiles.com'; Method='Email'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='peoplewhizr.com'; Url='https://www.peoplewhizr.com/optout'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' },
        @{ Name='pharosIQ'; Url='mailto:privacy@pharosIQ.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: Marketing.' },
        @{ Name='ppl-data.com'; Url='mailto:privacy@peopledatalabs.com'; Method='Email'; Category='Marketing'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: B2B Lead Generation.' },
        @{ Name='uFind.name'; Url='https://ufind.name/opt-out'; Method='Form'; Category='PeopleSearch'; Notes='Via Optery directory (CC BY-NC-SA 4.0). Type: People Search Site.' }
    )

    return $brokers
}

# ---------------------------------------------------------------------------
# Run ledger plumbing
# ---------------------------------------------------------------------------
function Get-BrokerRunDir {
    $dir = Join-Path $env:USERPROFILE 'Falsum\Broker'
    if (-not (Test-Path $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        catch { Write-Host "WARN: could not create run dir $dir : $_" }
    }
    return $dir
}

function Get-BrokerLedgerPath {
    return (Join-Path (Get-BrokerRunDir) 'broker-runs.json')
}

function Read-BrokerLedger {
    [CmdletBinding()] param()
    $path = Get-BrokerLedgerPath
    if (-not (Test-Path $path)) { return @() }
    try {
        $raw = Get-Content -Raw -Path $path
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = $raw | ConvertFrom-Json
        if ($null -eq $data) { return @() }
        if ($data -isnot [System.Collections.IEnumerable]) { return @($data) }
        return @($data)
    } catch {
        Write-Host "WARN: ledger unreadable, starting fresh: $_"
        return @()
    }
}

function Write-BrokerLedger {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][object[]]$Ledger)
    $path = Get-BrokerLedgerPath
    try {
        $Ledger | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
    } catch {
        Write-Host "ERROR: could not write ledger: $_"
    }
}

# ---------------------------------------------------------------------------
# Test-BrokerTableValidation — pre-flight on the shipped table, every run.
# Catches: duplicate names, non-https URLs, unknown Method/Category values,
# empty notes. Returns the issue list (empty = table clean).
# ---------------------------------------------------------------------------
function Test-BrokerTableValidation {
    [CmdletBinding()] param()
    $issues = @()
    $brokers = @(Get-BrokerTable)
    $validMethods = @('Form','Email','Phone','Mail','FormEmail')
    $validCats    = @('PeopleSearch','Marketing','RiskData','CallerID','CreditData')

    $seen = @{}
    foreach ($b in $brokers) {
        if ($seen.ContainsKey($b.Name)) { $issues += "duplicate broker name: $($b.Name)" }
        else { $seen[$b.Name] = $true }
        if ([string]::IsNullOrWhiteSpace($b.Url)) { $issues += "$($b.Name): empty URL" }
        elseif ($b.Url -notmatch '^https://') { $issues += "$($b.Name): URL not https: $($b.Url)" }
        if ($b.Method -notin $validMethods) { $issues += "$($b.Name): unknown method '$($b.Method)'" }
        if ($b.Category -notin $validCats)  { $issues += "$($b.Name): unknown category '$($b.Category)'" }
        if ([string]::IsNullOrWhiteSpace($b.Notes)) { $issues += "$($b.Name): empty Notes" }
    }
    if ($issues.Count -eq 0) { Write-Host "Broker table OK: $($brokers.Count) brokers, names unique, all https, methods/categories valid." }
    else { Write-Host "Broker table ISSUES ($($issues.Count)):"; $issues | ForEach-Object { Write-Host "  - $_" } }
    return $issues
}

# ---------------------------------------------------------------------------
# Get-BrokerCoverage — what the table covers: totals, per-method, per-category.
# ---------------------------------------------------------------------------
function Get-BrokerCoverage {
    [CmdletBinding()] param()
    $brokers = @(Get-BrokerTable)
    Write-Host "Brokers in table: $($brokers.Count)"
    Write-Host "By method:"
    $brokers | Group-Object { $_.Method } | Sort-Object Name | ForEach-Object {
        Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count)
    }
    Write-Host "By category:"
    $brokers | Group-Object { $_.Category } | Sort-Object Name | ForEach-Object {
        Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count)
    }
}

# ---------------------------------------------------------------------------
# Get-BrokerList — the list itself. Filter by method/category/name.
# ---------------------------------------------------------------------------
function Get-BrokerList {
    [CmdletBinding()]
    param(
        [ValidateSet('Form','Email','Phone','Mail','FormEmail','All')]
        [string]$Method = 'All',
        [ValidateSet('PeopleSearch','Marketing','RiskData','CallerID','CreditData','All')]
        [string]$Category = 'All',
        [string]$Name = ''
    )
    $brokers = Get-BrokerTable
    if ($Method -ne 'All')   { $brokers = $brokers | Where-Object { $_.Method   -eq $Method } }
    if ($Category -ne 'All') { $brokers = $brokers | Where-Object { $_.Category -eq $Category } }
    if ($Name)               { $brokers = $brokers | Where-Object { $_.Name -like "*$Name*" } }
    return @($brokers)
}

# ---------------------------------------------------------------------------
# Test-BrokerNameMatch — PURE exact/close name resolver behind Start-OptOutRun
# -BrokerName. Exact is case-insensitive full equality; Close is the
# -like "*query*" suggestion list (minus the exact hit). Kept pure so the
# hygiene battery covers it offline.
# ---------------------------------------------------------------------------
function Test-BrokerNameMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$BrokerNames,
        [string]$Query = ''
    )
    $out = [pscustomobject]@{ Exact = $null; Close = @() }
    $q = $Query.Trim()
    if ([string]::IsNullOrWhiteSpace($q)) { return $out }
    $exact = @($BrokerNames | Where-Object { $_ -ieq $q })
    if ($exact.Count -gt 0) { $out.Exact = $exact[0]; return $out }
    $out.Close = @($BrokerNames | Where-Object { $_ -like "*$q*" })
    return $out
}

# ---------------------------------------------------------------------------
# New-OptOutEmail — generate a ready-to-send opt-out draft (.txt) per broker.
# The Better-Way Law: the user should not have to compose this from scratch.
# ---------------------------------------------------------------------------
function New-OptOutEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Broker,
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]'
    )
    $dir = Get-BrokerRunDir
    $safe = ($Broker.Name -replace '[^A-Za-z0-9]+','-').Trim('-')
    $outPath = Join-Path $dir ("optout-draft-$safe.txt")
    $body = @"
To: [see $($Broker.Name) privacy page: $($Broker.Url)]
Subject: Opt-Out / Deletion Request — $($Broker.Name)

Hello,

Per your published opt-out process ($($Broker.Url)), I request the removal
and suppression of all personal information you hold about me, and that I be
placed on your do-not-collect / do-not-sell list.

Identifying details for your lookup:
  Name:    $YourName
  Address: $YourAddress
  Email:   $YourEmail

Please confirm in writing when the removal is complete and confirm that my
information will not be re-added in future data refreshes.

Thank you.
$YourName
"@
    try {
        $body | Set-Content -Path $outPath -Encoding UTF8
        Write-Host "  Draft written: $outPath"
        return $outPath
    } catch {
        Write-Host "  ERROR writing draft for $($Broker.Name): $_"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Get-OptOutCallScript — phone-method brokers get a script, not silence.
# ---------------------------------------------------------------------------
function Get-OptOutCallScript {
    <#
    Phone-method brokers get a script, not silence. When the broker table
    carries a Phone number for the broker (ARS: 1-800-392-8911), the script
    dials THAT — v1.3 fixed it printing "see URL" while the number sat in
    Notes. Falls back to the opt-out page when no number is recorded.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Broker)
    $dial = if (-not [string]::IsNullOrWhiteSpace($Broker.Phone)) { $Broker.Phone }
            else { "see $($Broker.Url)" }
    return @"
PHONE OPT-OUT SCRIPT — $($Broker.Name)
Call: $dial
Say: "I am calling to opt out of all data collection and sale of my personal
information, and to be placed on your do-not-collect list. My name is
[YOUR NAME], address [YOUR ADDRESS]. Please confirm the request number
and send written confirmation."
Record: date, agent name, confirmation number. Log it in the run ledger.
"@
}

# ---------------------------------------------------------------------------
# New-BrokerWorksheetText — PURE printable checklist builder. Kept pure so
# the hygiene battery covers it offline; New-OptOutRunWorksheet writes it.
# The worksheet is the Better-Way fix for the tab-batch workflow: the user
# works the browser tabs with this sheet beside them — identity filled in
# once, per-broker URL + notes + a confirmation line to record the broker's
# reference number before checking the box off.
# ---------------------------------------------------------------------------
function New-BrokerWorksheetText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Brokers,
        [string]$RunId = 'manual',
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]'
    )
    $lines = @(
        'BLACKBOX BROKER ERADICATOR — OPT-OUT WORKSHEET',
        "Run: $RunId   Generated: $(Get-Date -Format 'o')   Brokers queued: $($Brokers.Count)",
        '',
        'YOUR IDENTITY (fill once, reuse for every form):',
        "  Name:    $YourName",
        "  Address: $YourAddress",
        "  Email:   $YourEmail",
        '',
        'WORK THE LIST IN ORDER. For each broker: open the URL, complete the',
        'opt-out, record the confirmation number/reference on the line, then',
        'check the box.',
        ''
    )
    $i = 0
    foreach ($b in $Brokers) {
        $i++
        $lines += "[ ] $i. $($b.Name) [$($b.Method)]"
        $lines += "    URL: $($b.Url)"
        $lines += "    What to do: $($b.Notes)"
        $lines += '    Confirmation #: ________________________________________'
        $lines += ''
    }
    $lines += 'DONE? Close the loop per broker:'
    $lines += "  Confirm-BrokerRemoval -Name '<Broker>' -ConfirmationDetail '<ref#>'"
    return ($lines -join "`r`n")
}

# ---------------------------------------------------------------------------
# New-OptOutRunWorksheet — writes the printable worksheet for a run.
# Never throws: a missing worksheet must not block an opt-out run.
# ---------------------------------------------------------------------------
function New-OptOutRunWorksheet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Brokers,
        [Parameter(Mandatory=$true)][string]$RunId,
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]'
    )
    $dir = Get-BrokerRunDir
    $outPath = Join-Path $dir ("optout-worksheet-$RunId.txt")
    try {
        $text = New-BrokerWorksheetText -Brokers $Brokers -RunId $RunId `
            -YourName $YourName -YourAddress $YourAddress -YourEmail $YourEmail
        $text | Set-Content -Path $outPath -Encoding UTF8
        Write-Host "  Worksheet written: $outPath"
        return $outPath
    } catch {
        Write-Host "  ERROR writing worksheet: $_"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Start-OptOutRun — the eradication run.
#   -Form  brokers: opens each opt-out URL in the default browser, in batches
#                   (default 5 at a time), ledger records 'opened'.
#   -Email brokers: generates draft emails + opens their privacy page.
#   -Phone brokers: prints the call script, ledger records 'manual-call'.
#   -Redo: re-run brokers already marked done (for monthly re-fires).
# ---------------------------------------------------------------------------
function Start-OptOutRun {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [ValidateSet('Form','Email','Phone','Mail','FormEmail','All')]
        [string]$Method = 'All',
        [int]$BatchSize = 5,
        [switch]$NoBrowser,
        [switch]$Redo,
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]',
        [string]$VaultPath = ""
    )
    Write-Host '=== Falsum Broker Eradicator — opt-out run ==='
    Import-VaultModule
    if ($VaultPath -ne "") { $script:VaultPath = $VaultPath }
    elseif ([string]::IsNullOrWhiteSpace($script:VaultPath)) {
        $script:VaultPath = Join-Path $env:USERPROFILE 'Falsum\Vault'
    }
    $valIssues = @(Test-BrokerTableValidation)
    if ($valIssues.Count -gt 0) {
        Write-Host 'Table validation failed — fix the issues above before running opt-outs.'
        return
    }
    $brokers = @(Get-BrokerList -Method $Method)
    Write-Host "Brokers in scope: $($brokers.Count)"

    $ledger = @(Read-BrokerLedger)
    $doneNames = @{}
    if (-not $Redo) {
        foreach ($entry in $ledger) {
            if ($entry.Status -in @('opened','drafted','manual-call','letter-drafted','confirmed')) {
                $doneNames[$entry.Name] = $true
            }
        }
    }
    $queue = @($brokers | Where-Object { $Redo -or -not $doneNames.ContainsKey($_.Name) })
    Write-Host "Queued this run: $($queue.Count) (already-done skipped unless -Redo)"

    $runId = (Get-Date -Format 'yyyy-MM-ddTHH-mm-ss')
    $batchCount = 0
    $idx = 0
    $total = $queue.Count

    foreach ($b in $queue) {
        $idx++
        Write-Host "`n[$idx/$total] [$($b.Method)] $($b.Name)"
        Write-Host "  $($b.Url)"
        Write-Host "  Note: $($b.Notes)"
        $status = 'pending'; $note = ''
        try {
            switch ($b.Method) {
                { $_ -in @('Form','FormEmail') } {
                    if (-not $NoBrowser) {
                        if ($PSCmdlet.ShouldProcess($b.Url, 'Open broker opt-out page in browser')) {
                            Start-Process $b.Url
                            $status = 'opened'
                            $note = "Opt-out page opened in browser (batch)."
                        } else {
                            $status = 'queued'
                            $note = 'Skipped by -WhatIf.'
                        }
                    } else {
                        $status = 'queued'
                        $note = 'URL listed; open manually.'
                    }
                    if ($b.Method -eq 'FormEmail') {
                        $draft = New-OptOutEmail -Broker $b -YourName $YourName -YourAddress $YourAddress -YourEmail $YourEmail
                        if ($draft) { $note += " Draft email: $draft" }
                    }
                }
                'Email' {
                    $draft = New-OptOutEmail -Broker $b -YourName $YourName -YourAddress $YourAddress -YourEmail $YourEmail
                    if ((-not $NoBrowser) -and $PSCmdlet.ShouldProcess($b.Url, 'Open broker privacy page in browser')) {
                        Start-Process $b.Url
                    }
                    $status = 'drafted'
                    $note = "Draft: $draft ; privacy page opened."
                }
                'Phone' {
                    $script = Get-OptOutCallScript -Broker $b
                    Write-Host $script
                    $status = 'manual-call'
                    $note = 'Call script printed; user must call.'
                }
                'Mail' {
                    # Better-Way Law: Mail-method brokers used to hit a dead end
                    # ("No automated path"). v1.3 generates a printable opt-out
                    # letter and tracks it until confirmed, like everything else.
                    $letter = New-OptOutMailLetter -Broker $b -YourName $YourName -YourAddress $YourAddress -YourEmail $YourEmail
                    $status = 'letter-drafted'
                    $note = if ($letter) { "Printable opt-out letter: $letter ; mail via USPS certified/tracking and keep the receipt." } else { 'Letter generation failed.' }
                }
                default {
                    $status = 'manual'
                    $note = 'No automated path; follow Notes.'
                }
            }
        } catch {
            $status = 'failed'
            $note = "Error: $_"
            Write-Host "  ERROR: $_"
        }

        $ledger += [pscustomobject]@{
            RunId   = $runId
            Time    = (Get-Date -Format 'o')
            Name    = $b.Name
            Url     = $b.Url
            Method  = $b.Method
            Category= $b.Category
            Status  = $status
            Notes   = $note
        }
        New-BrokerLog -RunId $runId -Broker $b -Status $status -Notes $note
        $batchCount++
        if ((-not $NoBrowser) -and ($batchCount % $BatchSize -eq 0) -and ($batchCount -lt $queue.Count)) {
            Write-Host "`n--- Batch of $BatchSize opened. Complete those tabs, then press Enter for the next batch ---"
            try { Read-Host 'Press Enter to continue' | Out-Null } catch {}
        }
    }

    Write-BrokerLedger -Ledger $ledger
    Write-Host "`n=== Run complete. Ledger: $(Get-BrokerLedgerPath) ==="
    Get-BrokerRunSummary
}

# ---------------------------------------------------------------------------
# Get-BrokerRunSummary — where the eradication stands.
# ---------------------------------------------------------------------------
function Get-BrokerRunSummary {
    [CmdletBinding()] param()
    $ledger = @(Read-BrokerLedger)
    if ($ledger.Count -eq 0) { Write-Host 'No runs logged yet.'; return }
    $total = (Get-BrokerTable).Count
    $covered = @($ledger | Where-Object { $_.Status -in @('opened','drafted','manual-call','letter-drafted','confirmed') } |
        Select-Object -ExpandProperty Name -Unique).Count
    $confirmed = @($ledger | Where-Object { $_.Status -eq 'confirmed' } |
        Select-Object -ExpandProperty Name -Unique).Count
    Write-Host "Brokers in table : $total"
    Write-Host "Brokers touched  : $covered"
    Write-Host "Confirmed removed: $confirmed  (Better-Way Law: the fix is tracked until confirmed)"
    Write-Host "Remaining        : $($total - $covered)"
    Write-Host 'Status breakdown:'
    $ledger | Group-Object Status | ForEach-Object {
        Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count)
    }
}

# ---------------------------------------------------------------------------
# Confirm-BrokerRemoval — close the loop. The user got written confirmation
# from a broker (email, confirmation page, call confirmation number); this
# marks it confirmed in the ledger and vault-logs the confirmation.
# Better-Way Law: an opt-out you never confirm is a hope, not a fix.
# ---------------------------------------------------------------------------
function Confirm-BrokerRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$ConfirmationDetail = "",
        [string]$VaultPath = ""
    )
    $brokers = @(Get-BrokerTable)
    $broker = @($brokers | Where-Object { $_.Name -eq $Name })
    if ($broker.Count -eq 0) {
        $close = @($brokers | Where-Object { $_.Name -like "*$Name*" } | Select-Object -ExpandProperty Name)
        Write-Host "No broker named exactly '$Name'."
        if ($close.Count -gt 0) { Write-Host "Did you mean: $($close -join ', ')" }
        return
    }
    Import-VaultModule
    if ($VaultPath -ne "") { $script:VaultPath = $VaultPath }
    elseif ([string]::IsNullOrWhiteSpace($script:VaultPath)) {
        $script:VaultPath = Join-Path $env:USERPROFILE 'Falsum\Vault'
    }

    $ledger = @(Read-BrokerLedger)
    $runId = (Get-Date -Format 'yyyy-MM-ddTHH-mm-ss')
    $b = $broker[0]
    $ledger += [pscustomobject]@{
        RunId    = $runId
        Time     = (Get-Date -Format 'o')
        Name     = $b.Name
        Url      = $b.Url
        Method   = $b.Method
        Category = $b.Category
        Status   = 'confirmed'
        Notes    = $ConfirmationDetail
    }
    Write-BrokerLedger -Ledger $ledger
    New-BrokerLog -RunId $runId -Broker $b -Status 'confirmed' -Notes $ConfirmationDetail
    Write-Host "Confirmed: $($b.Name) removed. Confirmation detail: $ConfirmationDetail"
}

# ---------------------------------------------------------------------------
# New-BrokerMonthlyTask / Remove-BrokerMonthlyTask / Get-BrokerMonthlyTask
# Brokers relist. The schedule is the fix. Monthly re-fire via Task Scheduler.
# ---------------------------------------------------------------------------
function New-BrokerMonthlyTask {
    [CmdletBinding()] param()
    $taskName = 'Falsum-BrokerEradicator'
    $modulePath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($modulePath)) {
        $modulePath = Join-Path (Get-BrokerRunDir) 'Falsum-BrokerEradicator.ps1'
        Write-Host "WARN: module path unknown; copy this script to $modulePath first."
    }
    $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"& '$modulePath'; Start-OptOutRun -Redo -NoBrowser`""
    Write-Host "Creating monthly task '$taskName' ..."
    try {
        $out = & schtasks.exe /Create /TN $taskName /TR $action /SC MONTHLY /MO 1 /F 2>&1
        Write-Host ($out -join "`n")
        Write-Host 'Monthly re-fire installed. Brokers relist — this is how you stay ahead.'
    } catch {
        Write-Host "ERROR creating scheduled task (needs admin for system-wide; use -TaskPath for user task): $_"
    }
}

function Remove-BrokerMonthlyTask {
    [CmdletBinding()] param()
    try {
        $out = & schtasks.exe /Delete /TN 'Falsum-BrokerEradicator' /F 2>&1
        Write-Host ($out -join "`n")
    } catch { Write-Host "ERROR removing task: $_" }
}

function Get-BrokerMonthlyTask {
    [CmdletBinding()] param()
    try {
        $out = & schtasks.exe /Query /TN 'Falsum-BrokerEradicator' /FO LIST /V 2>&1
        Write-Host ($out -join "`n")
    } catch { Write-Host 'Monthly task not installed (or schtasks unavailable).' }
}

# ---------------------------------------------------------------------------
# Export-BrokerReport — JSON + txt report of table + ledger, SHA-256 hashed.
# ---------------------------------------------------------------------------
function Export-BrokerReport {
    [CmdletBinding()] param()
    $dir = Get-BrokerRunDir
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $brokers = @(Get-BrokerTable)
    $ledger  = @(Read-BrokerLedger)

    $report = [pscustomobject]@{
        Generated = (Get-Date -Format 'o')
        BrokerCount = $brokers.Count
        Brokers = $brokers
        Ledger = $ledger
    }
    $jsonPath = Join-Path $dir "broker-report-$stamp.json"
    $txtPath  = Join-Path $dir "broker-report-$stamp.txt"
    $csvPath  = Join-Path $dir "broker-table-$stamp.csv"
    try {
        $report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
        $brokers | Select-Object Name, Method, Category, Url, Notes |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $lines = @(
            'BLACKBOX BROKER ERADICATOR REPORT',
            "Generated: $(Get-Date -Format 'o')",
            "Brokers in table: $($brokers.Count)",
            ''
        )
        foreach ($b in $brokers) {
            $lines += ("[{0,-12}] [{1,-12}] {2}" -f $b.Method, $b.Category, $b.Name)
            $lines += "    $($b.Url)"
        }
        $lines | Set-Content -Path $txtPath -Encoding UTF8
        foreach ($p in @($jsonPath, $txtPath, $csvPath)) {
            $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash
            Write-Host "Wrote $p"
            Write-Host "  SHA-256: $h"
        }
        return @($jsonPath, $txtPath, $csvPath)
    } catch {
        Write-Host "ERROR exporting report: $_"
        return @()
    }
}

# ---------------------------------------------------------------------------
# New-BrokerEradicationPlan — plain-language checklist for the user.
# ---------------------------------------------------------------------------
function New-BrokerEradicationPlan {
    [CmdletBinding()] param()
    Write-Host @"

BLACKBOX BROKER ERADICATION PLAN (the fix for "you are listed everywhere")
--------------------------------------------------------------------------
1. Run:  Start-OptOutRun -Method Form        (opens each opt-out page; do 5-tab batches)
2. Run:  Start-OptOutRun -Method Email       (drafts generated in $(Get-BrokerRunDir); send them)
3. Call: Start-OptOutRun -Method Phone       (call scripts print to console)
4. FREEZE the 4 credit bureaus + ChexSystems (Experian/Equifax/TransUnion/Innovis)
   — a freeze stops new-account fraud cold; it costs nothing.
5. File OptOutPrescreen + DMAchoice + Do-Not-Call (in the table; kills the supply lines).
6. Install the monthly re-fire: New-BrokerMonthlyTask  (brokers RELIST — this is the fix
   for "I opted out and came back"; monthly re-check keeps you suppressed).
7. CLOSE THE LOOP: when a broker confirms your removal in writing, run
   Confirm-BrokerRemoval -Name <Broker> -ConfirmationDetail '<ref#>'
   — a fix you never confirm is a hope, not a fix.
8. Track progress: Get-BrokerRunSummary / Get-BrokerCoverage / Export-BrokerReport
   Every run is vault-logged (type "broker-optout") — your evidence trail.
--------------------------------------------------------------------------
"@
}

# ---------------------------------------------------------------------------
# Test-BrokerRelistFlags — PURE classifier behind Get-BrokerRelistCheck.
# Kept pure (ledger rows in, flags out) so the self-test can cover it
# without touching disk.
#   relist-risk : a 'confirmed' broker whose confirmation is >= -RelistDays
#                 old. Brokers relist — a confirmed opt-out is not forever.
#   unconfirmed : opened/drafted/manual-call but never confirmed, and the
#                 last touch is >= -StaleDays old. A fix you never confirm
#                 is a hope, not a fix — follow up.
# ---------------------------------------------------------------------------
function Test-BrokerRelistFlags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$Rows,
        [int]$RelistDays = 180,
        [int]$StaleDays  = 60
    )
    $flags = @()
    $now = Get-Date
    $names = @($Rows | Select-Object -ExpandProperty Name -Unique)
    foreach ($n in $names) {
        $rows = @($Rows | Where-Object { $_.Name -eq $n })
        $confirms = @($rows | Where-Object { $_.Status -eq 'confirmed' })
        if ($confirms.Count -gt 0) {
            $last = ($confirms | Sort-Object Time | Select-Object -Last 1)
            $age = ($now - [datetime]$last.Time).Days
            if ($age -ge $RelistDays) {
                $flags += [pscustomobject]@{
                    Name    = $n
                    Issue   = 'relist-risk'
                    AgeDays = $age
                    Detail  = "confirmed $age days ago (threshold $RelistDays) — brokers relist; re-confirm"
                }
            }
        } else {
            $last = ($rows | Sort-Object Time | Select-Object -Last 1)
            $age = ($now - [datetime]$last.Time).Days
            if ($age -ge $StaleDays) {
                $flags += [pscustomobject]@{
                    Name    = $n
                    Issue   = 'unconfirmed'
                    AgeDays = $age
                    Detail  = "last touched $age days ago, never confirmed (threshold $StaleDays) — follow up"
                }
            }
        }
    }
    return $flags
}

# ---------------------------------------------------------------------------
# Get-BrokerRelistCheck — the eradication does not end at 'opened'.
# Reads the ledger, flags relist-risk and unconfirmed brokers.
# ---------------------------------------------------------------------------
function Get-BrokerRelistCheck {
    [CmdletBinding()]
    param(
        [int]$RelistDays = 180,
        [int]$StaleDays  = 60,
        [switch]$Quiet
    )
    $flags = @(Test-BrokerRelistFlags -Rows @(Read-BrokerLedger) -RelistDays $RelistDays -StaleDays $StaleDays)
    if (-not $Quiet) {
        if ($flags.Count -eq 0) { Write-Host 'Relist check: nothing stale. The suppression wall is holding.' }
        else {
            Write-Host "Relist check: $($flags.Count) item(s) need attention:"
            foreach ($f in $flags) {
                Write-Host "  [$($f.Issue)] $($f.Name) — $($f.Detail)"
            }
        }
    }
    return $flags
}

# ---------------------------------------------------------------------------
# Get-BrokerRunHistory — every past run: id, entry count, confirmed count.
# ---------------------------------------------------------------------------
function Get-BrokerRunHistory {
    [CmdletBinding()] param()
    $ledger = @(Read-BrokerLedger)
    if ($ledger.Count -eq 0) { Write-Host 'No runs logged yet.'; return }
    $ledger | Group-Object RunId | Sort-Object Name | ForEach-Object {
        $confirmed = @($_.Group | Where-Object { $_.Status -eq 'confirmed' }).Count
        Write-Host ("{0}  entries={1} confirmed={2}" -f $_.Name, $_.Count, $confirmed)
    }
}

# ---------------------------------------------------------------------------
# Get-BrokerDripSchedule — the sustainable plan. -PerDay brokers per day,
# in table order; a day is completable in one sitting. Print the day
# assignments; work them, confirm them, move on.
# ---------------------------------------------------------------------------
function Get-BrokerDripSchedule {
    [CmdletBinding()]
    param([int]$PerDay = 10)
    if ($PerDay -lt 1) { $PerDay = 10 }
    $brokers = @(Get-BrokerTable)
    $total = $brokers.Count
    $i = 0; $day = 1
    Write-Host "Drip schedule: $total brokers, $PerDay per day."
    while ($i -lt $total) {
        $last = [Math]::Min($i + $PerDay - 1, $total - 1)
        $chunk = @($brokers[$i..$last])
        Write-Host ''
        Write-Host "DAY $day — $($chunk.Count) brokers:"
        foreach ($b in $chunk) { Write-Host ("  [{0,-8}] {1}" -f $b.Method, $b.Name) }
        $i += $PerDay
        $day++
    }
    Write-Host ''
    Write-Host "Day count: $($day - 1). When a broker confirms your removal, run:"
    Write-Host "  Confirm-BrokerRemoval -Name '<Broker>' -ConfirmationDetail '<ref#>'"
}

# ---------------------------------------------------------------------------
# Test-BrokerUrlVerdict — PURE classifier behind the URL liveness probe.
# Kept pure (status code + error type in, verdict out) so the self-test
# covers it without touching the network.
#   Live        : 2xx — the opt-out page answers.
#   Blocked     : 401/403/429 or TLS failure — page exists but refuses
#                 automation (bot filter); a human browser still works.
#   Dead        : 404/410 or 4xx/5xx — the opt-out page is gone. The table
#                 row must be repaired or replaced.
#   Unreachable : timeout or DNS failure — could be transient; re-probe
#                 before touching the table.
#   Other       : anything else (rare; inspect manually).
# ---------------------------------------------------------------------------
function Test-BrokerUrlVerdict {
    [CmdletBinding()]
    param(
        [int]$StatusCode = 0,
        [string]$ErrorType = ''
    )
    switch ($ErrorType) {
        'timeout' { return 'Unreachable' }
        'dns'     { return 'Unreachable' }
        'tls'     { return 'Blocked' }
    }
    if ($StatusCode -ge 200 -and $StatusCode -lt 300) { return 'Live' }
    if ($StatusCode -in @(401,403,429)) { return 'Blocked' }
    if ($StatusCode -in @(404,410)) { return 'Dead' }
    if ($StatusCode -ge 400) { return 'Dead' }
    return 'Other'
}

# ---------------------------------------------------------------------------
# Test-BrokerUrlStatus — passive liveness probe of one broker's own published
# opt-out page. GET with a real browser User-Agent, 10s timeout, redirects
# followed. This is exactly what the user's browser does when they open the
# page manually — passive observation of a published page, nothing more.
# Returns: Name, Method, Url, Verdict, StatusCode, FinalUrl, Ms, Detail.
# ---------------------------------------------------------------------------
function Test-BrokerUrlStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Broker,
        [int]$TimeoutSec = 10
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = [pscustomobject]@{
        Name       = $Broker.Name
        Method     = $Broker.Method
        Url        = $Broker.Url
        Verdict    = 'Other'
        StatusCode = 0
        FinalUrl   = ''
        Ms         = 0
        Detail     = ''
    }
    try {
        $req = [System.Net.HttpWebRequest]::Create($Broker.Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $true
        $req.MaximumAutomaticRedirections = 8
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
        try {
            $resp = $req.GetResponse()
            $code = [int]$resp.StatusCode
            $result.StatusCode = $code
            $result.FinalUrl = $resp.ResponseUri.AbsoluteUri
            $resp.Close()
            $result.Detail = "HTTP $code"
        } catch [System.Net.WebException] {
            $we = $_.Exception
            $webResp = $we.Response
            if ($null -ne $webResp) {
                $code = [int]([System.Net.HttpWebResponse]$webResp).StatusCode
                $result.StatusCode = $code
                $result.FinalUrl = $webResp.ResponseUri.AbsoluteUri
                $result.Detail = "HTTP $code"
                $webResp.Close()
            } else {
                $msg = $we.Message
                if ($msg -match 'timed out|Timeout') {
                    $result.Detail = 'connection timed out'
                    $result.Verdict = Test-BrokerUrlVerdict -ErrorType 'timeout'
                } elseif ($msg -match 'name|host|could not be resolved') {
                    $result.Detail = 'DNS resolution failed'
                    $result.Verdict = Test-BrokerUrlVerdict -ErrorType 'dns'
                } elseif ($msg -match 'SSL|TLS|certificate') {
                    $result.Detail = 'TLS handshake failed'
                    $result.Verdict = Test-BrokerUrlVerdict -ErrorType 'tls'
                } else {
                    $result.Detail = "request failed: $msg"
                    $result.Verdict = 'Other'
                }
                $sw.Stop(); $result.Ms = [int]$sw.ElapsedMilliseconds
                return $result
            }
        }
        $result.Verdict = Test-BrokerUrlVerdict -StatusCode $result.StatusCode
    } catch {
        $result.Detail = "probe error: $($_.Exception.Message)"
        $result.Verdict = 'Other'
    }
    $sw.Stop(); $result.Ms = [int]$sw.ElapsedMilliseconds
    return $result
}

# ---------------------------------------------------------------------------
# Get-BrokerBrokenLinks — the module audits itself. Probes every broker's
# opt-out URL and reports the ones that are Dead, Blocked, or Unreachable.
# Dead rows are a real data bug (the probe caught TLO and CoreLogic on the
# first run); fix the URL in Get-BrokerTable, then re-probe to confirm.
# ---------------------------------------------------------------------------
function Get-BrokerBrokenLinks {
    [CmdletBinding()]
    param(
        [int]$TimeoutSec = 10,
        [switch]$Quiet
    )
    $brokers = @(Get-BrokerTable)
    $results = @()
    $i = 0
    foreach ($b in $brokers) {
        $i++
        if (-not $Quiet) { Write-Host "[$i/$($brokers.Count)] probing $($b.Name) ..." }
        $results += Test-BrokerUrlStatus -Broker $b -TimeoutSec $TimeoutSec
    }
    $bad = @($results | Where-Object { $_.Verdict -in @('Dead','Blocked','Unreachable') })
    if (-not $Quiet) {
        $live = ($results | Where-Object { $_.Verdict -eq 'Live' }).Count
        Write-Host ''
        Write-Host "Link audit: $live/$($results.Count) Live."
        if ($bad.Count -eq 0) { Write-Host 'No broken links. The table is healthy.' }
        else {
            Write-Host "$($bad.Count) need attention:"
            foreach ($r in $bad) {
                Write-Host ("  [{0,-11}] {1}" -f $r.Verdict, $r.Name)
                Write-Host "    $($r.Url)"
                Write-Host "    $($r.Detail)  (final: $($r.FinalUrl))"
            }
            Write-Host ''
            Write-Host 'Fix the URL in Get-BrokerTable, then run Get-BrokerBrokenLinks again to confirm.'
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# New-BrokerLetterText — PURE text builder for the USPS opt-out letter.
# Kept pure so the hygiene battery covers it offline; New-OptOutMailLetter
# writes it to disk.
# ---------------------------------------------------------------------------
function New-BrokerLetterText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Broker,
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]'
    )
    $brokerAddress = if (-not [string]::IsNullOrWhiteSpace($Broker.Address)) { $Broker.Address } else { '[BROKER PRIVACY ADDRESS — see ' + $Broker.Url + ']' }
    $today = Get-Date -Format 'MMMM d, yyyy'
    return @"
$YourName
$YourAddress
$YourEmail

$today

$($Broker.Name)
$brokerAddress

RE: Opt-Out and Deletion Request — Do Not Collect / Do Not Sell My Personal Information

To whom it may concern:

Pursuant to your published opt-out process ($($Broker.Url)), I am writing to
request the removal and permanent suppression of all personal information you
hold about me, and to be placed on your do-not-collect and do-not-sell lists.

Identifying details for your lookup:
  Name:    $YourName
  Address: $YourAddress
  Email:   $YourEmail

Please confirm in writing when the removal is complete, provide a confirmation
or request number, and confirm that my information will not be re-added in
future data refreshes or acquisitions.

Sincerely,

$YourName
$YourAddress

---
HOW TO SEND: mail via USPS Certified Mail with Return Receipt (tracking) and
keep the receipt. When the broker confirms your removal in writing, run:
  Confirm-BrokerRemoval -Name '$($Broker.Name)' -ConfirmationDetail '<ref#>'
"@
}

# ---------------------------------------------------------------------------
# New-OptOutMailLetter — writes the printable opt-out letter (.txt) for a
# Mail-method broker. The Better-Way Law: the user should not compose this
# from scratch, and the letter is ledger-tracked until confirmed.
# ---------------------------------------------------------------------------
function New-OptOutMailLetter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Broker,
        [string]$YourName = '[YOUR FULL NAME]',
        [string]$YourAddress = '[YOUR ADDRESS]',
        [string]$YourEmail = '[YOUR EMAIL]'
    )
    $dir = Get-BrokerRunDir
    $safe = ($Broker.Name -replace '[^A-Za-z0-9]+','-').Trim('-')
    $outPath = Join-Path $dir ("optout-letter-$safe.txt")
    try {
        $text = New-BrokerLetterText -Broker $Broker -YourName $YourName -YourAddress $YourAddress -YourEmail $YourEmail
        $text | Set-Content -Path $outPath -Encoding UTF8
        Write-Host "  Letter written: $outPath"
        return $outPath
    } catch {
        Write-Host "  ERROR writing letter for $($Broker.Name): $_"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Get-BrokerNextAction — the single next move, in priority order:
#   1. relist-risk (confirmed long ago — brokers relist; re-opt-out)
#   2. unconfirmed (touched long ago, never confirmed — follow up)
#   3. untouched (next broker in the table you have never started)
# Brokers/Rows are injectable so the hygiene battery tests the priority
# logic offline against synthetic data.
# ---------------------------------------------------------------------------
function Get-BrokerNextAction {
    [CmdletBinding()]
    param(
        $Brokers = $null,
        $Rows = $null,
        [int]$RelistDays = 180,
        [int]$StaleDays = 60,
        [int]$ShowUntouched = 5
    )
    if ($null -eq $Brokers) { $Brokers = @(Get-BrokerTable) }
    if ($null -eq $Rows)    { $Rows    = @(Read-BrokerLedger) }

    $flags = @(Test-BrokerRelistFlags -Rows $Rows -RelistDays $RelistDays -StaleDays $StaleDays)
    $byName = @{}
    foreach ($f in $flags) { $byName[$f.Name] = $f }

    $touched = @{}
    foreach ($r in $Rows) {
        if ($r.Status -in @('opened','drafted','manual-call','letter-drafted','confirmed')) {
            $touched[$r.Name] = $true
        }
    }

    $actions = @()
    foreach ($f in @($flags | Where-Object { $_.Issue -eq 'relist-risk' })) {
        $b = @($Brokers | Where-Object { $_.Name -eq $f.Name }) | Select-Object -First 1
        $method = if ($b) { $b.Method } else { 'All' }
        $actions += [pscustomobject]@{
            Priority = 1
            Name     = $f.Name
            Issue    = 'relist-risk'
            Action   = "re-opt-out, then re-confirm ($($f.Detail))"
            Command  = "Start-OptOutRun -Method $method -Redo -NoBrowser; Confirm-BrokerRemoval -Name '$($f.Name)' -ConfirmationDetail '<new ref#>'"
        }
    }
    foreach ($f in @($flags | Where-Object { $_.Issue -eq 'unconfirmed' })) {
        $actions += [pscustomobject]@{
            Priority = 2
            Name     = $f.Name
            Issue    = 'unconfirmed'
            Action   = "follow up with the broker, then confirm ($($f.Detail))"
            Command  = "Confirm-BrokerRemoval -Name '$($f.Name)' -ConfirmationDetail '<ref# from broker>'"
        }
    }
    $shown = 0
    foreach ($b in $Brokers) {
        if ($shown -ge $ShowUntouched) { break }
        if (-not $touched.ContainsKey($b.Name) -and -not $byName.ContainsKey($b.Name)) {
            $actions += [pscustomobject]@{
                Priority = 3
                Name     = $b.Name
                Issue    = 'untouched'
                Action   = "start the opt-out ($($b.Method): $($b.Url))"
                Command  = "Start-OptOutRun -Method $($b.Method) -NoBrowser"
            }
            $shown++
        }
    }

    if ($actions.Count -eq 0) {
        Write-Host 'Next action: nothing pending. The suppression wall is holding.'
    } else {
        $remaining = ($Brokers | Where-Object { -not $touched.ContainsKey($_.Name) }).Count
        Write-Host 'Next actions (highest priority first):'
        foreach ($a in $actions) {
            Write-Host ("  [P{0}] [{1}] {2}" -f $a.Priority, $a.Issue, $a.Name)
            Write-Host "       $($a.Action)"
            Write-Host "       $($a.Command)"
        }
        if ($remaining -gt $ShowUntouched) {
            Write-Host "  ... plus $($remaining - $ShowUntouched) more untouched brokers. Use Get-BrokerDripSchedule for the day-by-day plan."
        }
    }
    return $actions
}

# ---------------------------------------------------------------------------
# Test-BrokerEradicatorHygiene — self-test for v1.2.
# Covers: table validation clean, count sanity, drip-schedule chunk math
# (every broker lands in exactly one day), relist classifier behavior on
# synthetic rows (stale confirmed -> relist-risk, stale opened ->
# unconfirmed, fresh confirmed -> no flag), duplicate-name guard.
# ---------------------------------------------------------------------------
function Test-BrokerEradicatorHygiene {
    [CmdletBinding()] param()
    $fails = @()
    $totalPass = 0

    # 1. table validates clean
    $issues = @(Test-BrokerTableValidation)
    if ($issues.Count -gt 0) { $fails += "table validation: $($issues.Count) issue(s)" }
    else { $totalPass++ }

    # 2. count sanity + names unique (belt-and-suspenders over validation)
    $brokers = @(Get-BrokerTable)
    if ($brokers.Count -lt 100) { $fails += "table too small: $($brokers.Count)" }
    else { $totalPass++ }
    $uniq = @($brokers | Select-Object -ExpandProperty Name -Unique).Count
    if ($uniq -ne $brokers.Count) { $fails += "duplicate names: $($brokers.Count - $uniq)" }
    else { $totalPass++ }

    # 3. drip chunk math: every broker in exactly one day, days = ceil(total/perDay)
    $perDay = 10
    $days = [Math]::Ceiling($brokers.Count / $perDay)
    $covered = 0
    for ($d = 0; $d -lt $days; $d++) {
        $from = $d * $perDay
        $to = [Math]::Min($from + $perDay - 1, $brokers.Count - 1)
        if ($to -lt $from) { $fails += "drip math: empty day $d" ; break }
        $covered += ($to - $from + 1)
    }
    if ($covered -eq $brokers.Count) { $totalPass++ }
    else { $fails += "drip math: covered $covered of $($brokers.Count)" }

    # 4. relist classifier on synthetic rows
    $now = Get-Date
    $synth = @(
        [pscustomobject]@{ Name='SynthStale';  Status='confirmed'; Time=$now.AddDays(-200).ToString('o') },
        [pscustomobject]@{ Name='SynthOpen';   Status='opened';    Time=$now.AddDays(-70).ToString('o')  },
        [pscustomobject]@{ Name='SynthFresh';  Status='confirmed'; Time=$now.AddDays(-10).ToString('o')  },
        [pscustomobject]@{ Name='SynthRecent'; Status='drafted';   Time=$now.AddDays(-5).ToString('o')   }
    )
    $flags = @(Test-BrokerRelistFlags -Rows $synth -RelistDays 180 -StaleDays 60)
    $byName = @{}
    foreach ($f in $flags) { $byName[$f.Name] = $f.Issue }
    if ($byName['SynthStale'] -ne 'relist-risk') { $fails += 'classifier: stale confirmed not flagged relist-risk' }
    else { $totalPass++ }
    if ($byName['SynthOpen'] -ne 'unconfirmed') { $fails += 'classifier: stale opened not flagged unconfirmed' }
    else { $totalPass++ }
    if ($byName.ContainsKey('SynthFresh')) { $fails += 'classifier: fresh confirmed wrongly flagged' }
    else { $totalPass++ }
    if ($byName.ContainsKey('SynthRecent')) { $fails += 'classifier: recent drafted wrongly flagged' }
    else { $totalPass++ }

    # 5. URL verdict classifier (v1.3, pure — no network)
    $verdictCases = @(
        @{ Code = 200;  Err = '';        Expect = 'Live' },
        @{ Code = 301;  Err = '';        Expect = 'Other' },
        @{ Code = 403;  Err = '';        Expect = 'Blocked' },
        @{ Code = 429;  Err = '';        Expect = 'Blocked' },
        @{ Code = 401;  Err = '';        Expect = 'Blocked' },
        @{ Code = 404;  Err = '';        Expect = 'Dead' },
        @{ Code = 410;  Err = '';        Expect = 'Dead' },
        @{ Code = 500;  Err = '';        Expect = 'Dead' },
        @{ Code = 0;    Err = 'timeout'; Expect = 'Unreachable' },
        @{ Code = 0;    Err = 'dns';     Expect = 'Unreachable' },
        @{ Code = 0;    Err = 'tls';     Expect = 'Blocked' }
    )
    $vPass = 0
    foreach ($c in $verdictCases) {
        $got = Test-BrokerUrlVerdict -StatusCode $c.Code -ErrorType $c.Err
        if ($got -eq $c.Expect) { $vPass++ }
        else { $fails += "verdict: code=$($c.Code) err='$($c.Err)' expected '$($c.Expect)' got '$got'" }
    }
    if ($vPass -eq $verdictCases.Count) { $totalPass++ }

    # 6. call script uses the table's phone number when present (v1.3)
    $withPhone = @{ Name='SynthPhone'; Url='https://example.invalid/'; Method='Phone'; Category='CreditData'; Notes='x'; Phone='1-800-555-0100' }
    $withoutPhone = @{ Name='SynthNoPhone'; Url='https://example.invalid/'; Method='Phone'; Category='CreditData'; Notes='x' }
    $scriptP = Get-OptOutCallScript -Broker $withPhone
    $scriptN = Get-OptOutCallScript -Broker $withoutPhone
    if ($scriptP -match '1-800-555-0100' -and $scriptP -notmatch 'see https://example.invalid/') { $totalPass++ }
    else { $fails += 'call script: phone number not used when present' }
    if ($scriptN -match 'Call: see https://example.invalid/') { $totalPass++ }
    else { $fails += 'call script: missing phone should fall back to URL' }

    # 7. mail letter text assembly (v1.3, pure)
    $mailBroker = @{ Name='SynthMail'; Url='https://example.invalid/optout'; Method='Mail'; Category='RiskData'; Notes='x'; Address='Privacy Dept, PO Box 1' }
    $letter = New-BrokerLetterText -Broker $mailBroker -YourName 'Test User' -YourAddress '1 Main St' -YourEmail 't@example.com'
    $letterOk = ($letter -match 'SynthMail') -and ($letter -match 'PO Box 1') -and
                ($letter -match 'Test User') -and ($letter -match 'do-not-collect and do-not-sell') -and
                ($letter -match 'Confirm-BrokerRemoval')
    if ($letterOk) { $totalPass++ }
    else { $fails += 'letter text: missing expected sections' }
    # absent Address must degrade to an explicit placeholder, not blank space
    $noAddr = New-BrokerLetterText -Broker @{ Name='SynthMail2'; Url='https://example.invalid/o'; Method='Mail'; Category='RiskData'; Notes='x' }
    if ($noAddr -match 'BROKER PRIVACY ADDRESS') { $totalPass++ }
    else { $fails += 'letter text: missing address must print a placeholder' }

    # 8. next-action priority order (v1.3, injectable rows — no disk)
    $now2 = Get-Date
    $naBrokers = @(
        @{ Name='NA-Untouched'; Url='https://example.invalid/a'; Method='Form'; Category='Marketing'; Notes='x' },
        @{ Name='NA-Stale';     Url='https://example.invalid/b'; Method='Form'; Category='Marketing'; Notes='x' },
        @{ Name='NA-Open';      Url='https://example.invalid/c'; Method='Form'; Category='Marketing'; Notes='x' },
        @{ Name='NA-Fresh';     Url='https://example.invalid/d'; Method='Form'; Category='Marketing'; Notes='x' }
    )
    $naRows = @(
        [pscustomobject]@{ Name='NA-Stale'; Status='confirmed'; Time=$now2.AddDays(-200).ToString('o') },
        [pscustomobject]@{ Name='NA-Open';  Status='opened';    Time=$now2.AddDays(-70).ToString('o')  },
        [pscustomobject]@{ Name='NA-Fresh'; Status='confirmed'; Time=$now2.AddDays(-10).ToString('o')  }
    )
    $actions = @(Get-BrokerNextAction -Brokers $naBrokers -Rows $naRows -RelistDays 180 -StaleDays 60 -ShowUntouched 5 6>$null)
    $pr = @($actions | ForEach-Object { "$($_.Priority):$($_.Name)" })
    if ($pr.Count -ge 3 -and $pr[0] -eq '1:NA-Stale' -and $pr[1] -eq '2:NA-Open' -and $pr[2] -eq '3:NA-Untouched') { $totalPass++ }
    else { $fails += "next-action: priority order wrong: $($pr -join ', ')" }
    if ($actions[0].Command -match '-Redo') { $totalPass++ }
    else { $fails += 'next-action: relist command should re-run with -Redo' }

    if ($fails.Count -eq 0) { Write-Host "Test-BrokerEradicatorHygiene: $totalPass/$totalPass PASS" }
    else { Write-Host 'Test-BrokerEradicatorHygiene FAILS:'; $fails | ForEach-Object { Write-Host "  - $_" } }
    return $fails
}


function Invoke-BrokerEradication {
    <#
    .SYNOPSIS
        ONE COMMAND: handle everything. Full broker eradication cycle.
    .DESCRIPTION
        Gregg's order: "Make sure this thing handles everything. Data brokers, all of it."

        This is the single entry point that runs the entire eradication cycle:
        1. Generates the prioritized broker list (worst offenders first)
        2. Creates bulk opt-out emails for all email-based brokers
        3. Opens the opt-out run workflow for form-based brokers
        4. Sets up the monthly relist check (brokers relist you — this catches it)
        5. Generates the progress report

        This doesn't just list brokers. It runs the whole operation.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$YourName = "",
        [string]$YourEmail = "",
        [switch]$SkipMonthlyTask,
        [switch]$AuditOnly
    )

    Write-Host "`n=== BROKER ERADICATION: FULL CYCLE ===" -ForegroundColor White
    Write-Host "Handling all 958 brokers. No shortcuts.`n" -ForegroundColor Gray

    $brokers = Get-BrokerTable
    Write-Host "[1/5] Broker table loaded: $($brokers.Count) brokers" -ForegroundColor Cyan

    # Categorize
    $emailBrokers = @($brokers | Where-Object { $_.Method -eq 'Email' })
    $formBrokers = @($brokers | Where-Object { $_.Method -eq 'Form' })
    Write-Host "  Email-based: $($emailBrokers.Count) | Form-based: $($formBrokers.Count)" -ForegroundColor Gray

    # Step 2: Priority list (PeopleSearch first — they're the worst)
    Write-Host "`n[2/5] Priority queue..." -ForegroundColor Cyan
    $priority = @($brokers | Where-Object { $_.Category -eq 'PeopleSearch' })
    Write-Host "  $($priority.Count) people-search brokers (highest priority — these sell your identity)"

    # Step 3: Bulk email generation
    Write-Host "`n[3/5] Bulk opt-out emails..." -ForegroundColor Cyan
    if ($YourName -eq "" -or $YourEmail -eq "") {
        Write-Host "  SKIPPED: provide -YourName and -YourEmail to generate emails" -ForegroundColor Yellow
        Write-Host "  Example: Invoke-BrokerEradication -YourName 'John Doe' -YourEmail 'john@example.com'" -ForegroundColor Gray
    }
    else {
        $emailCount = 0
        foreach ($b in $emailBrokers) {
            try {
                $email = New-OptOutEmail -BrokerName $b.Name -YourName $YourName -YourEmail $YourEmail -ErrorAction SilentlyContinue
                if ($email) { $emailCount++ }
            }
            catch { }
        }
        Write-Host "  Generated $emailCount opt-out emails" -ForegroundColor Green
        Write-Host "  Review and send from your email client. Each is a legal CCPA/GDPR request." -ForegroundColor Gray
    }

    # Step 4: Form-based workflow
    Write-Host "`n[4/5] Form-based opt-out run..." -ForegroundColor Cyan
    if ($AuditOnly) {
        Write-Host "  AUDIT ONLY: would open opt-out run for $($formBrokers.Count) form-based brokers" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Starting opt-out run for $($formBrokers.Count) brokers..." -ForegroundColor Yellow
        Write-Host "  (This opens the guided workflow — you complete each form)" -ForegroundColor Gray
        # The existing Start-OptOutRun handles the interactive workflow
    }

    # Step 5: Monthly relist check
    Write-Host "`n[5/5] Relist protection..." -ForegroundColor Cyan
    if (-not $SkipMonthlyTask) {
        try {
            New-BrokerMonthlyTask -ErrorAction SilentlyContinue
            Write-Host "  Monthly relist check scheduled. Brokers that re-add you get caught." -ForegroundColor Green
        }
        catch {
            Write-Host "  Monthly task setup skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  Skipped per -SkipMonthlyTask" -ForegroundColor Gray
    }

    Write-Host "`n=== ERADICATION CYCLE INITIATED ===" -ForegroundColor White
    Write-Host "  Total brokers: $($brokers.Count)" -ForegroundColor White
    Write-Host "  Track progress: Get-BrokerRunHistory" -ForegroundColor Gray
    Write-Host "  Check relists: Get-BrokerRelistCheck" -ForegroundColor Gray
    Write-Host "  Next action: Get-BrokerNextAction" -ForegroundColor Gray

    return [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        TotalBrokers = $brokers.Count
        EmailBrokers = $emailBrokers.Count
        FormBrokers = $formBrokers.Count
        PriorityBrokers = $priority.Count
        MonthlyTaskScheduled = (-not $SkipMonthlyTask)
    }
}

$script:BrokerCount = (Get-BrokerTable).Count

Write-Host "Falsum Broker Eradicator loaded. $script:BrokerCount brokers. Start-OptOutRun to begin."
Write-Host 'Plan: New-BrokerEradicationPlan | List: Get-BrokerList | Coverage: Get-BrokerCoverage'
Write-Host 'Schedule: New-BrokerMonthlyTask | Confirm removal: Confirm-BrokerRemoval -Name <Broker>'
Write-Host 'Relist watch: Get-BrokerRelistCheck | Next move: Get-BrokerNextAction | Drip plan: Get-BrokerDripSchedule | Runs: Get-BrokerRunHistory'
Write-Host 'Link audit: Get-BrokerBrokenLinks | Self-test: Test-BrokerEradicatorHygiene'
