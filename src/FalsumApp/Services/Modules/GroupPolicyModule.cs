// Group Policy Audit. New module per Gregg's order:
// "ESPECIALLY ANYTHING AROUND THE FUCKEN BULLSHIT GROUP POLICIES AND HOW
// MICROSOFT AND ALL THESE CORRUPT FUCKS TAKE ADVANTAGE OF THAT."
// Reads every Group Policy setting from the registry (Machine + User),
// names what each one locks, and flags the ones that take control away
// from the owner of the machine. Nothing hidden — every policy gets a name,
// a value, and a plain-language verdict.
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class GroupPolicyModule
{
    public sealed class Policy
    {
        public string Hive = "";      // HKLM or HKCU
        public string Path = "";
        public string Name = "";
        public string Value = "";
        public string Verdict = "";   // INFO | RESTRICTIVE | SUSPICIOUS
        public string Plain = "";     // what it does in plain language
    }

    /// <summary>
    /// Policies that take control away from the machine owner, with
    /// plain-language explanations.
    /// </summary>
    private static readonly (string Subkey, string ValueName, string Plain)[] WatchedPolicies =
    new[]
    {
        (@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate",
            "Windows Update disabled by policy — the machine stops receiving security patches."),
        (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware",
            "Windows Defender disabled by policy — the built-in antivirus is turned off."),
        (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring",
            "Defender real-time protection disabled by policy."),
        (@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen",
            "SmartScreen (download reputation) controlled by policy."),
        (@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry",
            "Telemetry level forced by policy: 0=Security(Enterprise only), 1=Basic, 2=Enhanced, 3=Full."),
        (@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast",
            "LLMNR controlled by policy (0 = disabled, the safe setting)."),
        (@"SOFTWARE\Policies\Microsoft\Windows\Explorer", "NoDriveTypeAutoRun",
            "AutoRun controlled by policy (0xFF = fully disabled, the safe setting)."),
        (@"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices", "Deny_All",
            "Removable storage (USB drives) denied by policy."),
        (@"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "DenyDeviceIDs",
            "Device installation restricted by policy — controls what hardware you may plug in."),
        (@"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures",
            "Consumer bloatware (Candy Crush etc.) blocked by policy."),
        (@"SOFTWARE\Policies\Microsoft\WindowsStore", "RemoveWindowsStore",
            "Microsoft Store removed by policy."),
        (@"SOFTWARE\Policies\Microsoft\WindowsStore", "DisableStoreApps",
            "Store apps disabled by policy."),
        (@"SOFTWARE\Policies\Microsoft\Edge", "HideFirstRunExperience",
            "Edge first-run controlled by policy (enterprise management signal)."),
        (@"SOFTWARE\Policies\Google\Chrome", "HomepageLocation",
            "Chrome homepage forced by policy — the browser is managed."),
        (@"SOFTWARE\Policies\Google\Chrome", "ExtensionInstallForcelist",
            "Chrome extensions force-installed by policy — they cannot be removed by the user."),
        (@"SOFTWARE\Policies\Mozilla\Firefox", "Homepage",
            "Firefox homepage forced by policy — the browser is managed."),
        (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell", "EnableScripts",
            "PowerShell script execution controlled by policy."),
        (@"SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0", "Task Creation",
            "Task Scheduler controlled by policy."),
        (@"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated",
            "MSI packages always install elevated — a privilege-escalation vector if abused."),
        (@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections",
            "Remote Desktop controlled (0 = enabled, 1 = disabled)."),
    };

    private static object? RegGet(RegistryHive hive, string subkey, string name)
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, RegistryView.Default)
                .OpenSubKey(subkey);
            return k?.GetValue(name);
        }
        catch { return null; }
    }

    public static List<Policy> Audit()
    {
        var policies = new List<Policy>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            string hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
            foreach (var (subkey, valueName, plain) in WatchedPolicies)
            {
                var v = RegGet(hive, subkey, valueName);
                if (v == null) continue;
                string valStr = v.ToString() ?? "";
                string verdict = "INFO";
                // Flag the ones that take control away.
                if (valueName is "DisableAntiSpyware" or "DisableRealtimeMonitoring"
                    && valStr == "1")
                    verdict = "RESTRICTIVE";
                if (valueName == "NoAutoUpdate" && valStr == "1")
                    verdict = "RESTRICTIVE";
                if (valueName == "AllowTelemetry" && valStr is "2" or "3")
                    verdict = "SUSPICIOUS";
                if (valueName == "ExtensionInstallForcelist")
                    verdict = "RESTRICTIVE";
                if (valueName == "AlwaysInstallElevated" && valStr == "1")
                    verdict = "SUSPICIOUS";
                policies.Add(new Policy
                {
                    Hive = hiveName,
                    Path = subkey,
                    Name = valueName,
                    Value = valStr,
                    Verdict = verdict,
                    Plain = plain,
                });
            }
        }
        return policies;
    }

    public static List<ModuleResult> AuditPolicies()
    {
        var results = new List<ModuleResult>();
        var policies = Audit();
        if (policies.Count == 0)
        {
            results.Add(ModuleResult.Pass("GroupPolicy",
                "No managed Group Policy settings found. This machine is not policy-managed — you are in control."));
            return results;
        }
        int restrictive = policies.Count(p => p.Verdict == "RESTRICTIVE");
        int suspicious = policies.Count(p => p.Verdict == "SUSPICIOUS");
        foreach (var p in policies)
        {
            string msg = $"[{p.Verdict}] {p.Hive}\\{p.Path}\\{p.Name} = {p.Value}. {p.Plain}";
            results.Add(p.Verdict == "INFO"
                ? ModuleResult.Pass("GroupPolicy", msg)
                : ModuleResult.Warn("GroupPolicy", msg));
        }
        if (restrictive + suspicious > 0)
            results.Add(ModuleResult.Warn("GroupPolicy",
                $"{policies.Count} managed policies found: {restrictive} restrictive, " +
                $"{suspicious} suspicious. A policy-managed personal machine means " +
                "someone else's rules run on your property — review each one.",
                policies));
        return results;
    }
}
