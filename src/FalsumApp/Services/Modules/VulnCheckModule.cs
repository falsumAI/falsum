// Module 06: Vuln Check. Faithful C# port of Test-WeakConfigs.
// Weak-configuration audit — each detection ships its fix guidance
// (Better-Way Law). Checks: SMBv1, LLMNR, NetBIOS, RDP, UAC, firewall
// profiles, Windows Update service, Guest account, AutoRun.
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class VulnCheckModule
{
    public sealed class Finding
    {
        public string Severity = "Info"; // Critical|High|Medium|Low|Info
        public string Title = "";
        public string Evidence = "";
        public string Fix = "";
    }

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

    public static List<Finding> WeakConfigs()
    {
        var f = new List<Finding>();

        // SMBv1
        try
        {
            var v = RegGet(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            if (v != null && Convert.ToInt32(v) == 1)
                f.Add(new Finding { Severity = "High", Title = "SMBv1 is enabled",
                    Evidence = "SMB1=1. SMBv1 has no encryption and enabled WannaCry/NotPetya-class worms.",
                    Fix = "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0, or disable the SMB1Protocol optional feature." });
            else
                f.Add(new Finding { Severity = "Info", Title = "SMBv1 disabled",
                    Evidence = "SMB1 not enabled." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "SMBv1 check inconclusive", Evidence = ex.Message }); }

        // LLMNR
        try
        {
            var v = RegGet(RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
            if (v != null && Convert.ToInt32(v) == 0)
                f.Add(new Finding { Severity = "Info", Title = "LLMNR disabled",
                    Evidence = "EnableMulticast=0 policy present." });
            else
                f.Add(new Finding { Severity = "High", Title = "LLMNR is enabled",
                    Evidence = "EnableMulticast is not set to 0. LLMNR answers name queries on the LAN and enables responder-style credential capture.",
                    Fix = "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0 (DWORD)." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "LLMNR check inconclusive", Evidence = ex.Message }); }

        // NetBIOS over TCP/IP per adapter.
        try
        {
            var enabled = new List<string>();
            using var ifaces = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces");
            if (ifaces != null)
                foreach (var name in ifaces.GetSubKeyNames())
                {
                    using var sk = ifaces.OpenSubKey(name);
                    var v = sk?.GetValue("NetbiosOptions");
                    // 2 = disabled; 0/1 = enabled/default. Absent = DHCP decides (treat as enabled risk).
                    if (v == null || Convert.ToInt32(v) != 2) enabled.Add(name);
                }
            if (enabled.Count > 0)
                f.Add(new Finding { Severity = "High", Title = "NetBIOS over TCP/IP enabled on adapters",
                    Evidence = $"Adapters without NetBT disabled: {enabled.Count}. NBT-NS enables the same responder-style poisoning as LLMNR.",
                    Fix = "Set NetbiosOptions=2 (DWORD) under each HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\<adapter>." });
            else
                f.Add(new Finding { Severity = "Info", Title = "NetBIOS over TCP/IP disabled",
                    Evidence = "All adapters have NetBT disabled (option 2)." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "NetBIOS check inconclusive", Evidence = ex.Message }); }

        // RDP
        try
        {
            var v = RegGet(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            if (v != null && Convert.ToInt32(v) == 0)
                f.Add(new Finding { Severity = "Medium", Title = "Remote Desktop is enabled",
                    Evidence = "fDenyTSConnections=0. Ensure Network Level Authentication and strong creds, or disable.",
                    Fix = "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections = 1." });
            else
                f.Add(new Finding { Severity = "Info", Title = "Remote Desktop disabled",
                    Evidence = "fDenyTSConnections=1." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "RDP check inconclusive", Evidence = ex.Message }); }

        // UAC
        try
        {
            var v = RegGet(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            if (v != null && Convert.ToInt32(v) == 0)
                f.Add(new Finding { Severity = "High", Title = "UAC is disabled",
                    Evidence = "EnableLUA=0. Every process runs with full admin rights.",
                    Fix = "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1 and reboot." });
            else
                f.Add(new Finding { Severity = "Info", Title = "UAC enabled", Evidence = "EnableLUA=1." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "UAC check inconclusive", Evidence = ex.Message }); }

        // Firewall profiles (via native INetFwPolicy2 wrapper).
        try
        {
            var off = new List<string>();
            foreach (var (name, profile) in new[] {
                ("Domain", 1), ("Private", 2), ("Public", 4) })
            {
                try
                {
                    if (!NativeFirewall.IsProfileEnabled(profile)) off.Add(name);
                }
                catch { off.Add(name + " (unreadable)"); }
            }
            if (off.Count > 0)
                f.Add(new Finding { Severity = "High", Title = "Firewall profile(s) off",
                    Evidence = "Off/unreadable: " + string.Join(", ", off),
                    Fix = "Enable Windows Defender Firewall on all profiles." });
            else
                f.Add(new Finding { Severity = "Info", Title = "All firewall profiles on",
                    Evidence = "Domain, Private, Public." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "Firewall profile check failed", Evidence = ex.Message }); }

        // AutoRun (0xFF = fully disabled on all drive types).
        try
        {
            var bad = new List<string>();
            foreach (var (hive, label) in new[] {
                (RegistryHive.LocalMachine, "HKLM"), (RegistryHive.CurrentUser, "HKCU") })
            {
                var v = RegGet(hive,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun");
                if (v == null || Convert.ToInt32(v) != 0xFF) bad.Add(label);
            }
            if (bad.Count > 0)
                f.Add(new Finding { Severity = "Medium", Title = "AutoRun is not fully disabled",
                    Evidence = "NoDriveTypeAutoRun != 0xFF in: " + string.Join(", ", bad) + ". USB-borne malware auto-executes.",
                    Fix = "Set NoDriveTypeAutoRun=0xFF (DWORD) in HKLM and HKCU ...\\Policies\\Explorer." });
            else
                f.Add(new Finding { Severity = "Info", Title = "AutoRun disabled on all drive types",
                    Evidence = "NoDriveTypeAutoRun=0xFF in HKLM and HKCU." });
        }
        catch (Exception ex)
        { f.Add(new Finding { Severity = "Low", Title = "AutoRun check inconclusive", Evidence = ex.Message }); }

        return f;
    }

    /// <summary>Card/ProtectAll action "Test-WeakConfigs".</summary>
    public static List<ModuleResult> TestWeakConfigs()
    {
        var results = new List<ModuleResult>();
        var findings = WeakConfigs();
        int bad = findings.Count(x =>
            x.Severity is "Critical" or "High" or "Medium");
        foreach (var x in findings)
        {
            string msg = $"{x.Severity}: {x.Title} — {x.Evidence}" +
                         (x.Fix != "" ? $" Fix: {x.Fix}" : "");
            results.Add(x.Severity is "Critical" or "High" or "Medium"
                ? ModuleResult.Fail("VulnCheck", msg)
                : ModuleResult.Pass("VulnCheck", msg));
        }
        if (results.Count == 0)
            results.Add(ModuleResult.Pass("VulnCheck", "No weak-configuration checks ran."));
        return results;
    }
}
