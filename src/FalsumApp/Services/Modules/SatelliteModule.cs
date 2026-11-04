// Module 36: Satellite Watch. Faithful C# port of Falsum-Satellite.ps1.
// Bluetooth radios and paired devices (potential exfiltration endpoints),
// plus nearby-device discovery state. WMI-based, no PowerShell.
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class SatelliteModule
{
    public sealed class BtDevice
    {
        public string Name = "";
        public string Id = "";
        public string Status = "";
    }

    public static List<BtDevice> GetBluetoothRadios()
    {
        var list = new List<BtDevice>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\ROOT\CIMV2"),
                new ObjectQuery("SELECT FriendlyName,DeviceID,Status FROM Win32_PnPEntity WHERE ClassGuid='{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}'"));
            // Fallback: match by PNPClass = Bluetooth.
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    list.Add(new BtDevice
                    {
                        Name = mo["FriendlyName"]?.ToString() ?? "",
                        Id = mo["DeviceID"]?.ToString() ?? "",
                        Status = mo["Status"]?.ToString() ?? "",
                    });
                }
            }
        }
        catch { }
        if (list.Count == 0)
        {
            // Fallback path: any PnP device whose class is Bluetooth.
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    new ManagementScope(@"\\.\ROOT\CIMV2"),
                    new ObjectQuery("SELECT Name,DeviceID,Status FROM Win32_PnPEntity WHERE PNPClass='Bluetooth'"));
                foreach (ManagementObject mo in searcher.Get())
                {
                    using (mo)
                    {
                        list.Add(new BtDevice
                        {
                            Name = mo["Name"]?.ToString() ?? "",
                            Id = mo["DeviceID"]?.ToString() ?? "",
                            Status = mo["Status"]?.ToString() ?? "",
                        });
                    }
                }
            }
            catch { }
        }
        return list;
    }

    public static List<string> GetPairedDevices()
    {
        var list = new List<string>();
        // Paired BT devices live under HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices.
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
            if (key != null)
                foreach (var sub in key.GetSubKeyNames())
                    list.Add("BT device: " + sub);
        }
        catch { }
        return list;
    }

    /// <summary>Card action "Invoke-FalsumSatelliteScan".</summary>
    public static List<ModuleResult> Scan()
    {
        var results = new List<ModuleResult>();
        var radios = GetBluetoothRadios();
        var paired = GetPairedDevices();

        if (radios.Count == 0)
            results.Add(ModuleResult.Pass("Satellite", "No active Bluetooth radios."));
        else
            results.Add(ModuleResult.Fail("Satellite",
                $"{radios.Count} Bluetooth radio(s) active: " +
                string.Join("; ", radios.Take(5).Select(r => r.Name)),
                radios));

        if (paired.Count == 0)
            results.Add(ModuleResult.Pass("Satellite", "No paired Bluetooth devices in registry."));
        else
            results.Add(ModuleResult.Fail("Satellite",
                $"{paired.Count} paired Bluetooth device(s) — potential exfiltration endpoints: " +
                string.Join("; ", paired.Take(5)),
                paired));

        // Vault.
        try
        {
            string vf = Path.Combine(Vault.VaultDir("satellite"),
                Vault.Timestamped("bt-scan", "jsonl"));
            foreach (var r in radios)
                Vault.AppendJsonl(vf, new Dictionary<string, object?>
                {
                    ["ts"] = Vault.IsoNow(), ["type"] = "bluetooth-radio",
                    ["name"] = r.Name, ["id"] = r.Id, ["status"] = r.Status,
                });
            foreach (var p in paired)
                Vault.AppendJsonl(vf, new Dictionary<string, object?>
                {
                    ["ts"] = Vault.IsoNow(), ["type"] = "paired-device", ["id"] = p,
                });
        }
        catch { }

        return results;
    }
}
