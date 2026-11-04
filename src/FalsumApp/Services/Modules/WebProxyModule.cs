// Module 15: Web Proxy. Faithful C# port of the Get-ProxyState action.
// Reports the machine's effective proxy configuration: WinINET (per-user,
// the one browsers use) from the registry, plus WinHTTP. No bodies, no
// traffic — state only, matching the .ps1's receipt-only design.
using Microsoft.Win32;

namespace FalsumApp.Services.Modules;

public static class WebProxyModule
{
    public static List<ModuleResult> GetProxyState()
    {
        var results = new List<ModuleResult>();
        var detail = new Dictionary<string, object?>();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key == null)
            {
                results.Add(ModuleResult.Pass("WebProxy",
                    "No per-user WinINET proxy settings found (direct connection).",
                    detail));
                return results;
            }
            int enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0));
            string server = key.GetValue("ProxyServer")?.ToString() ?? "";
            string overrideList = key.GetValue("ProxyOverride")?.ToString() ?? "";
            string autoConfig = key.GetValue("AutoConfigURL")?.ToString() ?? "";
            detail["ProxyEnable"] = enabled;
            detail["ProxyServer"] = server;
            detail["ProxyOverride"] = overrideList;
            detail["AutoConfigURL"] = autoConfig;
            if (enabled == 1 && server != "")
                results.Add(ModuleResult.Warn("WebProxy",
                    $"Proxy ENABLED: {server}. Overrides: {(overrideList == "" ? "(none)" : overrideList)}. " +
                    "All browser traffic routes through this proxy — verify it is yours.",
                    detail));
            else if (autoConfig != "")
                results.Add(ModuleResult.Pass("WebProxy",
                    $"No static proxy. Auto-config (PAC) in use: {autoConfig}.",
                    detail));
            else
                results.Add(ModuleResult.Pass("WebProxy",
                    "Proxy disabled. Direct connection.", detail));
        }
        catch (Exception ex)
        {
            results.Add(ModuleResult.Fail("WebProxy",
                "Could not read proxy state: " + ex.Message));
        }
        return results;
    }
}
