// Native Windows Defender Firewall access via the HNetCfg COM API.
// This is the same API the NetSecurity PowerShell cmdlets (Get/New/Remove-
// NetFirewallRule) wrap. Late-bound through IDispatch so no interop assembly
// or vtable ordering is needed. No PowerShell involved.
using System.Reflection;

namespace FalsumApp.Services.Modules;

internal static class NativeFirewall
{
    private const string FwPolicyProgId = "HNetCfg.FwPolicy2";
    private const string FwRuleProgId = "HNetCfg.FWRule";

    // NET_FW_RULE_DIRECTION_
    public const int DirectionInbound = 1;
    public const int DirectionOutbound = 2;
    // NET_FW_ACTION_
    public const int ActionBlock = 0;
    public const int ActionAllow = 1;
    // Protocol numbers (0 = any)
    public const int ProtocolTcp = 6;
    public const int ProtocolUdp = 17;

    private static dynamic CreatePolicy()
    {
        var t = Type.GetTypeFromProgID(FwPolicyProgId)
            ?? throw new InvalidOperationException("Windows Firewall COM API (HNetCfg.FwPolicy2) is not available.");
        return Activator.CreateInstance(t)!;
    }

    public static int CountRules(string namePrefix)
    {
        dynamic policy = CreatePolicy();
        int n = 0;
        foreach (dynamic rule in policy.Rules)
        {
            string name = (rule.Name as string) ?? "";
            if (name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)) n++;
        }
        return n;
    }

    /// <summary>Add a firewall rule unless an identical name already exists.</summary>
    public static void AddRule(string name, int direction, int action, int protocol = 0,
        string localPorts = "", string remoteAddress = "")
    {
        dynamic policy = CreatePolicy();
        foreach (dynamic rule in policy.Rules)
            if (string.Equals(rule.Name as string, name, StringComparison.OrdinalIgnoreCase)) return;

        var rt = Type.GetTypeFromProgID(FwRuleProgId)
            ?? throw new InvalidOperationException("Windows Firewall COM API (HNetCfg.FWRule) is not available.");
        dynamic newRule = Activator.CreateInstance(rt)!;
        newRule.Name = name;
        newRule.Direction = direction;
        newRule.Action = action;
        newRule.Enabled = true;
        if (protocol != 0) newRule.Protocol = protocol;
        if (!string.IsNullOrEmpty(localPorts)) newRule.LocalPorts = localPorts;
        if (!string.IsNullOrEmpty(remoteAddress)) newRule.RemoteAddresses = remoteAddress;
        policy.Rules.Add(newRule);
    }

    /// <summary>Remove every rule whose name starts with the prefix. Returns count removed.</summary>
    public static int RemoveRules(string namePrefix)
    {
        dynamic policy = CreatePolicy();
        var toRemove = new List<string>();
        foreach (dynamic rule in policy.Rules)
        {
            string name = (rule.Name as string) ?? "";
            if (name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase)) toRemove.Add(name);
        }
        foreach (var name in toRemove) policy.Rules.Remove(name);
        return toRemove.Count;
    }

    public static List<Dictionary<string, string>> GetAllRules()
    {
        dynamic policy = CreatePolicy();
        var list = new List<Dictionary<string, string>>();
        foreach (dynamic rule in policy.Rules)
        {
            list.Add(new Dictionary<string, string>
            {
                ["DisplayName"] = (rule.Name as string) ?? "",
                ["Enabled"] = ((rule.Enabled as bool?) ?? false).ToString(),
                ["Direction"] = ((rule.Direction as int?) ?? 0).ToString(),
                ["Action"] = ((rule.Action as int?) ?? 0).ToString(),
            });
        }
        return list;
    }

    /// <summary>
    /// Read/write the firewall default-outbound action for a profile set
    /// (pass 0x7FFFFFFF for all profiles). 0 = block, 1 = allow.
    /// Uses late-bound InvokeMember so no COM vtable ordering is needed.
    /// </summary>
    public static int GetDefaultOutboundAction(int profileTypes)
    {
        var policy = CreatePolicy();
        object? result = ((object)policy).GetType().InvokeMember(
            "DefaultOutboundAction",
            BindingFlags.GetProperty, null, policy, new object[] { profileTypes });
        return result is int i ? i : 1;
    }

    public static void SetDefaultOutboundAction(int profileTypes, int action)
    {
        var policy = CreatePolicy();
        ((object)policy).GetType().InvokeMember(
            "DefaultOutboundAction",
            BindingFlags.SetProperty, null, policy, new object[] { profileTypes, action });
    }
}
