// Falsum native module framework.
// Replaces the PowerShell module engine (Services/PowerShellEngine.cs).
// Every module below is a faithful C# port of its .ps1 reference implementation:
// same vault paths, same hash-chain formats, same semantics. Existing vault
// data written by the .ps1 modules verifies byte-identically under this code.
namespace FalsumApp.Services.Modules;

/// <summary>
/// Native replacement for a PSObject collection returned by a module.
/// Carries a name, a human-readable message, ok/fail, and optional structured data.
/// </summary>
public sealed class ModuleResult
{
    public string Name { get; set; } = "";
    public string Message { get; set; } = "";
    public bool Ok { get; set; } = true;
    public object? Data { get; set; }

    public static ModuleResult Pass(string name, string message, object? data = null)
        => new() { Name = name, Message = message, Ok = true, Data = data };

    public static ModuleResult Fail(string name, string message, object? data = null)
        => new() { Name = name, Message = message, Ok = false, Data = data };

    /// <summary>Warning: something needs attention but the module itself ran fine.</summary>
    public static ModuleResult Warn(string name, string message, object? data = null)
        => new() { Name = name, Message = message, Ok = true, Data = data };
}
