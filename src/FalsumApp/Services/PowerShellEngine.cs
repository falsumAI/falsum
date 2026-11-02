using System.Management.Automation;
using System.Collections.ObjectModel;

namespace FalsumApp.Services;

/// <summary>
/// Hosts PowerShell modules as the engine. C# provides the UI,
/// PowerShell provides the security logic. The user never sees a .ps1 file.
/// </summary>
public class PowerShellEngine : IDisposable
{
    private PowerShell _ps;
    private readonly string _modulesPath;

    public PowerShellEngine(string modulesPath)
    {
        _modulesPath = modulesPath;
        _ps = PowerShell.Create();
        _ps.AddCommand("Set-ExecutionPolicy").AddParameter("ExecutionPolicy", "Bypass").AddParameter("Scope", "Process");
        _ps.Invoke();
        _ps.Commands.Clear();
    }

    /// <summary>
    /// Run a Falsum module function and return results.
    /// Example: RunModule("06-vuln-check", "Test-WeakConfigs")
    /// </summary>
    public Collection<PSObject> RunModule(string moduleDir, string functionName, Dictionary<string, object>? parameters = null)
    {
        _ps.Commands.Clear();

        // Dot-source the module
        var modulePath = Path.Combine(_modulesPath, moduleDir, $"Falsum-{GetModuleFileName(moduleDir)}.ps1");
        _ps.AddScript($". '{modulePath}'");
        _ps.Invoke();
        _ps.Commands.Clear();

        // Call the function
        _ps.AddCommand(functionName);
        if (parameters != null)
        {
            foreach (var kvp in parameters)
                _ps.AddParameter(kvp.Key, kvp.Value);
        }

        var results = _ps.Invoke();

        if (_ps.HadErrors)
        {
            var errors = string.Join("\n", _ps.Streams.Error.Select(e => e.ToString()));
            throw new Exception($"Module {moduleDir}/{functionName} failed:\n{errors}");
        }

        return results;
    }

    private string GetModuleFileName(string moduleDir)
    {
        // "06-vuln-check" -> find the .ps1 file in that directory
        var dir = Path.Combine(_modulesPath, moduleDir);
        var ps1 = Directory.GetFiles(dir, "Falsum-*.ps1").FirstOrDefault();
        return ps1 != null ? Path.GetFileNameWithoutExtension(ps1).Replace("Falsum-", "") : "";
    }

    public void Dispose()
    {
        _ps?.Dispose();
    }
}
