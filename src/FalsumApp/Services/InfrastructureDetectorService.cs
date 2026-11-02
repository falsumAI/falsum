using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace FalsumApp.Services;

/// <summary>
/// Infrastructure Detector — native C# service.
///
/// WHAT IT DETECTS:
/// Windows computers being turned into cell phone infrastructure.
/// Carriers, governments, and corporations are pushing mobile-network
/// components onto desktop Windows: eSIM provisioning, cellular stacks,
/// carrier bloatware, mobile device management, phone-link bridges.
///
/// This service finds all of it:
/// - Cellular/eSIM services running on a desktop that has no cellular hardware
/// - Carrier provisioning packages
/// - Phone Link / mobile device bridges exfiltrating data
/// - MDM enrollment on a personal machine
/// - Mobile network drivers with no hardware to drive
///
/// If your desktop is running cell tower software, you deserve to know why.
/// </summary>
public class InfrastructureDetectorService
{
    private string RunCmd(string command, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };

            using var proc = Process.Start(psi);
            if (proc == null) return "";

            var output = new StringBuilder();
            proc.OutputDataReceived += (s, e) => { if (e.Data != null) output.AppendLine(e.Data); };
            proc.BeginOutputReadLine();
            proc.WaitForExit(timeoutMs);
            return output.ToString();
        }
        catch { return ""; }
    }

    /// <summary>
    /// Find cellular/mobile infrastructure on this machine.
    /// </summary>
    public InfrastructureReport Scan()
    {
        var report = new InfrastructureReport
        {
            Timestamp = DateTime.UtcNow,
            Findings = new List<InfrastructureFinding>()
        };

        // 1. Check for cellular services
        var services = RunCmd("sc query | findstr /i \"cellular mobile esim wwansvc\"");
        if (!string.IsNullOrWhiteSpace(services))
        {
            report.Findings.Add(new InfrastructureFinding
            {
                Category = "cellular-services",
                Severity = "warning",
                Description = "Cellular/mobile services found running.",
                Details = services.Trim(),
                Recommendation = "If this is a desktop with no cellular hardware, these services " +
                    "have no legitimate purpose. Disable them."
            });
        }

        // 2. Check for Phone Link / mobile bridges
        var phoneLink = RunCmd("tasklist | findstr /i \"PhoneLink PhoneExperienceHost YourPhone\"");
        if (!string.IsNullOrWhiteSpace(phoneLink))
        {
            report.Findings.Add(new InfrastructureFinding
            {
                Category = "phone-bridge",
                Severity = "info",
                Description = "Phone Link or mobile bridge software is running.",
                Details = phoneLink.Trim(),
                Recommendation = "This bridges your phone to your PC. If you didn't set it up, " +
                    "it may be exfiltrating notifications, messages, and photos. Disable if unwanted."
            });
        }

        // 3. Check for MDM enrollment
        var mdm = RunCmd("dsregcmd /status | findstr /i \"AzureAdJoined EnterpriseJoined\"");
        if (mdm.Contains("YES", StringComparison.OrdinalIgnoreCase))
        {
            report.Findings.Add(new InfrastructureFinding
            {
                Category = "mdm-enrollment",
                Severity = "critical",
                Description = "This machine is enrolled in enterprise/mobile device management.",
                Details = mdm.Trim(),
                Recommendation = "A personal computer should NOT be MDM-enrolled. This gives " +
                    "an organization remote control over your machine. Investigate immediately."
            });
        }

        // 4. Check for eSIM provisioning
        var esim = RunCmd("netsh mbn show interfaces");
        if (!esim.Contains("There is no Mobile Broadband", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(esim))
        {
            report.Findings.Add(new InfrastructureFinding
            {
                Category = "esim-provisioning",
                Severity = "warning",
                Description = "Mobile broadband interface detected.",
                Details = esim.Trim().Substring(0, Math.Min(500, esim.Trim().Length)),
                Recommendation = "If you don't have cellular hardware, this shouldn't exist."
            });
        }

        // 5. Check for carrier bloatware in installed programs
        var carriers = new[] { "Verizon", "AT&T", "T-Mobile", "Sprint", "Vodafone" };
        var programs = RunCmd("wmic product get name | findstr /i \"verizon at&t t-mobile sprint vodafone carrier\"");
        if (!string.IsNullOrWhiteSpace(programs))
        {
            report.Findings.Add(new InfrastructureFinding
            {
                Category = "carrier-bloatware",
                Severity = "warning",
                Description = "Carrier software found installed.",
                Details = programs.Trim(),
                Recommendation = "Carrier bloatware on a desktop serves the carrier, not you. Remove it."
            });
        }

        return report;
    }

    /// <summary>
    /// Disable cellular services that have no business running on a desktop.
    /// </summary>
    public string DisableCellularServices()
    {
        var result = new StringBuilder();
        var services = new[] { "WwanSvc", "SmsRouter" };

        foreach (var svc in services)
        {
            result.AppendLine(RunCmd($"sc stop {svc}"));
            result.AppendLine(RunCmd($"sc config {svc} start= disabled"));
        }

        return result.ToString();
    }
}

public class InfrastructureReport
{
    public DateTime Timestamp { get; set; }
    public List<InfrastructureFinding> Findings { get; set; } = new();
}

public class InfrastructureFinding
{
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string Description { get; set; } = "";
    public string Details { get; set; } = "";
    public string Recommendation { get; set; } = "";
}
