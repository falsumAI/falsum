namespace FalsumApp.Models;

public class GovernmentSector
{
    public string Icon { get; set; } = "";
    public string Name { get; set; } = "";
    public string GovernmentUse { get; set; } = "";
    public string Threat { get; set; } = "";
    public string FalsumProtection { get; set; } = "";
    public string[] ProtectiveModules { get; set; } = System.Array.Empty<string>();
    public string ActionLabel { get; set; } = "";

    public static List<GovernmentSector> AllSectors => new()
    {
        new()
        {
            Icon = "🛡️",
            Name = "Defense & Public Safety",
            GovernmentUse = "Intelligence analysis, surveillance, crime pattern AI, emergency response, evidence review.",
            Threat = "Surveillance tools on your device. Your data fed into pattern analysis without consent.",
            FalsumProtection = "Detects surveillance software, watches what data leaves your device, keeps tamper-proof receipts.",
            ProtectiveModules = new[] { "Active Defense", "Mobile Shield", "Packet Witness", "Evidence Vault" },
            ActionLabel = "Scan for Surveillance"
        },
        new()
        {
            Icon = "🏥",
            Name = "Healthcare",
            GovernmentUse = "Medical imaging AI, disease monitoring, hospital operations, visit scheduling.",
            Threat = "Your health data sold by brokers. Hospital breaches exposing your records.",
            FalsumProtection = "Removes health data from 958 brokers. Alerts on hospital breaches. Strips photo metadata.",
            ProtectiveModules = new[] { "Broker Eradicator", "Breach Cleaner", "Photo Scrub" },
            ActionLabel = "Protect Health Data"
        },
        new()
        {
            Icon = "🎓",
            Name = "Education",
            GovernmentUse = "AI tutors, student monitoring, predictive analytics on children.",
            Threat = "Ed-tech trackers profiling your kids. School portals fingerprinting devices.",
            FalsumProtection = "Blocks ed-tech trackers. Stops fingerprinting on school portals. Catches student-targeted phishing.",
            ProtectiveModules = new[] { "Tracker Block", "Browser Shield", "Mail Shield" },
            ActionLabel = "Protect Students"
        },
        new()
        {
            Icon = "💰",
            Name = "Tax & Revenue",
            GovernmentUse = "Fraud detection AI, automated auditing, government chatbots.",
            Threat = "Tax scams impersonating the IRS. Your filing data used to profile you.",
            FalsumProtection = "Blocks tax-scam addresses. Builds evidence packs. Vault proves what you filed and when.",
            ProtectiveModules = new[] { "Scam Shield", "Fraud Pack", "Evidence Vault" },
            ActionLabel = "Guard Tax Data"
        },
        new()
        {
            Icon = "🚗",
            Name = "Transportation",
            GovernmentUse = "Traffic AI, license plate readers, transit optimization, location tracking.",
            Threat = "Plate readers tracking your car. Transit apps selling your location.",
            FalsumProtection = "VPN blocks location trackers. Secures home network from IMSI catchers.",
            ProtectiveModules = new[] { "Android VPN Filter", "WiFi/Router Guard" },
            ActionLabel = "Block Location Tracking"
        },
        new()
        {
            Icon = "⚖️",
            Name = "Judiciary",
            GovernmentUse = "Risk assessment AI, document analysis, automated translation.",
            Threat = "Algorithmic risk scores deciding bail and sentencing. Your data used against you.",
            FalsumProtection = "Tamper-evident evidence log for legal defense. Preserves digital evidence correctly.",
            ProtectiveModules = new[] { "Evidence Vault", "Evidence Sweep" },
            ActionLabel = "Secure Legal Evidence"
        },
        new()
        {
            Icon = "🏛️",
            Name = "Citizen Services",
            GovernmentUse = "Benefit eligibility AI, government chatbots, document processing.",
            Threat = "Your benefit questions sent to cloud AI. Eligibility algorithms denying you without explanation.",
            FalsumProtection = "Local AI answers your questions on-device. No data ever leaves. No server sees what you asked.",
            ProtectiveModules = new[] { "Local AI Chat", "Data Gate" },
            ActionLabel = "Ask Local AI"
        },
    };
}
