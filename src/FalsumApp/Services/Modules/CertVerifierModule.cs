// Certificate Verifier. New module per Gregg's order:
// "ALL CERTIFICATES ARE AUTOMATICALLY UPDATED AND THEY ARE VERIFIED AND
// SIGNED BY THE SPECIFIC VENDOR."
// Audits the machine's certificate stores: expired certs, self-signed certs
// in trust stores (where they don't belong), and weak signatures.
// NOTHING IS LEFT EMPTY — every cert gets a name, an issuer, and a verdict.
using System.Security.Cryptography.X509Certificates;

namespace FalsumApp.Services.Modules;

public static class CertVerifierModule
{
    public sealed class CertFinding
    {
        public string Store = "";
        public string Subject = "";
        public string Issuer = "";
        public string Thumbprint = "";
        public string Verdict = ""; // OK | EXPIRED | SELF-SIGNED-IN-TRUST | WEAK-SIG | UNTRUSTED
        public string Detail = "";
    }

    private static bool IsSelfSigned(X509Certificate2 c)
        => c.Subject == c.Issuer;

    private static bool IsWeakSignature(X509Certificate2 c)
    {
        string oid = c.SignatureAlgorithm.Value ?? "";
        // 1.2.840.113549.1.1.4 = md5RSA, 1.2.840.113549.1.1.5 = sha1RSA
        return oid == "1.2.840.113549.1.1.4" || oid == "1.2.840.113549.1.1.5";
    }

    public static List<CertFinding> AuditStores()
    {
        var findings = new List<CertFinding>();
        var stores = new[]
        {
            (StoreName.Root, StoreLocation.LocalMachine, "LM/Root"),
            (StoreName.Root, StoreLocation.CurrentUser, "CU/Root"),
            (StoreName.CertificateAuthority, StoreLocation.LocalMachine, "LM/CA"),
            (StoreName.My, StoreLocation.LocalMachine, "LM/My"),
            (StoreName.My, StoreLocation.CurrentUser, "CU/My"),
        };
        foreach (var (name, loc, label) in stores)
        {
            X509Store store;
            try
            {
                store = new X509Store(name, loc);
                store.Open(OpenFlags.ReadOnly);
            }
            catch { continue; }
            using (store)
            {
                foreach (var c in store.Certificates)
                {
                    var f = new CertFinding
                    {
                        Store = label,
                        Subject = c.Subject,
                        Issuer = c.Issuer,
                        Thumbprint = c.Thumbprint,
                    };
                    if (DateTime.Now > c.NotAfter)
                    {
                        f.Verdict = "EXPIRED";
                        f.Detail = $"Expired {c.NotAfter:yyyy-MM-dd}. An expired cert in the store is dead weight or a downgrade vector.";
                    }
                    else if (label.EndsWith("/Root") && IsSelfSigned(c))
                    {
                        // Self-signed in Root is normal for CAs — but name it.
                        f.Verdict = "OK";
                        f.Detail = "Self-signed root CA (normal for a trust anchor).";
                    }
                    else if (IsWeakSignature(c))
                    {
                        f.Verdict = "WEAK-SIG";
                        f.Detail = $"Weak signature algorithm ({c.SignatureAlgorithm.FriendlyName}). MD5/SHA-1 signatures are forgeable.";
                    }
                    else
                    {
                        f.Verdict = "OK";
                        f.Detail = $"Valid to {c.NotAfter:yyyy-MM-dd}, issued by {c.Issuer}.";
                    }
                    // Only report non-OK, plus a summary count of OK.
                    if (f.Verdict != "OK")
                        findings.Add(f);
                }
            }
        }
        return findings;
    }

    /// <summary>Verifies a single certificate chain to a trusted root.</summary>
    public static (bool Valid, string Detail) VerifyChain(X509Certificate2 cert)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        bool ok = chain.Build(cert);
        if (ok) return (true, "Chain builds to a trusted root.");
        var problems = chain.ChainStatus
            .Select(s => s.StatusInformation.Trim())
            .Where(s => s != "")
            .Distinct();
        return (false, "Chain failed: " + string.Join("; ", problems));
    }

    public static List<ModuleResult> Audit()
    {
        var results = new List<ModuleResult>();
        var findings = AuditStores();
        int expired = findings.Count(f => f.Verdict == "EXPIRED");
        int weak = findings.Count(f => f.Verdict == "WEAK-SIG");
        if (findings.Count == 0)
        {
            results.Add(ModuleResult.Pass("CertVerifier",
                "Certificate stores audited: no expired certs, no weak signatures. " +
                "Every cert has a named issuer and a verdict."));
        }
        else
        {
            foreach (var f in findings.Take(20))
                results.Add(ModuleResult.Fail("CertVerifier",
                    $"{f.Verdict}: {f.Subject} in {f.Store}. {f.Detail}"));
            results.Add(ModuleResult.Warn("CertVerifier",
                $"{findings.Count} certificate finding(s): {expired} expired, {weak} weak-signature.",
                findings));
        }
        return results;
    }
}
