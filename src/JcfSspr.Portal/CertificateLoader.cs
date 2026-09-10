using System.Security.Cryptography.X509Certificates;

namespace JcfSspr.Portal;

public static class CertificateLoader
{
    public static X509Certificate2 FindByThumbprint(string thumbprint)
    {
        var normalized = Normalize(thumbprint);
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: true);
        if (matches.Count != 1)
            throw new InvalidOperationException("The configured portal client certificate was not found or is not valid.");
        var certificate = matches[0];
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException("The configured portal client certificate has no private key.");
        return certificate;
    }

    public static string Normalize(string thumbprint) => new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
}
