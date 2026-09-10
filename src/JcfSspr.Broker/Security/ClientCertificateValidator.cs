using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Security;

public sealed class ClientCertificateValidator(IOptions<BrokerSecurityOptions> options)
{
    private readonly HashSet<string> _allowed = options.Value.AllowedClientCertificateThumbprints.Select(Normalize).Where(x => x.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public async Task<string?> GetValidatedClientIdAsync(HttpContext context)
    {
        var certificate = await context.Connection.GetClientCertificateAsync();
        if (certificate is null) return null;
        var now = DateTime.UtcNow;
        if (certificate.NotBefore > now || certificate.NotAfter <= now) return null;
        var id = Normalize(certificate.Thumbprint);
        if (!_allowed.Contains(id)) return null;
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        if (!chain.Build(certificate)) return null;
        var hasClientAuth = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(x => x.EnhancedKeyUsages.Cast<Oid>()).Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2");
        return hasClientAuth ? id : null;
    }

    private static string Normalize(string value) => new string(value.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
}
