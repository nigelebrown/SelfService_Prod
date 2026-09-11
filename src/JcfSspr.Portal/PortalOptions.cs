namespace JcfSspr.Portal;

public sealed class PortalOptions
{
    public string Name { get; set; } = "Identity Recovery & Self-Service Portal";
    public string ListenUrl { get; set; } = "http://127.0.0.1:5130";
    public string BrokerUrl { get; set; } = string.Empty;
    public string ClientCertificateThumbprint { get; set; } = string.Empty;
    public int RequestTimeoutSeconds { get; set; } = 30;
    public string TrustedProxyIp { get; set; } = string.Empty;
    public bool KioskMode { get; set; }
    public int KioskIdleMinutes { get; set; } = 3;
    public string DataProtectionKeyPath { get; set; } = string.Empty;
    public string DataProtectionCertificateThumbprint { get; set; } = string.Empty;
    public bool RequirePersistentDataProtection { get; set; }
}
