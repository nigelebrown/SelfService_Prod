namespace JcfSspr.Broker.Options;

public sealed class MemberDirectoryOptions
{
    public string ViewName { get; set; } = "dbo.AD_ResetList";
}

public sealed class DirectoryOptions
{
    public string Server { get; set; } = string.Empty;
    public int Port { get; set; } = 636;
    public string BaseDn { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
    public bool RequireChangeAtNextLogon { get; set; } = true;
    public string[] DeniedAccountNames { get; set; } = ["Administrator", "krbtgt"];
    public string[] DeniedGroupDns { get; set; } = [];
}

public sealed class BrokerSecurityOptions
{
    public string[] AllowedClientCertificateThumbprints { get; set; } = [];
    public int SourceFailureLimit { get; set; } = 50;
    public int FailureWindowMinutes { get; set; } = 15;
    public int MaximumDelayMilliseconds { get; set; } = 4000;
}

public sealed class DataProtectionOptions
{
    public string KeyPath { get; set; } = @"C:\ProgramData\JcfSspr\keys";
}

public sealed class NotificationOptions
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 25;
    public bool EnableSsl { get; set; }
    public string From { get; set; } = "no-reply@jcf.gov.jm";
}
