namespace JcfSspr.Broker.Options;

public sealed class MemberDirectoryOptions
{
    public string ViewName { get; set; } = "dbo.IdentityRecoveryDirectory";
    public string[] ActiveEmploymentStatuses { get; set; } = ["ACTIVE"];
}

public sealed class DirectoryOptions
{
    public string Server { get; set; } = string.Empty;
    public int Port { get; set; } = 636;
    public string BaseDn { get; set; } = string.Empty;
    public string ProvisioningSearchBaseDn { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
    public bool RequireChangeAtNextLogon { get; set; }
    public string UpnSuffix { get; set; } = string.Empty;
    public string[] DeniedAccountNames { get; set; } = ["Administrator", "krbtgt"];
    public string[] DeniedGroupDns { get; set; } = [];
}

public sealed class BrokerSecurityOptions
{
    public string[] AllowedClientCertificateThumbprints { get; set; } = [];
    public int SourceFailureLimit { get; set; } = 50;
    public int FailureWindowMinutes { get; set; } = 15;
    public int MaximumDelayMilliseconds { get; set; } = 4000;
    public int ApiReplayWindowSeconds { get; set; } = 120;
}

public sealed class PinSecurityOptions
{
    public int MinimumDigits { get; set; } = 8;
    public int MaximumDigits { get; set; } = 12;
    public int Pbkdf2Iterations { get; set; } = 600_000;
    public int LockAfterFailures { get; set; } = 3;
    public bool RequireCorroborationForPinBootstrap { get; set; } = true;
    public string PepperEnvironmentVariable { get; set; } = "IDENTITY_RECOVERY_PIN_PEPPER";
}

public sealed class LocalAdminSecurityOptions
{
    public int MinimumPasswordLength { get; set; } = 20;
    public int MaximumPasswordLength { get; set; } = 128;
    public int Pbkdf2Iterations { get; set; } = 600_000;
    public int BlockAfterFailures { get; set; } = 5;
    public int BlockMinutes { get; set; } = 30;
    public int SessionMinutes { get; set; } = 15;
    public string PepperEnvironmentVariable { get; set; } = "IDENTITY_RECOVERY_LOCAL_ADMIN_PEPPER";
}

public sealed class AuthenticatorOptions
{
    public string Issuer { get; set; } = "Identity Recovery";
}

public sealed class ProvisioningOptions
{
    public bool AutoCreateEnabled { get; set; } = true;
    public string DefaultProfileCode { get; set; } = "DEFAULT";
    public ProvisioningProfileOptions[] Profiles { get; set; } = [];
    public string[] BlockedGroupDns { get; set; } = [];
    public string[] SelfServiceAllowedProfileCodes { get; set; } = [];
    public string[] SelfServiceAllowedGroupDns { get; set; } = [];
    public bool RequireNestedGroupValidation { get; set; } = true;
    public int GroupValidationRefreshMinutes { get; set; } = 5;
}

public sealed class ProvisioningProfileOptions
{
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string TargetOuDn { get; set; } = string.Empty;
    public string[] GroupDns { get; set; } = [];
    public bool Enabled { get; set; } = true;
    public bool UserSelectable { get; set; }
    public DateTime? EffectiveFromUtc { get; set; }
    public DateTime? EffectiveToUtc { get; set; }
}

public sealed class AdminAuthorizationOptions
{
    public string[] PlatformAdminGroupSids { get; set; } = [];
    public string[] HelpdeskGroupSids { get; set; } = [];
    public string[] ProvisioningAdminGroupSids { get; set; } = [];
    public string[] SecurityAdminGroupSids { get; set; } = [];
    public string[] AuditorGroupSids { get; set; } = [];
    public string[] AllowedGroupSids { get; set; } = [];
}

public sealed class DataProtectionOptions
{
    public string KeyPath { get; set; } = @"C:\ProgramData\IdentityRecovery\keys";
    public string KeyEncryptionCertificateThumbprint { get; set; } = string.Empty;
    public bool RequireCertificateProtection { get; set; }
    public int KeyLifetimeDays { get; set; } = 30;
}

public sealed class NotificationOptions
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 25;
    public bool EnableSsl { get; set; }
    public string From { get; set; } = "REPLACE-NO-REPLY-ADDRESS";
}

public sealed class SecurityAlertOptions
{
    public bool Enabled { get; set; }
    public string[] Recipients { get; set; } = [];
    public int PollSeconds { get; set; } = 30;
    public int MaximumDeliveryAttempts { get; set; } = 10;
    public string[] CriticalDetailCodes { get; set; } =
    [
        "LocalAdminAuthenticated", "LocalBreakGlassRotated", "AuthenticatorRevoked", "PinIssued",
        "AssistedPinRegistered", "SelfServiceDisabled", "ProvisioningProfileApplied",
        "IdentityVerifiedAccountProvisioned", "DirectoryAdminReview", "ProtectedAccount"
    ];
}

public sealed class RetentionOptions
{
    public int SweepMinutes { get; set; } = 30;
    public int ResetTransactionDays { get; set; } = 2;
    public int UsedRecoveryCodeDays { get; set; } = 30;
    public int ThrottleDays { get; set; } = 7;
    public int ClosedReviewDays { get; set; } = 180;
    public int AlertDeliveryDays { get; set; } = 90;
}
