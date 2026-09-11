namespace JcfSspr.Broker.Data;

public sealed class TotpEnrollmentEntity
{
    public string ComputerNumber { get; set; } = string.Empty;
    public string ProtectedSecret { get; set; } = string.Empty;
    public long LastAcceptedTimeStep { get; set; } = -1;
    public bool Enabled { get; set; } = true;
    public DateTime UpdatedUtc { get; set; }
}

public sealed class RecoveryCodeEntity
{
    public Guid Id { get; set; }
    public string ComputerNumber { get; set; } = string.Empty;
    public byte[] CodeHash { get; set; } = [];
    public DateTime CreatedUtc { get; set; }
    public DateTime? UsedUtc { get; set; }
}

public sealed class PinCredentialEntity
{
    public string SubjectId { get; set; } = string.Empty;
    public byte[] Salt { get; set; } = [];
    public byte[] Verifier { get; set; } = [];
    public int Iterations { get; set; }
    public int FailedAttempts { get; set; }
    public bool Locked { get; set; }
    public DateTime? LockedUtc { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime UpdatedUtc { get; set; }
}

public sealed class LocalAdminEntity
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public byte[] PasswordSalt { get; set; } = [];
    public byte[] PasswordVerifier { get; set; } = [];
    public int Iterations { get; set; }
    public string ProtectedTotpSecret { get; set; } = string.Empty;
    public long LastAcceptedTimeStep { get; set; } = -1;
    public int FailedAttempts { get; set; }
    public DateTime? BlockedUntilUtc { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime UpdatedUtc { get; set; }
}

public sealed class SelfServiceStatusEntity
{
    public string SubjectId { get; set; } = string.Empty;
    public bool Disabled { get; set; }
    public string DisabledReason { get; set; } = string.Empty;
    public DateTime UpdatedUtc { get; set; }
}

public sealed class SubjectIdentityEntity
{
    public string SubjectId { get; set; } = string.Empty;
    public string ComputerNumber { get; set; } = string.Empty;
    public string RegulationNumber { get; set; } = string.Empty;
    public string EmailAddress { get; set; } = string.Empty;
    public string AdAccountName { get; set; } = string.Empty;
    public Guid? AdObjectGuid { get; set; }
    public string ProvisioningState { get; set; } = "Unlinked";
    public string ProvisioningProfileCode { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
    public DateTime UpdatedUtc { get; set; }
}

public sealed class ThrottleEntity
{
    public string ThrottleKey { get; set; } = string.Empty;
    public DateTime WindowStartUtc { get; set; }
    public int Failures { get; set; }
    public DateTime? BlockUntilUtc { get; set; }
}

public sealed class ApiReplayEntity
{
    public string RequestId { get; set; } = string.Empty;
    public DateTime ExpiresUtc { get; set; }
}

public sealed class ResetTransactionEntity
{
    public byte[] TokenHash { get; set; } = [];
    public string SubjectId { get; set; } = string.Empty;
    public string ComputerNumber { get; set; } = string.Empty;
    public string AccountName { get; set; } = string.Empty;
    public Guid ObjectGuid { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string ClientCertificateId { get; set; } = string.Empty;
    public bool ProfileConfirmed { get; set; }
    public bool RequiresTotpEnrollment { get; set; }
    public DateTime ExpiresUtc { get; set; }
    public DateTime? UsedUtc { get; set; }
    public int PasswordAttempts { get; set; }
}

public sealed class ProvisioningReviewEntity
{
    public Guid Id { get; set; }
    public string SubjectId { get; set; } = string.Empty;
    public string ReasonCode { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public string Status { get; set; } = "Open";
    public DateTime CreatedUtc { get; set; }
    public DateTime? ResolvedUtc { get; set; }
    public string ResolvedBy { get; set; } = string.Empty;
}

public sealed class AuditEntity
{
    public Guid Id { get; set; }
    public string CorrelationId { get; set; } = string.Empty;
    public DateTime TimestampUtc { get; set; }
    public string? SubjectId { get; set; }
    public string? ComputerNumber { get; set; }
    public string? AccountName { get; set; }
    public string? SourceIp { get; set; }
    public string Actor { get; set; } = "SelfService";
    public string Category { get; set; } = "Identity";
    public string Outcome { get; set; } = string.Empty;
    public string DetailCode { get; set; } = string.Empty;
}

public sealed class MemberRecord
{
    public string ComputerNumber { get; init; } = string.Empty;
    public string FirstName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string Trn { get; init; } = string.Empty;
    public DateOnly DateOfBirth { get; init; }
    public string AdAccountName { get; init; } = string.Empty;
    public Guid AdObjectGuid { get; init; }
    public string EmailAddress { get; init; } = string.Empty;
    public override string ToString() => $"MemberRecord {{ ComputerNumber = {ComputerNumber}, AdAccountName = {AdAccountName}, Sensitive = [REDACTED] }}";
}

public sealed class HrPersonRecord
{
    public string SubjectId { get; init; } = string.Empty;
    public string ComputerNumber { get; init; } = string.Empty;
    public string RegulationNumber { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public string FirstName { get; init; } = string.Empty;
    public string MiddleName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string Trn { get; init; } = string.Empty;
    public DateOnly DateOfBirth { get; init; }
    public string EmailAddress { get; init; } = string.Empty;
    public string EmploymentStatus { get; init; } = string.Empty;
    public string PhotoBase64 { get; init; } = string.Empty;
    public string PhotoContentType { get; init; } = "image/jpeg";
    public string DisplayName => string.Join(' ', new[] { FirstName, MiddleName, LastName }.Where(x => !string.IsNullOrWhiteSpace(x)));
    public override string ToString() => $"HrPersonRecord {{ SubjectId = {SubjectId}, Sensitive = [REDACTED] }}";
}

public sealed class AmbiguousIdentityException : Exception
{
    public AmbiguousIdentityException() : base("Identity resolution was ambiguous.") { }
}
