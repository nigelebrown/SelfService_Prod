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

public sealed class ThrottleEntity
{
    public string ThrottleKey { get; set; } = string.Empty;
    public DateTime WindowStartUtc { get; set; }
    public int Failures { get; set; }
    public DateTime? BlockUntilUtc { get; set; }
}

public sealed class ResetTransactionEntity
{
    public byte[] TokenHash { get; set; } = [];
    public string ComputerNumber { get; set; } = string.Empty;
    public string AccountName { get; set; } = string.Empty;
    public Guid ObjectGuid { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string ClientCertificateId { get; set; } = string.Empty;
    public DateTime ExpiresUtc { get; set; }
    public DateTime? UsedUtc { get; set; }
    public int PasswordAttempts { get; set; }
}

public sealed class AuditEntity
{
    public Guid Id { get; set; }
    public string CorrelationId { get; set; } = string.Empty;
    public DateTime TimestampUtc { get; set; }
    public string? ComputerNumber { get; set; }
    public string? AccountName { get; set; }
    public string? SourceIp { get; set; }
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
