namespace JcfSspr.Core.Contracts;

public enum IdentityMethod
{
    Authenticator = 1,
    Pin = 2
}

public sealed class IdentityVerificationRequest
{
    public string Identifier { get; set; } = string.Empty;
    public IdentityMethod Method { get; set; }
    public string Secret { get; set; } = string.Empty;
    public string Trn { get; set; } = string.Empty;
    public DateOnly? DateOfBirth { get; set; }
    public string MiddleName { get; set; } = string.Empty;
    public string ProvisioningCode { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "IdentityVerificationRequest [REDACTED]";
}

public sealed class IdentityProfile
{
    public string DisplayName { get; init; } = string.Empty;
    public string FirstName { get; init; } = string.Empty;
    public string MiddleName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string ComputerNumber { get; init; } = string.Empty;
    public string RegulationNumberMasked { get; init; } = string.Empty;
    public string EmailAddress { get; init; } = string.Empty;
    public string DirectoryStatus { get; init; } = string.Empty;
    public string PhotoDataUri { get; init; } = string.Empty;
    public bool AuthenticatorEnrolled { get; init; }
}

public sealed class IdentityVerificationResponse
{
    public bool Success { get; init; }
    public bool AdminReviewRequired { get; init; }
    public bool AccountCreated { get; init; }
    public bool AuthenticatorEnrollmentRequired { get; init; }
    public string Message { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public string TransactionToken { get; init; } = string.Empty;
    public IdentityProfile? Profile { get; init; }

    public static IdentityVerificationResponse Rejected(string correlationId, string? message = null, bool adminReviewRequired = false) => new()
    {
        Success = false,
        AdminReviewRequired = adminReviewRequired,
        CorrelationId = correlationId,
        Message = message ?? "We could not verify this request. Check the information provided and try again."
    };
}

public sealed class ProfileConfirmationRequest
{
    public string TransactionToken { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "ProfileConfirmationRequest [REDACTED]";
}

public sealed class ProfileConfirmationResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
}

public sealed class TotpEnrollmentStartRequest
{
    public string TransactionToken { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "TotpEnrollmentStartRequest [REDACTED]";
}

public sealed class TotpEnrollmentStartResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string ProtectedState { get; init; } = string.Empty;
    public string ManualSecret { get; init; } = string.Empty;
    public string OtpAuthUri { get; init; } = string.Empty;
}

public sealed class TotpEnrollmentConfirmRequest
{
    public string ProtectedState { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string TransactionToken { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "TotpEnrollmentConfirmRequest [REDACTED]";
}

public sealed class TotpEnrollmentConfirmResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public IReadOnlyList<string> RecoveryCodes { get; init; } = Array.Empty<string>();
}
