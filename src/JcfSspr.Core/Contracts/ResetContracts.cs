namespace JcfSspr.Core.Contracts;

public sealed class VerificationRequest
{
    public string ComputerNumber { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Trn { get; set; } = string.Empty;
    public DateOnly DateOfBirth { get; set; }
    public string AuthenticatorCode { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "VerificationRequest [REDACTED]";
}

public sealed class VerificationResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public string TransactionToken { get; init; } = string.Empty;

    public static VerificationResponse Accepted(string correlationId, string token) => new()
    {
        Success = true, CorrelationId = correlationId, TransactionToken = token,
        Message = "Identity verified. Choose your new password."
    };

    public static VerificationResponse Rejected(string correlationId, string? message = null) => new()
    {
        Success = false, CorrelationId = correlationId,
        Message = message ?? "We could not verify this request. Check your information and authenticator code, then try again."
    };
}

public sealed class PasswordResetRequest
{
    public string TransactionToken { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public override string ToString() => "PasswordResetRequest [REDACTED]";
}

public sealed class ResetResponse
{
    public bool Success { get; init; }
    public bool CanRetry { get; init; }
    public string Message { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;

    public static ResetResponse Accepted(string correlationId) => new()
    {
        Success = true, CorrelationId = correlationId, Message = "Your password was reset successfully."
    };

    public static ResetResponse Rejected(string correlationId, string message, bool canRetry = false) => new()
    {
        Success = false, CanRetry = canRetry, CorrelationId = correlationId, Message = message
    };
}
