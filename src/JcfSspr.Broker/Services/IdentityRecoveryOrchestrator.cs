using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Core.Contracts;
using JcfSspr.Core.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class IdentityRecoveryOrchestrator(
    HrIdentityDirectoryService hr,
    PinCredentialService pins,
    TotpEnrollmentService totp,
    ThrottleService throttle,
    DirectoryProvisioningService directoryProvisioning,
    ResetTransactionService transactions,
    ActiveDirectoryResetService directoryReset,
    SecurityNotifier notifier,
    AuditService audit,
    SecurityDbContext db,
    IOptions<PinSecurityOptions> pinOptions,
    IOptions<PasswordPolicyOptions> passwordOptions,
    TimeProvider timeProvider,
    ILogger<IdentityRecoveryOrchestrator> logger)
{
    private static readonly Action<ILogger, string, Exception?> VerificationError = LoggerMessage.Define<string>(LogLevel.Error, new EventId(2101, "IdentityVerificationError"), "Identity verification failed; correlation {CorrelationId}");
    private static readonly Action<ILogger, string, Exception?> ResetError = LoggerMessage.Define<string>(LogLevel.Error, new EventId(2102, "IdentityResetError"), "Identity reset failed; correlation {CorrelationId}");
    private readonly PinSecurityOptions _pinOptions = pinOptions.Value;
    private readonly PasswordPolicyOptions _passwordOptions = passwordOptions.Value;

    public async Task<IdentityVerificationResponse> VerifyAsync(IdentityVerificationRequest request, string clientCertificateId, CancellationToken ct)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var identifier = request.Identifier.Trim();
        var sourceIp = Sanitize(request.ClientIp);
        try
        {
            if (identifier.Length is < 2 or > 128 || request.Secret.Length is < 1 or > 128)
                return IdentityVerificationResponse.Rejected(correlationId);
            var decision = await throttle.BeforeAttemptAsync(identifier, sourceIp, ct);
            if (decision.Blocked) return IdentityVerificationResponse.Rejected(correlationId, "Too many attempts have been received from this connection. Try again later.");
            if (decision.Delay > TimeSpan.Zero) await Task.Delay(decision.Delay, ct);

            HrPersonRecord? person;
            try { person = await hr.FindByIdentifierAsync(identifier, ct); }
            catch (AmbiguousIdentityException)
            {
                await throttle.RecordFailureAsync(identifier, sourceIp, ct);
                await audit.WriteAsync(correlationId, null, null, sourceIp, "Rejected", "AmbiguousIdentity", ct);
                return IdentityVerificationResponse.Rejected(correlationId);
            }
            if (person is null)
            {
                await throttle.RecordFailureAsync(identifier, sourceIp, ct);
                return IdentityVerificationResponse.Rejected(correlationId);
            }
            var status = await db.SelfServiceStatuses.AsNoTracking().SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, ct);
            if (status?.Disabled == true)
            {
                await audit.WriteAsync(correlationId, person.ComputerNumber, null, sourceIp, "Rejected", "SelfServiceDisabled", ct);
                return IdentityVerificationResponse.Rejected(correlationId, "Self-service is unavailable for this profile. Contact an administrator.");
            }

            var enrolled = await totp.IsEnrolledAsync(person.ComputerNumber, ct);
            var authenticated = false;
            if (request.Method == IdentityMethod.Authenticator)
            {
                authenticated = enrolled && await totp.VerifyPossessionFactorAsync(person.ComputerNumber, request.Secret, ct);
            }
            else if (request.Method == IdentityMethod.Pin)
            {
                if (!enrolled && _pinOptions.RequireCorroborationForPinBootstrap && !HrIdentityDirectoryService.Corroborates(person, request.Trn, request.DateOfBirth, request.MiddleName))
                {
                    await throttle.RecordFailureAsync(identifier, sourceIp, ct);
                    return IdentityVerificationResponse.Rejected(correlationId);
                }
                var result = await pins.VerifyAsync(person.SubjectId, request.Secret, ct);
                authenticated = result == PinVerificationResult.Success;
                if (result == PinVerificationResult.Locked)
                {
                    await audit.WriteAsync(correlationId, person.ComputerNumber, null, sourceIp, "Rejected", "PinMethodLocked", ct);
                    return IdentityVerificationResponse.Rejected(correlationId, "The PIN verification method is locked. Use an enrolled authenticator or contact an administrator.");
                }
            }

            if (!authenticated)
            {
                await throttle.RecordFailureAsync(identifier, sourceIp, ct);
                await audit.WriteAsync(correlationId, person.ComputerNumber, null, sourceIp, "Rejected", "AuthenticationFailed", ct);
                return IdentityVerificationResponse.Rejected(correlationId);
            }

            var resolution = await directoryProvisioning.ResolveOrProvisionAsync(person, request.ProvisioningCode, ct);
            if (resolution.AdminReviewRequired || resolution.Member is null)
            {
                await audit.WriteAsync(correlationId, person.ComputerNumber, null, sourceIp, "Pending", "DirectoryAdminReview", ct);
                return IdentityVerificationResponse.Rejected(correlationId, "Your identity was verified, but the directory account requires administrator review before self-service can continue.", true);
            }

            var requireEnrollment = request.Method == IdentityMethod.Pin && !enrolled;
            var token = await transactions.CreateAsync(resolution.Member, person.SubjectId, requireEnrollment, sourceIp, clientCertificateId, ct);
            await audit.WriteAsync(correlationId, person.ComputerNumber, resolution.Member.AdAccountName, sourceIp, "Success", resolution.AccountCreated ? "IdentityVerifiedAccountProvisioned" : "IdentityVerified", ct);
            return new IdentityVerificationResponse
            {
                Success = true,
                AccountCreated = resolution.AccountCreated,
                AuthenticatorEnrollmentRequired = requireEnrollment,
                CorrelationId = correlationId,
                TransactionToken = token,
                Message = requireEnrollment ? "Identity verified. Confirm your profile, then register an authenticator before completing account recovery." : "Identity verified. Confirm your profile to continue.",
                Profile = BuildProfile(person, resolution.State, enrolled)
            };
        }
        catch (Exception ex)
        {
            VerificationError(logger, correlationId, ex);
            return IdentityVerificationResponse.Rejected(correlationId, "The identity service is temporarily unavailable.");
        }
        finally
        {
            request.Secret = string.Empty;
            request.Trn = string.Empty;
        }
    }

    public async Task<ProfileConfirmationResponse> ConfirmProfileAsync(ProfileConfirmationRequest request, string clientCertificateId, CancellationToken ct)
    {
        var sourceIp = Sanitize(request.ClientIp);
        try
        {
            var transaction = await transactions.GetUsableAsync(request.TransactionToken, sourceIp, clientCertificateId, ct);
            if (transaction is null || string.IsNullOrWhiteSpace(transaction.SubjectId)) return new ProfileConfirmationResponse { Message = "This recovery session is no longer valid." };
            var person = await hr.FindBySubjectIdAsync(transaction.SubjectId, ct);
            if (person is null) return new ProfileConfirmationResponse { Message = "This recovery session is no longer valid." };
            await transactions.MarkProfileConfirmedAsync(transaction, ct);
            await audit.WriteAsync(Guid.NewGuid().ToString("N"), person.ComputerNumber, transaction.AccountName, sourceIp, "Success", "ProfileConfirmed", ct);
            return new ProfileConfirmationResponse { Success = true, Message = "Profile confirmed." };
        }
        finally
        {
            request.TransactionToken = string.Empty;
        }
    }

    public async Task<TotpEnrollmentStartResponse> StartAuthenticatorEnrollmentAsync(TotpEnrollmentStartRequest request, string clientCertificateId, CancellationToken ct)
    {
        var transaction = await transactions.GetUsableAsync(request.TransactionToken, Sanitize(request.ClientIp), clientCertificateId, ct);
        if (transaction is null || !transaction.ProfileConfirmed || string.IsNullOrWhiteSpace(transaction.SubjectId)) return new TotpEnrollmentStartResponse { Message = "This registration session is no longer valid or the profile has not been confirmed." };
        var person = await hr.FindBySubjectIdAsync(transaction.SubjectId, ct);
        if (person is null) return new TotpEnrollmentStartResponse { Message = "This registration session is no longer valid." };
        var member = MemberFromTransaction(person, transaction);
        var start = totp.Begin(member);
        return new TotpEnrollmentStartResponse { Success = true, ProtectedState = start.ProtectedState, ManualSecret = start.Secret, OtpAuthUri = start.OtpAuthUri };
    }

    public async Task<TotpEnrollmentConfirmResponse> ConfirmAuthenticatorEnrollmentAsync(TotpEnrollmentConfirmRequest request, string clientCertificateId, CancellationToken ct)
    {
        var transaction = await transactions.GetUsableAsync(request.TransactionToken, Sanitize(request.ClientIp), clientCertificateId, ct);
        if (transaction is null || !transaction.ProfileConfirmed) return new TotpEnrollmentConfirmResponse { Message = "This registration session is no longer valid or the profile has not been confirmed." };
        try
        {
            var codes = await totp.ConfirmAsync(request.ProtectedState, request.Code, transaction.AccountName, ct);
            await transactions.MarkTotpEnrollmentCompleteAsync(transaction, ct);
            return new TotpEnrollmentConfirmResponse { Success = true, Message = "Authenticator registration completed.", RecoveryCodes = codes };
        }
        catch
        {
            return new TotpEnrollmentConfirmResponse { Message = "Authenticator registration could not be confirmed. Start again and enter the current code." };
        }
        finally
        {
            request.Code = string.Empty;
            request.ProtectedState = string.Empty;
        }
    }

    public async Task<ResetResponse> ResetAsync(PasswordResetRequest request, string clientCertificateId, CancellationToken ct)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sourceIp = Sanitize(request.ClientIp);
        try
        {
            var transaction = await transactions.GetUsableAsync(request.TransactionToken, sourceIp, clientCertificateId, ct);
            if (transaction is null) return ResetResponse.Rejected(correlationId, "This reset session has expired or is no longer valid. Start again.");
            if (!transaction.ProfileConfirmed) return ResetResponse.Rejected(correlationId, "Confirm the verified profile before completing this reset.");
            if (transaction.RequiresTotpEnrollment) return ResetResponse.Rejected(correlationId, "Register your authenticator before completing this reset.");
            await transactions.IncrementAttemptAsync(transaction, ct);
            var person = string.IsNullOrWhiteSpace(transaction.SubjectId) ? null : await hr.FindBySubjectIdAsync(transaction.SubjectId, ct);
            if (person is null) return ResetResponse.Rejected(correlationId, "This reset session is no longer valid. Start again.");
            var link = await db.SubjectIdentities.AsNoTracking().SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, ct);
            if (link?.AdObjectGuid != transaction.ObjectGuid || !link.AdAccountName.Equals(transaction.AccountName, StringComparison.OrdinalIgnoreCase))
                return ResetResponse.Rejected(correlationId, "This reset session is no longer valid. Start again.");
            var member = MemberFromTransaction(person, transaction);
            var policy = PasswordPolicy.Validate(request.NewPassword, _passwordOptions, member.FirstName, member.LastName, member.Trn, member.ComputerNumber, member.AdAccountName);
            if (!policy.IsValid) return ResetResponse.Rejected(correlationId, policy.Message, canRetry: transaction.PasswordAttempts < 5);
            await directoryReset.ResetAsync(member, request.NewPassword, ct);
            await directoryProvisioning.CompleteNewAccountAsync(person.SubjectId, ct);
            await transactions.MarkUsedAsync(transaction, ct);
            await audit.WriteAsync(correlationId, member.ComputerNumber, member.AdAccountName, sourceIp, "Success", "PasswordReset", ct);
            await notifier.NotifyResetAsync(member, timeProvider.GetUtcNow(), ct);
            return ResetResponse.Accepted(correlationId);
        }
        catch (ProtectedAccountException)
        {
            await audit.WriteAsync(correlationId, null, null, sourceIp, "Rejected", "ProtectedAccount", ct);
            return ResetResponse.Rejected(correlationId, "This account cannot be reset through self-service.");
        }
        catch (Exception ex)
        {
            ResetError(logger, correlationId, ex);
            return ResetResponse.Rejected(correlationId, "The reset service is temporarily unavailable.", canRetry: true);
        }
        finally
        {
            request.NewPassword = string.Empty;
            request.TransactionToken = string.Empty;
        }
    }

    private static IdentityProfile BuildProfile(HrPersonRecord person, string directoryStatus, bool enrolled)
    {
        var digits = new string(person.RegulationNumber.Where(char.IsLetterOrDigit).ToArray());
        var masked = digits.Length <= 4 ? new string('*', digits.Length) : new string('*', digits.Length - 4) + digits[^4..];
        var photo = string.IsNullOrWhiteSpace(person.PhotoBase64) ? string.Empty : $"data:{person.PhotoContentType};base64,{person.PhotoBase64}";
        return new IdentityProfile
        {
            DisplayName = person.DisplayName, FirstName = person.FirstName, MiddleName = person.MiddleName, LastName = person.LastName,
            ComputerNumber = person.ComputerNumber, RegulationNumberMasked = masked, EmailAddress = person.EmailAddress,
            DirectoryStatus = directoryStatus, PhotoDataUri = photo, AuthenticatorEnrolled = enrolled
        };
    }

    private static MemberRecord MemberFromTransaction(HrPersonRecord person, ResetTransactionEntity transaction) => new()
    {
        ComputerNumber = person.ComputerNumber, FirstName = person.FirstName, LastName = person.LastName, Trn = person.Trn,
        DateOfBirth = person.DateOfBirth, AdAccountName = transaction.AccountName, AdObjectGuid = transaction.ObjectGuid, EmailAddress = person.EmailAddress
    };

    private static string Sanitize(string value)
    {
        var trimmed = value.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? "unknown" : trimmed[..Math.Min(trimmed.Length, 64)];
    }
}
