using JcfSspr.Broker.Data;
using JcfSspr.Core.Contracts;
using JcfSspr.Core.Security;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class ResetOrchestrator(MemberDirectoryService members, TotpEnrollmentService enrollment, ThrottleService throttle, ResetTransactionService transactions, ActiveDirectoryResetService directory, SecurityNotifier notifier, AuditService audit, IOptions<PasswordPolicyOptions> policyOptions, TimeProvider timeProvider, ILogger<ResetOrchestrator> logger)
{
    public async Task<VerificationResponse> VerifyAsync(VerificationRequest request, string clientCertificateId, CancellationToken ct)
    {
        var correlationId = Guid.NewGuid().ToString("N");
        var sourceIp = Sanitize(request.ClientIp);
        var number = request.ComputerNumber.Trim();
        try
        {
            if (!Plausible(request))
            {
                await Failure(number, sourceIp, correlationId, "MalformedRequest", ct);
                return VerificationResponse.Rejected(correlationId);
            }
            var decision = await throttle.BeforeAttemptAsync(number, sourceIp, ct);
            if (decision.Blocked)
            {
                await audit.WriteAsync(correlationId, number, null, sourceIp, "Rejected", "SourceRateLimit", ct);
                return VerificationResponse.Rejected(correlationId, "Too many attempts have been received from this connection. Try again later.");
            }
            if (decision.Delay > TimeSpan.Zero) await Task.Delay(decision.Delay, ct);
            var member = await members.VerifyAsync(request, ct);
            if (member is null || !await enrollment.VerifyPossessionFactorAsync(member.ComputerNumber, request.AuthenticatorCode, ct))
            {
                await Failure(number, sourceIp, correlationId, "IdentityOrFactorFailed", ct);
                return VerificationResponse.Rejected(correlationId);
            }
            var token = await transactions.CreateAsync(member, sourceIp, clientCertificateId, ct);
            await audit.WriteAsync(correlationId, member.ComputerNumber, member.AdAccountName, sourceIp, "Success", "IdentityVerified", ct);
            return VerificationResponse.Accepted(correlationId, token);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "SSPR verification failed; correlation {CorrelationId}", correlationId);
            return VerificationResponse.Rejected(correlationId, "The reset service is temporarily unavailable.");
        }
        finally
        {
            request.Trn = string.Empty;
            request.AuthenticatorCode = string.Empty;
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
            await transactions.IncrementAttemptAsync(transaction, ct);
            if (!int.TryParse(transaction.ComputerNumber, out var number)) return ResetResponse.Rejected(correlationId, "This reset session is no longer valid. Start again.");
            var member = await members.FindByComputerNumberAsync(number, ct);
            if (member is null || member.AdObjectGuid != transaction.ObjectGuid || !member.AdAccountName.Equals(transaction.AccountName, StringComparison.OrdinalIgnoreCase))
                return ResetResponse.Rejected(correlationId, "This reset session is no longer valid. Start again.");
            var policy = PasswordPolicy.Validate(request.NewPassword, policyOptions.Value, member.FirstName, member.LastName, member.Trn, member.ComputerNumber, member.AdAccountName);
            if (!policy.IsValid) return ResetResponse.Rejected(correlationId, policy.Message, canRetry: transaction.PasswordAttempts < 5);
            await directory.ResetAsync(member, request.NewPassword, ct);
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
            logger.LogError(ex, "SSPR reset failed; correlation {CorrelationId}", correlationId);
            return ResetResponse.Rejected(correlationId, "The reset service is temporarily unavailable.", canRetry: true);
        }
        finally
        {
            request.NewPassword = string.Empty;
            request.TransactionToken = string.Empty;
        }
    }

    private async Task Failure(string number, string ip, string correlation, string detail, CancellationToken ct)
    {
        await throttle.RecordFailureAsync(number, ip, ct);
        await audit.WriteAsync(correlation, null, null, ip, "Rejected", detail, ct);
    }

    private static bool Plausible(VerificationRequest r) => r.ComputerNumber.Length is > 0 and <= 32 && r.FirstName.Length is > 0 and <= 64 && r.LastName.Length is > 0 and <= 64 && r.Trn.Length is > 0 and <= 20 && r.AuthenticatorCode.Length is > 0 and <= 64;
    private static string Sanitize(string value) => string.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim()[..Math.Min(value.Trim().Length, 64)];
}
