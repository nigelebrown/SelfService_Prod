using System.Security.Cryptography;
using System.Text.Json;
using JcfSspr.Broker.Data;
using JcfSspr.Core.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Services;

public sealed class TotpEnrollmentService(SecurityDbContext db, IDataProtectionProvider dataProtectionProvider, TimeProvider timeProvider)
{
    private readonly IDataProtector _secretProtector = dataProtectionProvider.CreateProtector("JcfSspr.TotpSecret.v1");
    private readonly ITimeLimitedDataProtector _stateProtector = dataProtectionProvider.CreateProtector("JcfSspr.EnrollmentState.v1").ToTimeLimitedDataProtector();

    public EnrollmentStart Begin(MemberRecord member)
    {
        var secret = Totp.GenerateSecret();
        var state = new EnrollmentState(member.ComputerNumber, member.AdAccountName, secret);
        var token = _stateProtector.Protect(JsonSerializer.Serialize(state), TimeSpan.FromMinutes(10));
        var label = Uri.EscapeDataString($"JCF:{member.AdAccountName}");
        var issuer = Uri.EscapeDataString("Jamaica Constabulary Force");
        var uri = $"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        return new EnrollmentStart(token, secret, uri);
    }

    public async Task<IReadOnlyList<string>> ConfirmAsync(string protectedState, string code, string expectedAccountName, CancellationToken cancellationToken)
    {
        var json = _stateProtector.Unprotect(protectedState);
        var state = JsonSerializer.Deserialize<EnrollmentState>(json) ?? throw new InvalidOperationException("Enrollment state is invalid.");
        if (!state.AdAccountName.Equals(expectedAccountName, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Enrollment identity changed.");
        if (!Totp.Verify(state.Secret, NormalizeCode(code), timeProvider.GetUtcNow(), -1, out var acceptedStep)) throw new InvalidOperationException("The authenticator code is not valid.");

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var enrollment = await db.TotpEnrollments.FindAsync([state.ComputerNumber], cancellationToken);
        if (enrollment is null)
        {
            enrollment = new TotpEnrollmentEntity { ComputerNumber = state.ComputerNumber };
            db.TotpEnrollments.Add(enrollment);
        }
        enrollment.ProtectedSecret = _secretProtector.Protect(state.Secret);
        enrollment.LastAcceptedTimeStep = acceptedStep;
        enrollment.Enabled = true;
        enrollment.UpdatedUtc = now;

        var oldCodes = await db.RecoveryCodes.Where(x => x.ComputerNumber == state.ComputerNumber && x.UsedUtc == null).ToListAsync(cancellationToken);
        db.RecoveryCodes.RemoveRange(oldCodes);
        var displayCodes = Enumerable.Range(0, 8).Select(_ => NewRecoveryCode()).ToArray();
        foreach (var displayCode in displayCodes)
        {
            db.RecoveryCodes.Add(new RecoveryCodeEntity
            {
                Id = Guid.NewGuid(), ComputerNumber = state.ComputerNumber, CodeHash = HashRecoveryCode(displayCode), CreatedUtc = now
            });
        }
        await db.SaveChangesAsync(cancellationToken);
        return displayCodes;
    }

    public async Task<bool> VerifyPossessionFactorAsync(string computerNumber, string candidate, CancellationToken cancellationToken)
    {
        var normalized = NormalizeCode(candidate);
        var enrollment = await db.TotpEnrollments.SingleOrDefaultAsync(x => x.ComputerNumber == computerNumber && x.Enabled, cancellationToken);
        if (enrollment is null) return false;

        if (normalized.Length == 6 && normalized.All(char.IsDigit))
        {
            var secret = _secretProtector.Unprotect(enrollment.ProtectedSecret);
            if (!Totp.Verify(secret, normalized, timeProvider.GetUtcNow(), enrollment.LastAcceptedTimeStep, out var acceptedStep)) return false;
            enrollment.LastAcceptedTimeStep = acceptedStep;
            enrollment.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }

        var hash = HashRecoveryCode(candidate);
        var codes = await db.RecoveryCodes.Where(x => x.ComputerNumber == computerNumber && x.UsedUtc == null).ToListAsync(cancellationToken);
        var match = codes.FirstOrDefault(x => CryptographicOperations.FixedTimeEquals(x.CodeHash, hash));
        if (match is null) return false;
        match.UsedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static string NewRecoveryCode()
    {
        var text = Convert.ToHexString(RandomNumberGenerator.GetBytes(10));
        return string.Join('-', Enumerable.Range(0, 4).Select(i => text.Substring(i * 5, 5)));
    }

    private static byte[] HashRecoveryCode(string code) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(NormalizeRecoveryCode(code)));
    private static string NormalizeRecoveryCode(string code) => new(code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
    private static string NormalizeCode(string code) => code.Trim().Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);

    private sealed record EnrollmentState(string ComputerNumber, string AdAccountName, string Secret);
}

public sealed record EnrollmentStart(string ProtectedState, string Secret, string OtpAuthUri);
