using System.Security.Cryptography;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Core.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class PinCredentialService(SecurityDbContext db, IOptions<PinSecurityOptions> options, TimeProvider timeProvider)
{
    private readonly PinSecurityOptions _options = options.Value;

    public async Task<PinVerificationResult> VerifyAsync(string subjectId, string pin, CancellationToken cancellationToken)
    {
        var credential = await db.PinCredentials.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (credential is null || !credential.Enabled) return PinVerificationResult.NotEnrolled;
        if (credential.Locked) return PinVerificationResult.Locked;
        var pepper = LoadPepper();
        var valid = false;
        try { valid = PinHasher.Verify(pin, credential.Salt, pepper, credential.Iterations, credential.Verifier); }
        finally { CryptographicOperations.ZeroMemory(pepper); }

        if (valid)
        {
            credential.FailedAttempts = 0;
            credential.Locked = false;
            credential.LockedUtc = null;
            credential.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
            await db.SaveChangesAsync(cancellationToken);
            return PinVerificationResult.Success;
        }

        credential.FailedAttempts++;
        if (credential.FailedAttempts >= _options.LockAfterFailures)
        {
            credential.Locked = true;
            credential.LockedUtc = timeProvider.GetUtcNow().UtcDateTime;
        }
        credential.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
        return credential.Locked ? PinVerificationResult.Locked : PinVerificationResult.Failed;
    }

    public async Task SetAsync(string subjectId, string pin, CancellationToken cancellationToken)
    {
        if (!PinHasher.IsValidPinFormat(pin, _options.MinimumDigits, _options.MaximumDigits))
            throw new InvalidOperationException($"PIN must contain {_options.MinimumDigits}-{_options.MaximumDigits} digits.");
        var pepper = LoadPepper();
        var salt = RandomNumberGenerator.GetBytes(16);
        byte[] verifier;
        try { verifier = PinHasher.DeriveVerifier(pin, salt, pepper, _options.Pbkdf2Iterations); }
        finally { CryptographicOperations.ZeroMemory(pepper); }
        var entity = await db.PinCredentials.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (entity is null)
        {
            entity = new PinCredentialEntity { SubjectId = subjectId };
            db.PinCredentials.Add(entity);
        }
        entity.Salt = salt;
        entity.Verifier = verifier;
        entity.Iterations = _options.Pbkdf2Iterations;
        entity.FailedAttempts = 0;
        entity.Locked = false;
        entity.LockedUtc = null;
        entity.Enabled = true;
        entity.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task UnlockAsync(string subjectId, CancellationToken cancellationToken)
    {
        var entity = await db.PinCredentials.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (entity is null) return;
        entity.FailedAttempts = 0;
        entity.Locked = false;
        entity.LockedUtc = null;
        entity.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }

    private byte[] LoadPepper()
    {
        var encoded = Environment.GetEnvironmentVariable(_options.PepperEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(encoded)) throw new InvalidOperationException("PIN pepper is not configured.");
        byte[] pepper;
        try { pepper = Convert.FromBase64String(encoded); }
        catch (FormatException ex) { throw new InvalidOperationException("PIN pepper must be base64.", ex); }
        if (pepper.Length < 32) { CryptographicOperations.ZeroMemory(pepper); throw new InvalidOperationException("PIN pepper must be at least 256 bits."); }
        return pepper;
    }
}

public enum PinVerificationResult
{
    Success,
    Failed,
    Locked,
    NotEnrolled
}
