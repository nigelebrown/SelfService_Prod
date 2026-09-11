using System.Security.Cryptography;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Core.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class LocalAdminService(
    SecurityDbContext db,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<LocalAdminSecurityOptions> options,
    IOptions<AuthenticatorOptions> authenticatorOptions,
    TimeProvider timeProvider)
{
    private const int SingletonId = 1;
    private readonly LocalAdminSecurityOptions _options = options.Value;
    private readonly IDataProtector _totpProtector = dataProtectionProvider.CreateProtector("IdentityRecovery.LocalAdminTotp.v1");
    private readonly string _issuer = string.IsNullOrWhiteSpace(authenticatorOptions.Value.Issuer) ? "Identity Recovery" : authenticatorOptions.Value.Issuer.Trim();

    public async Task<LocalAdminStatus> GetStatusAsync(CancellationToken ct)
    {
        var account = await db.LocalAdmins.AsNoTracking().SingleOrDefaultAsync(x => x.Id == SingletonId, ct);
        return account is null
            ? new LocalAdminStatus(false, string.Empty, false, null, 0)
            : new LocalAdminStatus(account.Enabled, account.Username, account.BlockedUntilUtc is not null && account.BlockedUntilUtc > timeProvider.GetUtcNow().UtcDateTime, account.BlockedUntilUtc, account.FailedAttempts);
    }

    public async Task<LocalAdminBootstrap> RotateAsync(string username, string actor, CancellationToken ct)
    {
        username = NormalizeUsername(username);
        if (!IsValidUsername(username)) throw new InvalidOperationException("Local administrator username must be 4-64 characters using letters, digits, period, underscore, or hyphen.");

        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        if (password.Length < _options.MinimumPasswordLength) throw new InvalidOperationException("Generated local administrator password does not meet policy.");
        var totpSecret = Totp.GenerateSecret();
        var salt = RandomNumberGenerator.GetBytes(16);
        var pepper = LoadPepper();
        byte[] verifier;
        try { verifier = SecretVerifier.DeriveVerifier(password, salt, pepper, _options.Pbkdf2Iterations); }
        finally { CryptographicOperations.ZeroMemory(pepper); }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var account = await db.LocalAdmins.SingleOrDefaultAsync(x => x.Id == SingletonId, ct);
        if (account is null)
        {
            account = new LocalAdminEntity { Id = SingletonId };
            db.LocalAdmins.Add(account);
        }
        account.Username = username;
        account.PasswordSalt = salt;
        account.PasswordVerifier = verifier;
        account.Iterations = _options.Pbkdf2Iterations;
        account.ProtectedTotpSecret = _totpProtector.Protect(totpSecret);
        account.LastAcceptedTimeStep = -1;
        account.FailedAttempts = 0;
        account.BlockedUntilUtc = null;
        account.Enabled = true;
        account.UpdatedUtc = now;
        db.Audits.Add(AdminAudit(actor, "LocalBreakGlassRotated", now));
        await db.SaveChangesAsync(ct);

        var label = Uri.EscapeDataString($"{_issuer}:{username}");
        var issuer = Uri.EscapeDataString(_issuer);
        var uri = $"otpauth://totp/{label}?secret={totpSecret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        return new LocalAdminBootstrap(username, password, totpSecret, uri);
    }

    public async Task<LocalAdminAuthenticationResult> AuthenticateAsync(string username, string password, string code, string sourceIp, CancellationToken ct)
    {
        username = NormalizeUsername(username);
        var account = await db.LocalAdmins.AsNoTracking().SingleOrDefaultAsync(x => x.Id == SingletonId, ct);
        var now = timeProvider.GetUtcNow();
        if (account is null || !account.Enabled || !account.Username.Equals(username, StringComparison.OrdinalIgnoreCase))
        {
            await WriteLoginAuditAsync(username, sourceIp, "Rejected", "LocalAdminAuthenticationFailed", ct);
            return LocalAdminAuthenticationResult.Failed;
        }
        if (account.BlockedUntilUtc is DateTime blocked && blocked > now.UtcDateTime)
        {
            await WriteLoginAuditAsync(username, sourceIp, "Rejected", "LocalAdminTemporarilyBlocked", ct);
            return LocalAdminAuthenticationResult.Blocked;
        }

        var pepper = LoadPepper();
        var passwordValid = false;
        try { passwordValid = SecretVerifier.Verify(password, account.PasswordSalt, pepper, account.Iterations, account.PasswordVerifier); }
        finally { CryptographicOperations.ZeroMemory(pepper); }

        var codeValid = false;
        var acceptedStep = -1L;
        if (passwordValid && code.Length == Totp.Digits && code.All(char.IsDigit))
        {
            string secret;
            try { secret = _totpProtector.Unprotect(account.ProtectedTotpSecret); }
            catch { secret = string.Empty; }
            if (!string.IsNullOrWhiteSpace(secret)) codeValid = Totp.Verify(secret, code, now, account.LastAcceptedTimeStep, out acceptedStep);
        }

        if (passwordValid && codeValid)
        {
            var updated = await db.LocalAdmins.Where(x => x.Id == SingletonId && x.Enabled && x.LastAcceptedTimeStep < acceptedStep)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(x => x.LastAcceptedTimeStep, acceptedStep)
                    .SetProperty(x => x.FailedAttempts, 0)
                    .SetProperty(x => x.BlockedUntilUtc, (DateTime?)null)
                    .SetProperty(x => x.UpdatedUtc, now.UtcDateTime), ct);
            if (updated == 1)
            {
                await WriteLoginAuditAsync(username, sourceIp, "Success", "LocalAdminAuthenticated", ct);
                return LocalAdminAuthenticationResult.Success;
            }
        }

        var threshold = Math.Clamp(_options.BlockAfterFailures, 3, 20);
        var blockUntil = now.AddMinutes(Math.Clamp(_options.BlockMinutes, 5, 120)).UtcDateTime;
        await db.LocalAdmins.Where(x => x.Id == SingletonId && x.Enabled)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.FailedAttempts, x => x.FailedAttempts + 1)
                .SetProperty(x => x.BlockedUntilUtc, x => x.FailedAttempts + 1 >= threshold ? blockUntil : x.BlockedUntilUtc)
                .SetProperty(x => x.UpdatedUtc, now.UtcDateTime), ct);
        await WriteLoginAuditAsync(username, sourceIp, "Rejected", "LocalAdminAuthenticationFailed", ct);
        var latest = await db.LocalAdmins.AsNoTracking().SingleAsync(x => x.Id == SingletonId, ct);
        return latest.BlockedUntilUtc is DateTime latestBlock && latestBlock > now.UtcDateTime
            ? LocalAdminAuthenticationResult.Blocked
            : LocalAdminAuthenticationResult.Failed;
    }

    public async Task UnlockAsync(string actor, CancellationToken ct)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await db.LocalAdmins.Where(x => x.Id == SingletonId).ExecuteUpdateAsync(setters => setters
            .SetProperty(x => x.FailedAttempts, 0)
            .SetProperty(x => x.BlockedUntilUtc, (DateTime?)null)
            .SetProperty(x => x.UpdatedUtc, now), ct);
        db.Audits.Add(AdminAudit(actor, "LocalBreakGlassUnlocked", now));
        await db.SaveChangesAsync(ct);
    }

    public async Task DisableAsync(string actor, CancellationToken ct)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await db.LocalAdmins.Where(x => x.Id == SingletonId).ExecuteUpdateAsync(setters => setters
            .SetProperty(x => x.Enabled, false)
            .SetProperty(x => x.UpdatedUtc, now), ct);
        db.Audits.Add(AdminAudit(actor, "LocalBreakGlassDisabled", now));
        await db.SaveChangesAsync(ct);
    }

    private async Task WriteLoginAuditAsync(string username, string sourceIp, string outcome, string detailCode, CancellationToken ct)
    {
        db.Audits.Add(new AuditEntity
        {
            Id = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = timeProvider.GetUtcNow().UtcDateTime,
            Actor = "LocalAdmin:" + username, Category = "Administration", SourceIp = sourceIp[..Math.Min(sourceIp.Length, 64)], Outcome = outcome, DetailCode = detailCode
        });
        await db.SaveChangesAsync(ct);
    }

    private static AuditEntity AdminAudit(string actor, string detailCode, DateTime now) => new()
    {
        Id = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = now,
        Actor = actor, Category = "Administration", Outcome = "Success", DetailCode = detailCode
    };

    private byte[] LoadPepper()
    {
        var encoded = Environment.GetEnvironmentVariable(_options.PepperEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(encoded)) throw new InvalidOperationException("Local administrator pepper is not configured.");
        byte[] pepper;
        try { pepper = Convert.FromBase64String(encoded); }
        catch (FormatException ex) { throw new InvalidOperationException("Local administrator pepper must be base64.", ex); }
        if (pepper.Length < 32) { CryptographicOperations.ZeroMemory(pepper); throw new InvalidOperationException("Local administrator pepper must be at least 256 bits."); }
        return pepper;
    }

    private static string NormalizeUsername(string value) => value.Trim();
    private static bool IsValidUsername(string value) => value.Length is >= 4 and <= 64 && value.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-');
}

public enum LocalAdminAuthenticationResult { Success, Failed, Blocked }
public sealed record LocalAdminBootstrap(string Username, string Password, string ManualTotpSecret, string OtpAuthUri);
public sealed record LocalAdminStatus(bool Enabled, string Username, bool TemporarilyBlocked, DateTime? BlockedUntilUtc, int FailedAttempts);
