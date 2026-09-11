using System.Security.Cryptography;
using JcfSspr.Broker.Data;
using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Services;

public sealed class ResetTransactionService(SecurityDbContext db, TimeProvider timeProvider)
{
    public Task<string> CreateAsync(MemberRecord member, string sourceIp, string clientCertificateId, CancellationToken ct)
        => CreateAsync(member, string.Empty, false, sourceIp, clientCertificateId, ct);

    public async Task<string> CreateAsync(MemberRecord member, string subjectId, bool requiresTotpEnrollment, string sourceIp, string clientCertificateId, CancellationToken ct)
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var token = Base64Url(tokenBytes);
        db.ResetTransactions.Add(new ResetTransactionEntity
        {
            TokenHash = SHA256.HashData(tokenBytes), SubjectId = subjectId, ComputerNumber = member.ComputerNumber,
            AccountName = member.AdAccountName, ObjectGuid = member.AdObjectGuid, SourceIp = sourceIp,
            ClientCertificateId = clientCertificateId, RequiresTotpEnrollment = requiresTotpEnrollment,
            ExpiresUtc = timeProvider.GetUtcNow().AddMinutes(5).UtcDateTime
        });
        await db.SaveChangesAsync(ct);
        CryptographicOperations.ZeroMemory(tokenBytes);
        return token;
    }

    public async Task<ResetTransactionEntity?> GetUsableAsync(string token, string sourceIp, string clientCertificateId, CancellationToken ct)
    {
        var hash = HashToken(token);
        if (hash is null) return null;
        var transaction = await db.ResetTransactions.SingleOrDefaultAsync(x => x.TokenHash == hash, ct);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (transaction is null || transaction.UsedUtc is not null || transaction.ExpiresUtc <= now || transaction.PasswordAttempts >= 5) return null;
        if (!transaction.SourceIp.Equals(sourceIp, StringComparison.OrdinalIgnoreCase) || !transaction.ClientCertificateId.Equals(clientCertificateId, StringComparison.OrdinalIgnoreCase)) return null;
        return transaction;
    }

    public async Task MarkTotpEnrollmentCompleteAsync(ResetTransactionEntity transaction, CancellationToken ct)
    {
        transaction.RequiresTotpEnrollment = false;
        await db.SaveChangesAsync(ct);
    }

    public async Task IncrementAttemptAsync(ResetTransactionEntity transaction, CancellationToken ct) { transaction.PasswordAttempts++; await db.SaveChangesAsync(ct); }
    public async Task MarkUsedAsync(ResetTransactionEntity transaction, CancellationToken ct) { transaction.UsedUtc = timeProvider.GetUtcNow().UtcDateTime; await db.SaveChangesAsync(ct); }

    private static byte[]? HashToken(string token)
    {
        byte[] raw;
        try { raw = FromBase64Url(token); } catch (FormatException) { return null; }
        if (raw.Length != 32) { CryptographicOperations.ZeroMemory(raw); return null; }
        var hash = SHA256.HashData(raw);
        CryptographicOperations.ZeroMemory(raw);
        return hash;
    }

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static byte[] FromBase64Url(string value) { var s=value.Replace('-','+').Replace('_','/'); s += new string('=', (4-s.Length%4)%4); return Convert.FromBase64String(s); }
}
