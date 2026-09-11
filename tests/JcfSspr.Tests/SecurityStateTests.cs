using System.Security.Cryptography;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Tests;

public sealed class SecurityStateTests
{
    [Fact]
    public async Task PinLocksAfterThreeFailuresAndRequiresAdminUnlock()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync();

        var environmentVariable = "IDENTITY_RECOVERY_PIN_PEPPER_TEST_" + Guid.NewGuid().ToString("N");
        var pepper = RandomNumberGenerator.GetBytes(32);
        Environment.SetEnvironmentVariable(environmentVariable, Convert.ToBase64String(pepper));
        CryptographicOperations.ZeroMemory(pepper);
        try
        {
            var options = Options.Create(new PinSecurityOptions
            {
                MinimumDigits = 8,
                MaximumDigits = 12,
                Pbkdf2Iterations = 600_000,
                LockAfterFailures = 3,
                PepperEnvironmentVariable = environmentVariable
            });
            var service = new PinCredentialService(db, options, TimeProvider.System);
            const string subjectId = "EMP-1001";
            const string correctPin = "82736491";

            await service.SetAsync(subjectId, correctPin, CancellationToken.None);
            Assert.Equal(PinVerificationResult.Failed, await service.VerifyAsync(subjectId, "00000000", CancellationToken.None));
            Assert.Equal(PinVerificationResult.Failed, await service.VerifyAsync(subjectId, "11111111", CancellationToken.None));
            Assert.Equal(PinVerificationResult.Locked, await service.VerifyAsync(subjectId, "22222222", CancellationToken.None));
            Assert.Equal(PinVerificationResult.Locked, await service.VerifyAsync(subjectId, correctPin, CancellationToken.None));

            var locked = await db.PinCredentials.AsNoTracking().SingleAsync(x => x.SubjectId == subjectId);
            Assert.True(locked.Locked);
            Assert.Equal(3, locked.FailedAttempts);
            Assert.NotNull(locked.LockedUtc);

            await service.UnlockAsync(subjectId, CancellationToken.None);
            Assert.Equal(PinVerificationResult.Success, await service.VerifyAsync(subjectId, correctPin, CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable(environmentVariable, null);
        }
    }

    [Fact]
    public async Task ResetTransactionIsBoundToSourceAndClientAndCannotBeReused()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync();

        var service = new ResetTransactionService(db, TimeProvider.System);
        var member = new MemberRecord
        {
            ComputerNumber = "1001",
            FirstName = "Test",
            LastName = "Member",
            Trn = "000000000",
            DateOfBirth = new DateOnly(1990, 1, 1),
            AdAccountName = "tmember",
            AdObjectGuid = Guid.NewGuid(),
            EmailAddress = "test.member@example.invalid"
        };

        var token = await service.CreateAsync(member, "EMP-1001", true, "10.1.2.3", "CERT-A", CancellationToken.None);

        Assert.Null(await service.GetUsableAsync(token, "10.1.2.4", "CERT-A", CancellationToken.None));
        Assert.Null(await service.GetUsableAsync(token, "10.1.2.3", "CERT-B", CancellationToken.None));

        var transaction = await service.GetUsableAsync(token, "10.1.2.3", "CERT-A", CancellationToken.None);
        Assert.NotNull(transaction);
        Assert.False(transaction.ProfileConfirmed);
        Assert.True(transaction.RequiresTotpEnrollment);

        await service.MarkProfileConfirmedAsync(transaction, CancellationToken.None);
        await service.MarkTotpEnrollmentCompleteAsync(transaction, CancellationToken.None);
        Assert.True(transaction.ProfileConfirmed);
        Assert.False(transaction.RequiresTotpEnrollment);

        await service.MarkUsedAsync(transaction, CancellationToken.None);
        Assert.Null(await service.GetUsableAsync(token, "10.1.2.3", "CERT-A", CancellationToken.None));
    }

    private static SecurityDbContext NewDb(SqliteConnection connection)
    {
        var options = new DbContextOptionsBuilder<SecurityDbContext>()
            .UseSqlite(connection)
            .Options;
        return new SecurityDbContext(options);
    }
}
