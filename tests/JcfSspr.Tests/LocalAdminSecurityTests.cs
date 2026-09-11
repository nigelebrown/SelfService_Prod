using System.Security.Cryptography;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Tests;

public sealed class LocalAdminSecurityTests
{
    [Fact]
    public async Task LocalAdminRequiresPasswordAndTotpAndRejectsTotpReplay()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync();
        var env = "IDENTITY_RECOVERY_LOCAL_ADMIN_PEPPER_TEST_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(env, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        try
        {
            var service = NewService(db, env);
            var bootstrap = await service.RotateAsync("breakglass-admin", "DOMAIN\\admin", CancellationToken.None);
            var code = JcfSspr.Core.Security.Totp.Compute(bootstrap.ManualTotpSecret, JcfSspr.Core.Security.Totp.GetTimeStep(DateTimeOffset.UtcNow));

            Assert.Equal(LocalAdminAuthenticationResult.Failed, await service.AuthenticateAsync("breakglass-admin", "wrong-password", code, "10.0.0.10", CancellationToken.None));
            Assert.Equal(LocalAdminAuthenticationResult.Success, await service.AuthenticateAsync("breakglass-admin", bootstrap.Password, code, "10.0.0.10", CancellationToken.None));
            Assert.NotEqual(LocalAdminAuthenticationResult.Success, await service.AuthenticateAsync("breakglass-admin", bootstrap.Password, code, "10.0.0.10", CancellationToken.None));
        }
        finally { Environment.SetEnvironmentVariable(env, null); }
    }

    [Fact]
    public async Task LocalAdminCredentialsAreStoredOnlyAsVerifierAndProtectedTotp()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = NewDb(connection);
        await db.Database.EnsureCreatedAsync();
        var env = "IDENTITY_RECOVERY_LOCAL_ADMIN_PEPPER_TEST_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(env, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        try
        {
            var service = NewService(db, env);
            var bootstrap = await service.RotateAsync("breakglass-admin", "DOMAIN\\admin", CancellationToken.None);
            var stored = await db.LocalAdmins.AsNoTracking().SingleAsync();
            Assert.NotEmpty(stored.PasswordSalt);
            Assert.NotEmpty(stored.PasswordVerifier);
            Assert.DoesNotContain(bootstrap.Password, Convert.ToBase64String(stored.PasswordVerifier), StringComparison.Ordinal);
            Assert.DoesNotContain(bootstrap.ManualTotpSecret, stored.ProtectedTotpSecret, StringComparison.Ordinal);
        }
        finally { Environment.SetEnvironmentVariable(env, null); }
    }

    private static LocalAdminService NewService(SecurityDbContext db, string env)
    {
        var local = Options.Create(new LocalAdminSecurityOptions { PepperEnvironmentVariable = env, Pbkdf2Iterations = 600_000, MinimumPasswordLength = 20, BlockAfterFailures = 5, BlockMinutes = 30, SessionMinutes = 15 });
        var auth = Options.Create(new AuthenticatorOptions { Issuer = "Identity Recovery Test" });
        return new LocalAdminService(db, new EphemeralDataProtectionProvider(), local, auth, TimeProvider.System);
    }

    private static SecurityDbContext NewDb(SqliteConnection connection) => new(new DbContextOptionsBuilder<SecurityDbContext>().UseSqlite(connection).Options);
}
