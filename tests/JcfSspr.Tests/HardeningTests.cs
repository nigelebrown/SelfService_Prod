using JcfSspr.Broker.Data;
using JcfSspr.Core.Security;
using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Tests;

public sealed class HardeningTests
{
    [Fact]
    public void PasswordBlocklistFileRejectsListedPassword()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "ThisPasswordWasBreached!\n");
            var options = new PasswordPolicyOptions { MinimumLength = 14, MinimumUniqueCharacters = 6, BlockedPasswordFile = path, RequireBlockedPasswordFile = true };
            var result = PasswordPolicy.Validate("ThisPasswordWasBreached!", options);
            Assert.False(result.IsValid);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task AuditEntityCannotBeModifiedThroughApplicationDbContext()
    {
        var interceptor = new AuditAppendOnlyInterceptor();
        var dbOptions = new DbContextOptionsBuilder<SecurityDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).AddInterceptors(interceptor).Options;
        await using var db = new SecurityDbContext(dbOptions);
        var audit = new AuditEntity { Id = Guid.NewGuid(), CorrelationId = "c", TimestampUtc = DateTime.UtcNow, Outcome = "Success", DetailCode = "Test" };
        db.Audits.Add(audit);
        await db.SaveChangesAsync();
        audit.Outcome = "Changed";
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }
}
