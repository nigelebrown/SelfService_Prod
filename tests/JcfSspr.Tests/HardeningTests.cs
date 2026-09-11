using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Services;
using JcfSspr.Core.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

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
    public void ProvisioningGroupValidationFailsClosedUntilGroupIsExplicitlyValidated()
    {
        var group = $"CN=Baseline-{Guid.NewGuid():N},OU=Groups,DC=test,DC=local";
        var options = Options.Create(new ProvisioningOptions
        {
            DefaultProfileCode = "DEFAULT", SelfServiceAllowedProfileCodes = ["DEFAULT"], SelfServiceAllowedGroupDns = [group], RequireNestedGroupValidation = true,
            Profiles = [new ProvisioningProfileOptions { Code = "DEFAULT", TargetOuDn = "OU=New,DC=test,DC=local", GroupDns = [group], Enabled = true, UserSelectable = true }]
        });
        var service = new ProvisioningPolicyService(options, TimeProvider.System);
        Assert.Throws<InvalidOperationException>(() => service.GetForSelfService("DEFAULT"));
        ProvisioningGroupSafetyRegistry.MarkSafe(group, DateTime.UtcNow);
        Assert.Equal("DEFAULT", service.GetForSelfService("DEFAULT").Code);
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
