using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Security;
using JcfSspr.Broker.Services;
using JcfSspr.Core.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Tests;

public sealed class IdentitySecurityTests
{
    [Fact]
    public void StaticHrAttributesRequireAtLeastTwoMatchingClaims()
    {
        var person = new HrPersonRecord { Trn = "123-456-789", DateOfBirth = new DateOnly(1990, 4, 3), MiddleName = "Alicia" };
        Assert.False(HrIdentityDirectoryService.Corroborates(person, "123456789", null, string.Empty));
        Assert.True(HrIdentityDirectoryService.Corroborates(person, "123456789", new DateOnly(1990, 4, 3), string.Empty));
        Assert.False(HrIdentityDirectoryService.Corroborates(person, "123456789", new DateOnly(1991, 4, 3), "Alicia"));
    }

    [Fact]
    public void SelfServiceRequiresPositiveProvisioningProfileAllowList()
    {
        var options = Options.Create(new ProvisioningOptions
        {
            DefaultProfileCode = "DEFAULT", SelfServiceAllowedProfileCodes = ["DEFAULT"], RequireNestedGroupValidation = false,
            Profiles = [
                new ProvisioningProfileOptions { Code = "DEFAULT", Name = "New", TargetOuDn = "OU=New,DC=test,DC=local", Enabled = true, UserSelectable = true },
                new ProvisioningProfileOptions { Code = "ICT", Name = "ICT", TargetOuDn = "OU=ICT,DC=test,DC=local", Enabled = true, UserSelectable = true }
            ]
        });
        var service = new ProvisioningPolicyService(options, TimeProvider.System);
        Assert.Throws<InvalidOperationException>(() => service.GetForSelfService("ICT"));
        Assert.Equal("ICT", service.GetForAdmin("ICT").Code);
        Assert.Equal("DEFAULT", service.GetForSelfService("DEFAULT").Code);
    }

    [Fact]
    public void SelfServiceGroupRequiresPositiveAllowList()
    {
        const string users = "CN=Baseline,CN=Users,DC=test,DC=local";
        var denied = Options.Create(new ProvisioningOptions { DefaultProfileCode = "DEFAULT", SelfServiceAllowedProfileCodes = ["DEFAULT"], RequireNestedGroupValidation = false, Profiles = [new ProvisioningProfileOptions { Code = "DEFAULT", TargetOuDn = "OU=New,DC=test,DC=local", GroupDns = [users], Enabled = true, UserSelectable = true }] });
        Assert.Throws<InvalidOperationException>(() => new ProvisioningPolicyService(denied, TimeProvider.System).GetForSelfService("DEFAULT"));
        var allowed = Options.Create(new ProvisioningOptions { DefaultProfileCode = "DEFAULT", SelfServiceAllowedProfileCodes = ["DEFAULT"], SelfServiceAllowedGroupDns = [users], RequireNestedGroupValidation = false, Profiles = [new ProvisioningProfileOptions { Code = "DEFAULT", TargetOuDn = "OU=New,DC=test,DC=local", GroupDns = [users], Enabled = true, UserSelectable = true }] });
        Assert.Equal("DEFAULT", new ProvisioningPolicyService(allowed, TimeProvider.System).GetForSelfService("DEFAULT").Code);
    }

    [Fact]
    public void BlockedPrivilegedGroupCannotAppearInProvisioningProfile()
    {
        const string admins = "CN=Domain Admins,CN=Users,DC=test,DC=local";
        var options = Options.Create(new ProvisioningOptions { DefaultProfileCode = "DEFAULT", SelfServiceAllowedProfileCodes = ["DEFAULT"], SelfServiceAllowedGroupDns = [admins], RequireNestedGroupValidation = false, BlockedGroupDns = [admins], Profiles = [new ProvisioningProfileOptions { Code = "DEFAULT", TargetOuDn = "OU=New,DC=test,DC=local", GroupDns = [admins], Enabled = true, UserSelectable = true }] });
        Assert.Throws<InvalidOperationException>(() => new ProvisioningPolicyService(options, TimeProvider.System).GetForSelfService("DEFAULT"));
    }

    [Fact]
    public async Task ApiReplayGuardRejectsDuplicateRequestId()
    {
        var dbOptions = new DbContextOptionsBuilder<SecurityDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new SecurityDbContext(dbOptions);
        var guard = new ApiReplayGuard(db, Options.Create(new BrokerSecurityOptions { ApiReplayWindowSeconds = 120 }), TimeProvider.System);
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Identity-Request-ID"] = Guid.NewGuid().ToString("D");
        context.Request.Headers["X-Identity-Timestamp"] = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(await guard.AcceptAsync(context, "client-cert", CancellationToken.None));
        Assert.False(await guard.AcceptAsync(context, "client-cert", CancellationToken.None));
    }

    [Fact]
    public void SensitiveRequestsNeverRenderSecretsInToString()
    {
        var request = new IdentityVerificationRequest { Identifier = "abc", Secret = "12345678", Trn = "secret" };
        Assert.DoesNotContain("12345678", request.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", request.ToString(), StringComparison.Ordinal);
    }
}
