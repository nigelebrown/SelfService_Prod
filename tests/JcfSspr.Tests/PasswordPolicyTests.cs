using Xunit;
using JcfSspr.Core.Security;

namespace JcfSspr.Tests;

public sealed class PasswordPolicyTests
{
    private readonly PasswordPolicyOptions _options = new() { MinimumLength = 14, MaximumLength = 64, BlockedTerms = ["jcf", "police"] };

    [Fact]
    public void RejectsMemberIdentityTerms() => Assert.False(PasswordPolicy.Validate("Brown-Excellent-2026", _options, "Brown").IsValid);

    [Fact]
    public void AcceptsLongPassphraseWithoutCompositionRules() => Assert.True(PasswordPolicy.Validate("violet harbor climbs quietly", _options, "Brown", "12345").IsValid);

    [Fact]
    public void RejectsTooShort() => Assert.False(PasswordPolicy.Validate("short phrase", _options).IsValid);
}
