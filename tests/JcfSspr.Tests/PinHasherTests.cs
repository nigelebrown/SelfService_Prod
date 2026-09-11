using System.Security.Cryptography;
using JcfSspr.Core.Security;

namespace JcfSspr.Tests;

public sealed class PinHasherTests
{
    [Fact]
    public void PinFormatRejectsShortOrNonNumericValues()
    {
        Assert.False(PinHasher.IsValidPinFormat("1234"));
        Assert.False(PinHasher.IsValidPinFormat("1234567A"));
        Assert.True(PinHasher.IsValidPinFormat("12345678"));
    }

    [Fact]
    public void VerifierAcceptsOnlyTheCorrectPin()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var pepper = RandomNumberGenerator.GetBytes(32);
        var verifier = PinHasher.DeriveVerifier("84927516", salt, pepper, PinHasher.MinimumIterations);
        Assert.True(PinHasher.Verify("84927516", salt, pepper, PinHasher.MinimumIterations, verifier));
        Assert.False(PinHasher.Verify("84927517", salt, pepper, PinHasher.MinimumIterations, verifier));
    }

    [Fact]
    public void WeakWorkFactorIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PinHasher.DeriveVerifier("84927516", new byte[16], new byte[32], 10_000));
    }
}
