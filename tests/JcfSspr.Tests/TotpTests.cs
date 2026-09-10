using Xunit;
using JcfSspr.Core.Security;

namespace JcfSspr.Tests;

public sealed class TotpTests
{
    [Fact]
    public void Rfc6238Sha1VectorMatchesForSixDigits()
    {
        const string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var step = 59L / 30L;
        Assert.Equal("287082", Totp.Compute(secret, step));
    }

    [Fact]
    public void VerifyRejectsReplayOfAcceptedTimeStep()
    {
        var secret = Totp.GenerateSecret();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = Totp.GetTimeStep(now);
        var code = Totp.Compute(secret, step);
        Assert.True(Totp.Verify(secret, code, now, -1, out var accepted));
        Assert.Equal(step, accepted);
        Assert.False(Totp.Verify(secret, code, now, accepted, out _));
    }

    [Fact]
    public void Base32RoundTrips()
    {
        var bytes = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        Assert.Equal(bytes, Base32.Decode(Base32.Encode(bytes)));
    }
}
