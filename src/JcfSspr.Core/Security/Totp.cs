using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace JcfSspr.Core.Security;

public static class Totp
{
    public const int PeriodSeconds = 30;
    public const int Digits = 6;

    public static string GenerateSecret(int bytes = 20)
    {
        if (bytes < 20) throw new ArgumentOutOfRangeException(nameof(bytes), "TOTP secrets must be at least 160 bits.");
        return Base32.Encode(RandomNumberGenerator.GetBytes(bytes));
    }

    public static long GetTimeStep(DateTimeOffset instant) => instant.ToUnixTimeSeconds() / PeriodSeconds;

    public static string Compute(string base32Secret, long timeStep)
    {
        var key = Base32.Decode(base32Secret);
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, timeStep);
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);
        var otp = binary % 1_000_000;
        return otp.ToString("D6", CultureInfo.InvariantCulture);
    }

    public static bool Verify(string base32Secret, string candidate, DateTimeOffset now, long minimumTimeStepExclusive, out long acceptedTimeStep, int allowedDriftSteps = 1)
    {
        acceptedTimeStep = -1;
        if (candidate.Length != Digits || candidate.Any(c => c is < '0' or > '9')) return false;
        var current = GetTimeStep(now);
        for (var offset = -allowedDriftSteps; offset <= allowedDriftSteps; offset++)
        {
            var step = current + offset;
            if (step <= minimumTimeStepExclusive) continue;
            var expected = Compute(base32Secret, step);
            if (CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(expected),
                System.Text.Encoding.ASCII.GetBytes(candidate)))
            {
                acceptedTimeStep = step;
                return true;
            }
        }
        return false;
    }
}
