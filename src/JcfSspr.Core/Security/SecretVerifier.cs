using System.Security.Cryptography;
using System.Text;

namespace JcfSspr.Core.Security;

public static class SecretVerifier
{
    public const int MinimumIterations = 600_000;

    public static byte[] DeriveVerifier(string secret, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> pepper, int iterations)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations);
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        byte[] preHash;
        using (var hmac = new HMACSHA256(pepper.ToArray()))
        {
            preHash = hmac.ComputeHash(secretBytes);
        }
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(preHash, salt, iterations, HashAlgorithmName.SHA256, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            CryptographicOperations.ZeroMemory(preHash);
        }
    }

    public static bool Verify(string secret, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> pepper, int iterations, ReadOnlySpan<byte> expected)
    {
        var actual = DeriveVerifier(secret, salt, pepper, iterations);
        try { return CryptographicOperations.FixedTimeEquals(actual, expected); }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }
}
