using System.Security.Cryptography;
using System.Text;

namespace JcfSspr.Core.Security;

public static class PinHasher
{
    public const int MinimumIterations = 600_000;

    public static bool IsValidPinFormat(string pin, int minimumDigits = 8, int maximumDigits = 12) =>
        pin.Length >= minimumDigits && pin.Length <= maximumDigits && pin.All(char.IsDigit);

    public static byte[] DeriveVerifier(string pin, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> pepper, int iterations)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations);
        var pinBytes = Encoding.UTF8.GetBytes(pin);
        byte[] preHash;
        using (var hmac = new HMACSHA256(pepper.ToArray()))
        {
            preHash = hmac.ComputeHash(pinBytes);
        }
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(preHash, salt, iterations, HashAlgorithmName.SHA256, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
            CryptographicOperations.ZeroMemory(preHash);
        }
    }

    public static bool Verify(string pin, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> pepper, int iterations, ReadOnlySpan<byte> expected)
    {
        var actual = DeriveVerifier(pin, salt, pepper, iterations);
        try { return CryptographicOperations.FixedTimeEquals(actual, expected); }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }
}
