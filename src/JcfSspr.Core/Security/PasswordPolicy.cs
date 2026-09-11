using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace JcfSspr.Core.Security;

public sealed class PasswordPolicyOptions
{
    public int MinimumLength { get; set; } = 14;
    public int MaximumLength { get; set; } = 64;
    public int MinimumUniqueCharacters { get; set; } = 8;
    public string[] BlockedTerms { get; set; } = ["password", "welcome", "changeme"];
    public string BlockedPasswordFile { get; set; } = string.Empty;
    public bool RequireBlockedPasswordFile { get; set; }
}

public sealed record PasswordPolicyResult(bool IsValid, string Message)
{
    public static PasswordPolicyResult Valid() => new(true, string.Empty);
    public static PasswordPolicyResult Invalid(string message) => new(false, message);
}

public static partial class PasswordPolicy
{
    private static readonly ConcurrentDictionary<string, HashSet<string>> FileLists = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password1!", "qwerty", "qwerty123", "welcome", "welcome1", "letmein",
        "admin", "administrator", "changeme", "12345678", "123456789", "iloveyou", "abc123", "monkey", "dragon"
    };

    public static PasswordPolicyResult Validate(string? password, PasswordPolicyOptions options, params string?[] memberTerms)
    {
        if (string.IsNullOrEmpty(password)) return PasswordPolicyResult.Invalid("Enter a new password.");
        if (password.Length < options.MinimumLength) return PasswordPolicyResult.Invalid($"Use at least {options.MinimumLength} characters.");
        if (password.Length > options.MaximumLength) return PasswordPolicyResult.Invalid($"Use no more than {options.MaximumLength} characters.");
        if (password.Distinct().Count() < Math.Clamp(options.MinimumUniqueCharacters, 4, 20)) return PasswordPolicyResult.Invalid("Choose a password with more unique characters.");
        if (CommonPasswords.Contains(password) || IsFileBlocked(password, options)) return PasswordPolicyResult.Invalid("Choose a password that is not commonly used or compromised.");

        var normalized = Normalize(password);
        foreach (var term in options.BlockedTerms.Concat(memberTerms).Where(v => !string.IsNullOrWhiteSpace(v)))
        {
            var blocked = Normalize(term!);
            if (blocked.Length >= 3 && normalized.Contains(blocked, StringComparison.OrdinalIgnoreCase))
                return PasswordPolicyResult.Invalid("The password must not contain your identifying information or blocked organizational terms.");
        }
        return PasswordPolicyResult.Valid();
    }

    public static bool BlocklistAvailable(PasswordPolicyOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.BlockedPasswordFile)) return !options.RequireBlockedPasswordFile;
        return File.Exists(ResolvePath(options.BlockedPasswordFile));
    }

    private static bool IsFileBlocked(string password, PasswordPolicyOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.BlockedPasswordFile)) return false;
        var path = ResolvePath(options.BlockedPasswordFile);
        if (!File.Exists(path)) return false;
        var list = FileLists.GetOrAdd(path, static p => File.ReadLines(p)
            .Select(x => x.Trim()).Where(x => x.Length > 0 && !x.StartsWith('#')).Take(2_000_000)
            .ToHashSet(StringComparer.OrdinalIgnoreCase));
        return list.Contains(password);
    }

    private static string ResolvePath(string configured) => Path.IsPathRooted(configured) ? configured : Path.Combine(AppContext.BaseDirectory, configured);
    private static string Normalize(string value) => NonAlphaNumeric().Replace(value, string.Empty).ToLowerInvariant();

    [GeneratedRegex("[^a-zA-Z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex NonAlphaNumeric();
}
