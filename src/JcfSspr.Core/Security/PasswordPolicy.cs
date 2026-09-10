using System.Text.RegularExpressions;

namespace JcfSspr.Core.Security;

public sealed class PasswordPolicyOptions
{
    public int MinimumLength { get; set; } = 14;
    public int MaximumLength { get; set; } = 64;
    public string[] BlockedTerms { get; set; } = ["password", "jamaica", "police", "jcf"];
}

public sealed record PasswordPolicyResult(bool IsValid, string Message)
{
    public static PasswordPolicyResult Valid() => new(true, string.Empty);
    public static PasswordPolicyResult Invalid(string message) => new(false, message);
}

public static partial class PasswordPolicy
{
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password1!", "qwerty", "qwerty123", "welcome", "welcome1", "letmein",
        "admin", "administrator", "changeme", "12345678", "123456789", "iloveyou", "police1!", "jamaica1!"
    };

    public static PasswordPolicyResult Validate(string? password, PasswordPolicyOptions options, params string?[] memberTerms)
    {
        if (string.IsNullOrEmpty(password)) return PasswordPolicyResult.Invalid("Enter a new password.");
        if (password.Length < options.MinimumLength) return PasswordPolicyResult.Invalid($"Use at least {options.MinimumLength} characters.");
        if (password.Length > options.MaximumLength) return PasswordPolicyResult.Invalid($"Use no more than {options.MaximumLength} characters.");
        if (CommonPasswords.Contains(password)) return PasswordPolicyResult.Invalid("Choose a less common password.");

        var normalized = Normalize(password);
        foreach (var term in options.BlockedTerms.Concat(memberTerms).Where(v => !string.IsNullOrWhiteSpace(v)))
        {
            var blocked = Normalize(term!);
            if (blocked.Length >= 3 && normalized.Contains(blocked, StringComparison.OrdinalIgnoreCase))
                return PasswordPolicyResult.Invalid("The password must not contain your identifying information or common JCF terms.");
        }
        return PasswordPolicyResult.Valid();
    }

    private static string Normalize(string value) => NonAlphaNumeric().Replace(value, string.Empty).ToLowerInvariant();

    [GeneratedRegex("[^a-zA-Z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex NonAlphaNumeric();
}
