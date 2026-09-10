using System.ComponentModel.DataAnnotations;

namespace JcfSspr.Portal.Models;

public sealed class VerificationInput
{
    [Required, StringLength(32), Display(Name = "Regulation / computer number")] public string ComputerNumber { get; set; } = string.Empty;
    [Required, StringLength(64), Display(Name = "First name")] public string FirstName { get; set; } = string.Empty;
    [Required, StringLength(64), Display(Name = "Last name")] public string LastName { get; set; } = string.Empty;
    [Required, StringLength(20), Display(Name = "TRN")] public string Trn { get; set; } = string.Empty;
    [Required, DataType(DataType.Date), Display(Name = "Date of birth")] public DateOnly? DateOfBirth { get; set; }
    [Required, StringLength(64), Display(Name = "Authenticator or recovery code")] public string AuthenticatorCode { get; set; } = string.Empty;
    public override string ToString() => "VerificationInput [REDACTED]";
}

public sealed class ResetPasswordInput
{
    [Required, StringLength(64, MinimumLength = 14), DataType(DataType.Password), Display(Name = "New password")] public string NewPassword { get; set; } = string.Empty;
    [Required, Compare(nameof(NewPassword)), DataType(DataType.Password), Display(Name = "Confirm new password")] public string ConfirmPassword { get; set; } = string.Empty;
    public override string ToString() => "ResetPasswordInput [REDACTED]";
}
