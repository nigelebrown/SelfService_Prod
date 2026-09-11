using System.ComponentModel.DataAnnotations;
using JcfSspr.Core.Contracts;

namespace JcfSspr.Portal.Models;

public sealed class IdentityVerificationInput
{
    [Required, StringLength(128), Display(Name = "Username, computer number or regulation number")]
    public string Identifier { get; set; } = string.Empty;

    [Required, Display(Name = "Verification method")]
    public IdentityMethod Method { get; set; } = IdentityMethod.Authenticator;

    [Required, StringLength(128), DataType(DataType.Password), Display(Name = "Authenticator code or secure PIN")]
    public string Secret { get; set; } = string.Empty;

    [StringLength(20), Display(Name = "TRN")]
    public string Trn { get; set; } = string.Empty;

    [DataType(DataType.Date), Display(Name = "Date of birth")]
    public DateOnly? DateOfBirth { get; set; }

    [StringLength(64), Display(Name = "Middle name")]
    public string MiddleName { get; set; } = string.Empty;

    [StringLength(40), Display(Name = "Provisioning code (if provided)")]
    public string ProvisioningCode { get; set; } = string.Empty;

    public override string ToString() => "IdentityVerificationInput [REDACTED]";
}

public sealed class ResetPasswordInput
{
    [Required, StringLength(64, MinimumLength = 14), DataType(DataType.Password), Display(Name = "New password")] public string NewPassword { get; set; } = string.Empty;
    [Required, Compare(nameof(NewPassword)), DataType(DataType.Password), Display(Name = "Confirm new password")] public string ConfirmPassword { get; set; } = string.Empty;
    public override string ToString() => "ResetPasswordInput [REDACTED]";
}
