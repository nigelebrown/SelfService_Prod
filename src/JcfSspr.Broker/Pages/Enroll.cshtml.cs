using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;

namespace JcfSspr.Broker.Pages;

[Authorize]
public sealed class EnrollModel(MemberDirectoryService members, TotpEnrollmentService enrollment) : PageModel
{
    [BindProperty] public string ProtectedState { get; set; } = string.Empty;
    [BindProperty] public string Code { get; set; } = string.Empty;
    public string QrDataUri { get; private set; } = string.Empty;
    public string ManualSecret { get; private set; } = string.Empty;
    public string ErrorMessage { get; private set; } = string.Empty;
    public IReadOnlyList<string> RecoveryCodes { get; private set; } = Array.Empty<string>();

    public void OnGet() { }

    public async Task<IActionResult> OnPostBeginAsync(CancellationToken cancellationToken)
    {
        var account = CurrentAccount();
        var member = await members.FindByAccountNameAsync(account, cancellationToken);
        if (member is null) { ErrorMessage = "Your Windows account is not mapped to an eligible member record."; return Page(); }
        var start = enrollment.Begin(member);
        ProtectedState = start.ProtectedState;
        ManualSecret = start.Secret;
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(start.OtpAuthUri, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        QrDataUri = "data:image/png;base64," + Convert.ToBase64String(png);
        return Page();
    }

    public async Task<IActionResult> OnPostConfirmAsync(CancellationToken cancellationToken)
    {
        try
        {
            RecoveryCodes = await enrollment.ConfirmAsync(ProtectedState, Code, CurrentAccount(), cancellationToken);
            ProtectedState = string.Empty;
            Code = string.Empty;
        }
        catch
        {
            ErrorMessage = "Enrollment could not be confirmed. Start again and enter the current authenticator code.";
            ProtectedState = string.Empty;
        }
        return Page();
    }

    private string CurrentAccount()
    {
        var name = User.Identity?.Name ?? throw new InvalidOperationException("Windows identity is required.");
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];
        var at = name.IndexOf('@');
        if (at > 0) name = name[..at];
        return name.Trim();
    }
}
