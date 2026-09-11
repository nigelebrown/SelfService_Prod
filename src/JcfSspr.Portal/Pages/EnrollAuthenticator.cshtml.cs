using JcfSspr.Core.Contracts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;

namespace JcfSspr.Portal.Pages;

public sealed class EnrollAuthenticatorModel(BrokerClient broker) : PageModel
{
    [BindProperty] public string ProtectedState { get; set; } = string.Empty;
    [BindProperty] public string Code { get; set; } = string.Empty;
    public string QrDataUri { get; private set; } = string.Empty;
    public string ManualSecret { get; private set; } = string.Empty;
    public string StatusMessage { get; private set; } = string.Empty;
    public bool Complete { get; private set; }
    public IReadOnlyList<string> RecoveryCodes { get; private set; } = Array.Empty<string>();

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (TempData.Peek("ResetTransaction") is not string token) return RedirectToPage("/Index");
        var response = await broker.StartEnrollmentAsync(new TotpEnrollmentStartRequest { TransactionToken = token, ClientIp = ClientIp() }, cancellationToken);
        if (!response.Success) { StatusMessage = response.Message; return Page(); }
        ProtectedState = response.ProtectedState;
        ManualSecret = response.ManualSecret;
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(response.OtpAuthUri, QRCodeGenerator.ECCLevel.Q);
        QrDataUri = "data:image/png;base64," + Convert.ToBase64String(new PngByteQRCode(data).GetGraphic(8));
        TempData.Keep("ResetTransaction");
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (TempData.Peek("ResetTransaction") is not string token) return RedirectToPage("/Index");
        if (string.IsNullOrWhiteSpace(Code) || string.IsNullOrWhiteSpace(ProtectedState)) { StatusMessage = "Enter the current six-digit authenticator code."; return Page(); }
        var response = await broker.ConfirmEnrollmentAsync(new TotpEnrollmentConfirmRequest { TransactionToken = token, ProtectedState = ProtectedState, Code = Code, ClientIp = ClientIp() }, cancellationToken);
        Code = string.Empty;
        ProtectedState = string.Empty;
        StatusMessage = response.Message;
        Complete = response.Success;
        RecoveryCodes = response.RecoveryCodes;
        if (response.Success) TempData["EnrollmentRequired"] = false;
        TempData.Keep("ResetTransaction");
        return Page();
    }

    private string ClientIp() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
