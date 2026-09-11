using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy = "DirectoryAdminOnly")]
public sealed class BreakGlassModel(LocalAdminService localAdmin) : PageModel
{
    [BindProperty] public string Username { get; set; } = "breakglass-admin";
    public LocalAdminStatus Status { get; private set; } = new(false, string.Empty, false, null, 0);
    public string GeneratedPassword { get; private set; } = string.Empty;
    public string ManualTotpSecret { get; private set; } = string.Empty;
    public string QrDataUri { get; private set; } = string.Empty;
    public string StatusMessage { get; private set; } = string.Empty;

    public async Task OnGetAsync(CancellationToken ct) => Status = await localAdmin.GetStatusAsync(ct);

    public async Task<IActionResult> OnPostRotateAsync(CancellationToken ct)
    {
        try
        {
            var bootstrap = await localAdmin.RotateAsync(Username, User.Identity?.Name ?? "unknown", ct);
            GeneratedPassword = bootstrap.Password;
            ManualTotpSecret = bootstrap.ManualTotpSecret;
            using var generator = new QRCodeGenerator();
            using var data = generator.CreateQrCode(bootstrap.OtpAuthUri, QRCodeGenerator.ECCLevel.Q);
            QrDataUri = "data:image/png;base64," + Convert.ToBase64String(new PngByteQRCode(data).GetGraphic(8));
            StatusMessage = "Local emergency administrator rotated. Record the password and authenticator secret now; they cannot be retrieved later.";
        }
        catch (InvalidOperationException ex) { StatusMessage = ex.Message; }
        Status = await localAdmin.GetStatusAsync(ct);
        return Page();
    }

    public async Task<IActionResult> OnPostUnlockAsync(CancellationToken ct)
    {
        await localAdmin.UnlockAsync(User.Identity?.Name ?? "unknown", ct);
        StatusMessage = "Local emergency administrator temporary block cleared.";
        Status = await localAdmin.GetStatusAsync(ct);
        return Page();
    }

    public async Task<IActionResult> OnPostDisableAsync(CancellationToken ct)
    {
        await localAdmin.DisableAsync(User.Identity?.Name ?? "unknown", ct);
        StatusMessage = "Local emergency administrator disabled.";
        Status = await localAdmin.GetStatusAsync(ct);
        return Page();
    }
}
