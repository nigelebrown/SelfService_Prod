using JcfSspr.Core.Contracts;
using JcfSspr.Portal.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Portal.Pages;

public sealed class IndexModel(BrokerClient broker) : PageModel
{
    [BindProperty] public IdentityVerificationInput Input { get; set; } = new();
    public string StatusMessage { get; private set; } = string.Empty;
    public IdentityProfile? Profile { get; private set; }
    public bool Verified => Profile is not null;
    public bool AccountCreated { get; private set; }
    public bool EnrollmentRequired { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return Page();
        var response = await broker.VerifyIdentityAsync(new IdentityVerificationRequest
        {
            Identifier = Input.Identifier.Trim(), Method = Input.Method, Secret = Input.Secret,
            Trn = Input.Trn.Trim(), DateOfBirth = Input.DateOfBirth, MiddleName = Input.MiddleName.Trim(),
            ProvisioningCode = Input.ProvisioningCode.Trim(), ClientIp = ClientIp()
        }, cancellationToken);
        Input.Secret = string.Empty;
        Input.Trn = string.Empty;
        ModelState.Clear();
        StatusMessage = response.Message;
        if (!response.Success || response.Profile is null) return Page();
        TempData["ResetTransaction"] = response.TransactionToken;
        TempData["EnrollmentRequired"] = response.AuthenticatorEnrollmentRequired;
        Profile = response.Profile;
        AccountCreated = response.AccountCreated;
        EnrollmentRequired = response.AuthenticatorEnrollmentRequired;
        return Page();
    }

    public async Task<IActionResult> OnPostConfirmAsync(CancellationToken cancellationToken)
    {
        if (TempData.Peek("ResetTransaction") is not string token) return RedirectToPage("/Index");
        var confirmation = await broker.ConfirmProfileAsync(new ProfileConfirmationRequest { TransactionToken = token, ClientIp = ClientIp() }, cancellationToken);
        if (!confirmation.Success)
        {
            TempData.Remove("ResetTransaction");
            TempData.Remove("EnrollmentRequired");
            return RedirectToPage("/Index");
        }
        var enrollment = TempData.Peek("EnrollmentRequired") is bool required && required;
        TempData.Keep("ResetTransaction");
        TempData.Keep("EnrollmentRequired");
        return RedirectToPage(enrollment ? "/EnrollAuthenticator" : "/Reset");
    }

    public IActionResult OnPostReject()
    {
        TempData.Remove("ResetTransaction");
        TempData.Remove("EnrollmentRequired");
        return RedirectToPage("/Index");
    }

    private string ClientIp() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
