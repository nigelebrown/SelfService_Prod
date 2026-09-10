using JcfSspr.Core.Contracts;
using JcfSspr.Portal.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace JcfSspr.Portal.Pages;

public sealed class IndexModel(BrokerClient broker, IOptions<PortalOptions> options) : PageModel
{
    [BindProperty] public VerificationInput Input { get; set; } = new();
    public string StatusMessage { get; private set; } = string.Empty;
    public bool ShowEnrollmentLink => options.Value.ShowEnrollmentLink;
    public string EnrollmentUrl => options.Value.EnrollmentUrl;
    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid) return Page();
        var request = new VerificationRequest
        {
            ComputerNumber = Input.ComputerNumber.Trim(),
            FirstName = Input.FirstName.Trim(),
            LastName = Input.LastName.Trim(),
            Trn = Input.Trn.Trim(),
            DateOfBirth = Input.DateOfBirth!.Value,
            AuthenticatorCode = Input.AuthenticatorCode.Trim(),
            ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"
        };
        var response = await broker.VerifyAsync(request, cancellationToken);
        Input.Trn = string.Empty;
        Input.AuthenticatorCode = string.Empty;
        if (!response.Success)
        {
            StatusMessage = response.Message;
            ModelState.Clear();
            return Page();
        }
        TempData["ResetTransaction"] = response.TransactionToken;
        return RedirectToPage("/Reset");
    }
}
