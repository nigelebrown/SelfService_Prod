using JcfSspr.Core.Contracts;
using JcfSspr.Portal.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Portal.Pages;

public sealed class ResetModel(BrokerClient broker) : PageModel
{
    [BindProperty] public ResetPasswordInput Input { get; set; } = new();
    public string StatusMessage { get; private set; } = string.Empty;
    public bool Success { get; private set; }

    public IActionResult OnGet()
    {
        if (TempData.Peek("ResetTransaction") is not string) return RedirectToPage("/Index");
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (TempData.Peek("ResetTransaction") is not string token) return RedirectToPage("/Index");
        if (!ModelState.IsValid) return Page();

        var response = await broker.ResetAsync(new PasswordResetRequest
        {
            TransactionToken = token,
            NewPassword = Input.NewPassword,
            ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"
        }, cancellationToken);

        Input.NewPassword = string.Empty;
        Input.ConfirmPassword = string.Empty;
        ModelState.Clear();
        Success = response.Success;
        StatusMessage = response.Message;

        if (response.Success)
        {
            TempData.Remove("ResetTransaction");
            return Page();
        }

        if (response.CanRetry) TempData.Keep("ResetTransaction");
        else TempData.Remove("ResetTransaction");

        return Page();
    }
}
