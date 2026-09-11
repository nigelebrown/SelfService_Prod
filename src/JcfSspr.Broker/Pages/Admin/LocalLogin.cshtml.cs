using System.Security.Claims;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Security;
using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Pages.Admin;

[AllowAnonymous]
public sealed class LocalLoginModel(LocalAdminService localAdmin, ThrottleService throttle, IOptions<LocalAdminSecurityOptions> options) : PageModel
{
    [BindProperty] public string Username { get; set; } = string.Empty;
    [BindProperty] public string Password { get; set; } = string.Empty;
    [BindProperty] public string AuthenticatorCode { get; set; } = string.Empty;
    [BindProperty(SupportsGet = true)] public string ReturnUrl { get; set; } = "/Admin";
    public string StatusMessage { get; private set; } = string.Empty;

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var decision = await throttle.BeforeAttemptAsync("local-break-glass", sourceIp, ct);
        if (decision.Blocked)
        {
            StatusMessage = "Local administrator sign-in is temporarily unavailable from this connection.";
            ClearSecrets();
            return Page();
        }
        if (decision.Delay > TimeSpan.Zero) await Task.Delay(decision.Delay, ct);

        var result = await localAdmin.AuthenticateAsync(Username, Password, AuthenticatorCode.Trim().Replace(" ", string.Empty, StringComparison.Ordinal), sourceIp, ct);
        ClearSecrets();
        if (result != LocalAdminAuthenticationResult.Success)
        {
            await throttle.RecordFailureAsync("local-break-glass", sourceIp, ct);
            StatusMessage = result == LocalAdminAuthenticationResult.Blocked
                ? "The local administrator is temporarily blocked. Use an authorized AD administrator to unlock it, or wait for the block period to expire."
                : "Sign-in could not be verified.";
            return Page();
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, Username),
            new Claim(LocalAdminAuthDefaults.ClaimType, "true"),
            new Claim(ClaimTypes.AuthenticationMethod, "LocalBreakGlass")
        };
        var identity = new ClaimsIdentity(claims, LocalAdminAuthDefaults.Scheme);
        await HttpContext.SignInAsync(LocalAdminAuthDefaults.Scheme, new ClaimsPrincipal(identity), new AuthenticationProperties
        {
            IsPersistent = false,
            AllowRefresh = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(Math.Clamp(options.Value.SessionMinutes, 5, 30))
        });
        var destination = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/Admin";
        return LocalRedirect(destination);
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await HttpContext.SignOutAsync(LocalAdminAuthDefaults.Scheme);
        return RedirectToPage();
    }

    private void ClearSecrets()
    {
        Password = string.Empty;
        AuthenticatorCode = string.Empty;
    }
}
