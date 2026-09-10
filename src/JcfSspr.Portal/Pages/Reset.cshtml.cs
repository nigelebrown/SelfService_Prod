using JcfSspr.Portal.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Portal.Pages;

public sealed class ResetModel : PageModel
{
    [BindProperty] public ResetPasswordInput Input { get; set; } = new();
    public string StatusMessage { get; private set; } = string.Empty;
    public bool Success => false;

    public IActionResult OnGet()
    {
        if (TempData.Peek("ResetTransaction") is not string) return RedirectToPage("/Index");
        return Page();
    }

    public IActionResult OnPost()
    {
        if (TempData.Peek("ResetTransaction") is not string) return RedirectToPage("/Index");
        Input = new ResetPasswordInput();
        ModelState.Clear();
        StatusMessage = "Password submission is intentionally disabled in this review branch until the secure broker handoff is approved and enabled.";
        return Page();
    }
}
