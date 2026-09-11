using System.ComponentModel.DataAnnotations;
using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy = "Helpdesk")]
public sealed class AssistedRegistrationModel(AdminIdentityService admin) : PageModel
{
    [BindProperty] public string Identifier { get; set; } = string.Empty;
    [BindProperty] public string SubjectId { get; set; } = string.Empty;
    [BindProperty, StringLength(12, MinimumLength = 8)] public string Pin { get; set; } = string.Empty;
    [BindProperty, StringLength(12, MinimumLength = 8)] public string ConfirmPin { get; set; } = string.Empty;
    [BindProperty, StringLength(100)] public string SupportReference { get; set; } = string.Empty;
    [BindProperty] public bool MemberPresentAndVerified { get; set; }
    public AdminSubjectView? Subject { get; private set; }
    public string StatusMessage { get; private set; } = string.Empty;

    public void OnGet() { }

    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct)
    {
        Subject = await admin.FindAsync(Identifier, ct);
        if (Subject is null) StatusMessage = "No unique active employee profile was found.";
        else SubjectId = Subject.SubjectId;
        return Page();
    }

    public async Task<IActionResult> OnPostRegisterAsync(CancellationToken ct)
    {
        try
        {
            if (!MemberPresentAndVerified) throw new InvalidOperationException("Confirm that the member is physically present and the HR photo/profile has been verified.");
            if (Pin != ConfirmPin) throw new InvalidOperationException("The PIN entries do not match.");
            await admin.SetMemberChosenPinAsync(SubjectId, Pin, Actor, SupportReference, ct);
            StatusMessage = "PIN registered securely. It was not stored in retrievable form. The member can now use the PIN to bootstrap Authenticator registration.";
        }
        catch (InvalidOperationException ex) { StatusMessage = ex.Message; }
        finally { Pin = string.Empty; ConfirmPin = string.Empty; ModelState.Remove(nameof(Pin)); ModelState.Remove(nameof(ConfirmPin)); }
        Subject = await admin.FindAsync(SubjectId, ct);
        return Page();
    }

    private string Actor => User.Identity?.Name ?? "unknown";
}
