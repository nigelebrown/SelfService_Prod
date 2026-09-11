using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy = "Helpdesk")]
public sealed class SupportModel(AdminIdentityService admin) : PageModel
{
    [BindProperty] public string Identifier { get; set; } = string.Empty;
    [BindProperty] public string SubjectId { get; set; } = string.Empty;
    [BindProperty] public string SupportReference { get; set; } = string.Empty;
    public AdminSubjectView? Subject { get; private set; }
    public string StatusMessage { get; private set; } = string.Empty;
    public void OnGet() { }
    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct){ await LoadAsync(Identifier,ct); return Page(); }
    public async Task<IActionResult> OnPostUnlockPinAsync(CancellationToken ct){ try{await admin.UnlockPinAsync(SubjectId,Actor,SupportReference,ct);StatusMessage="PIN method unlocked.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;} await LoadAsync(SubjectId,ct);return Page(); }
    public async Task<IActionResult> OnPostResetAuthenticatorAsync(CancellationToken ct){ try{await admin.ResetAuthenticatorAsync(SubjectId,Actor,SupportReference,ct);StatusMessage="Authenticator registration revoked. The member must prove identity and enroll again.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;} await LoadAsync(SubjectId,ct);return Page(); }
    private async Task LoadAsync(string value,CancellationToken ct){Subject=await admin.FindAsync(value,ct);if(Subject is not null)SubjectId=Subject.SubjectId;else StatusMessage="No unique active employee profile was found.";}
    private string Actor=>User.Identity?.Name??"unknown";
}
