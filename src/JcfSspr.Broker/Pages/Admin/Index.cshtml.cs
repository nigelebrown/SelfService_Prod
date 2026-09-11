using JcfSspr.Broker.Options;
using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Pages.Admin;

public sealed class IndexModel(AdminIdentityService admin, IOptions<ProvisioningOptions> provisioning) : PageModel
{
    [BindProperty] public string Identifier { get; set; } = string.Empty;
    [BindProperty] public string SubjectId { get; set; } = string.Empty;
    [BindProperty] public string ProfileCode { get; set; } = string.Empty;
    public AdminSubjectView? Subject { get; private set; }
    public string StatusMessage { get; private set; } = string.Empty;
    public IReadOnlyList<ProvisioningProfileOptions> Profiles { get; } = provisioning.Value.Profiles.Where(x => x.Enabled).ToArray();

    public void OnGet() { }

    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct)
    {
        await LoadAsync(Identifier, ct);
        if (Subject is null) StatusMessage = "No unique active employee profile was found.";
        return Page();
    }

    public async Task<IActionResult> OnPostUnlockPinAsync(CancellationToken ct)
    {
        await admin.UnlockPinAsync(SubjectId, ct); StatusMessage = "PIN method unlocked."; await LoadSubjectAsync(SubjectId, ct); return Page();
    }

    public async Task<IActionResult> OnPostResetAuthenticatorAsync(CancellationToken ct)
    {
        await admin.ResetAuthenticatorAsync(SubjectId, ct); StatusMessage = "Authenticator enrollment revoked. The member must register again."; await LoadSubjectAsync(SubjectId, ct); return Page();
    }

    public async Task<IActionResult> OnPostEnableSelfServiceAsync(CancellationToken ct)
    {
        await admin.SetSelfServiceDisabledAsync(SubjectId, false, string.Empty, ct); StatusMessage = "Self-service enabled."; await LoadSubjectAsync(SubjectId, ct); return Page();
    }

    public async Task<IActionResult> OnPostDisableSelfServiceAsync(CancellationToken ct)
    {
        await admin.SetSelfServiceDisabledAsync(SubjectId, true, "Disabled by administrator", ct); StatusMessage = "Self-service disabled."; await LoadSubjectAsync(SubjectId, ct); return Page();
    }

    public async Task<IActionResult> OnPostApplyProfileAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ProfileCode)) { StatusMessage = "Select a provisioning profile."; await LoadSubjectAsync(SubjectId, ct); return Page(); }
        await admin.ApplyProfileAsync(SubjectId, ProfileCode, User.Identity?.Name ?? "unknown", ct); StatusMessage = "Provisioning profile applied."; await LoadSubjectAsync(SubjectId, ct); return Page();
    }

    private async Task LoadAsync(string identifier, CancellationToken ct) => Subject = await admin.FindAsync(identifier, ct);
    private async Task LoadSubjectAsync(string subjectId, CancellationToken ct)
    {
        Subject = await admin.FindAsync(subjectId, ct); Identifier = subjectId;
    }
}
