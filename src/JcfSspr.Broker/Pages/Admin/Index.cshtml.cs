using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy = "IdentityAdmin")]
public sealed class IndexModel(AdminIdentityService admin, IAuthorizationService authorization) : PageModel
{
    [BindProperty] public string Identifier { get; set; } = string.Empty;
    public AdminSubjectView? Subject { get; private set; }
    public bool CanHelpdesk { get; private set; }
    public bool CanProvision { get; private set; }
    public bool CanSecurity { get; private set; }
    public bool CanAudit { get; private set; }
    public bool CanPlatform { get; private set; }

    public async Task OnGetAsync() => await LoadPermissionsAsync();

    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct)
    {
        await LoadPermissionsAsync();
        Subject = await admin.FindAsync(Identifier, ct);
        return Page();
    }

    private async Task LoadPermissionsAsync()
    {
        CanHelpdesk = (await authorization.AuthorizeAsync(User, "Helpdesk")).Succeeded;
        CanProvision = (await authorization.AuthorizeAsync(User, "ProvisioningAdmin")).Succeeded;
        CanSecurity = (await authorization.AuthorizeAsync(User, "SecurityAdmin")).Succeeded;
        CanAudit = (await authorization.AuthorizeAsync(User, "AuditReader")).Succeeded;
        CanPlatform = (await authorization.AuthorizeAsync(User, "DirectoryAdminOnly")).Succeeded;
    }
}
