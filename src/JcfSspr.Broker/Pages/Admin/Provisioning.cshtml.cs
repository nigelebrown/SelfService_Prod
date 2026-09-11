using JcfSspr.Broker.Options;
using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy="ProvisioningAdmin")]
public sealed class ProvisioningModel(AdminIdentityService admin,IOptions<ProvisioningOptions> options):PageModel
{
    [BindProperty] public string Identifier{get;set;}=string.Empty;
    [BindProperty] public string SubjectId{get;set;}=string.Empty;
    [BindProperty] public string ProfileCode{get;set;}=string.Empty;
    [BindProperty] public string ChangeReference{get;set;}=string.Empty;
    public AdminSubjectView? Subject{get;private set;}
    public IReadOnlyList<ProvisioningProfileOptions> Profiles{get;}=options.Value.Profiles.Where(x=>x.Enabled).ToArray();
    public string StatusMessage{get;private set;}=string.Empty;
    public void OnGet(){}
    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct){await LoadAsync(Identifier,ct);return Page();}
    public async Task<IActionResult> OnPostApplyAsync(CancellationToken ct){try{if(string.IsNullOrWhiteSpace(ProfileCode))throw new InvalidOperationException("Select an approved provisioning profile.");await admin.ApplyProfileAsync(SubjectId,ProfileCode,Actor,ChangeReference,ct);StatusMessage="Approved provisioning profile applied.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;}await LoadAsync(SubjectId,ct);return Page();}
    private async Task LoadAsync(string value,CancellationToken ct){Subject=await admin.FindAsync(value,ct);if(Subject is not null)SubjectId=Subject.SubjectId;else StatusMessage="No unique active employee profile was found.";}
    private string Actor=>User.Identity?.Name??"unknown";
}
