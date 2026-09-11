using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy="SecurityAdmin")]
public sealed class SecurityModel(AdminIdentityService admin) : PageModel
{
    [BindProperty] public string Identifier{get;set;}=string.Empty;
    [BindProperty] public string SubjectId{get;set;}=string.Empty;
    [BindProperty] public string Reference{get;set;}=string.Empty;
    [BindProperty] public string Reason{get;set;}=string.Empty;
    public AdminSubjectView? Subject{get;private set;}
    public string StatusMessage{get;private set;}=string.Empty;
    public void OnGet(){}
    public async Task<IActionResult> OnPostSearchAsync(CancellationToken ct){await LoadAsync(Identifier,ct);return Page();}
    public async Task<IActionResult> OnPostDisableAsync(CancellationToken ct){try{await admin.SetSelfServiceDisabledAsync(SubjectId,true,string.IsNullOrWhiteSpace(Reason)?"Disabled by security administrator":Reason,Actor,Reference,ct);StatusMessage="Self-service disabled.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;}await LoadAsync(SubjectId,ct);return Page();}
    public async Task<IActionResult> OnPostEnableAsync(CancellationToken ct){try{await admin.SetSelfServiceDisabledAsync(SubjectId,false,string.Empty,Actor,Reference,ct);StatusMessage="Self-service enabled.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;}await LoadAsync(SubjectId,ct);return Page();}
    private async Task LoadAsync(string value,CancellationToken ct){Subject=await admin.FindAsync(value,ct);if(Subject is not null)SubjectId=Subject.SubjectId;else StatusMessage="No unique active employee profile was found.";}
    private string Actor=>User.Identity?.Name??"unknown";
}
