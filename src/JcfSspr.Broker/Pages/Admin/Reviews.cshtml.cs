using JcfSspr.Broker.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy="ProvisioningAdmin")]
public sealed class ReviewsModel(AdminIdentityService admin):PageModel
{
    [BindProperty] public Guid ReviewId{get;set;}
    [BindProperty] public string ResolutionReference{get;set;}=string.Empty;
    public IReadOnlyList<AdminReviewView> Reviews{get;private set;}=Array.Empty<AdminReviewView>();
    public string StatusMessage{get;private set;}=string.Empty;
    public async Task OnGetAsync(CancellationToken ct)=>Reviews=await admin.GetOpenReviewsAsync(ct);
    public async Task<IActionResult> OnPostRetryAsync(CancellationToken ct){try{var result=await admin.RetryReviewAsync(ReviewId,Actor,ResolutionReference,ct);StatusMessage=result.Message;}catch(InvalidOperationException ex){StatusMessage=ex.Message;}Reviews=await admin.GetOpenReviewsAsync(ct);return Page();}
    public async Task<IActionResult> OnPostCloseAsync(CancellationToken ct){try{await admin.CloseReviewAsync(ReviewId,Actor,ResolutionReference,ct);StatusMessage="Review closed with the recorded resolution.";}catch(InvalidOperationException ex){StatusMessage=ex.Message;}Reviews=await admin.GetOpenReviewsAsync(ct);return Page();}
    private string Actor=>User.Identity?.Name??"unknown";
}
