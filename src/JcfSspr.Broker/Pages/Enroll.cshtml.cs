using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Broker.Pages;

[Authorize]
public sealed class EnrollModel : PageModel
{
    public void OnGet() { }
}
