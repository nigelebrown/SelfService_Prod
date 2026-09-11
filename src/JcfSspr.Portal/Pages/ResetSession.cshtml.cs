using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JcfSspr.Portal.Pages;

public sealed class ResetSessionModel : PageModel
{
    public void OnGet()
    {
        TempData.Clear();
        Response.Headers["Clear-Site-Data"] = "\"cache\", \"storage\"";
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
    }
}
