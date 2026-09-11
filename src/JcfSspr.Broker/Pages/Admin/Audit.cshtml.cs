using JcfSspr.Broker.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Pages.Admin;

[Authorize(Policy="AuditReader")]
public sealed class AuditModel(SecurityDbContext db):PageModel
{
    [BindProperty(SupportsGet=true)] public string Subject{get;set;}=string.Empty;
    [BindProperty(SupportsGet=true)] public string Actor{get;set;}=string.Empty;
    [BindProperty(SupportsGet=true)] public string Event{get;set;}=string.Empty;
    [BindProperty(SupportsGet=true)] public string Outcome{get;set;}=string.Empty;
    [BindProperty(SupportsGet=true)] public DateTime? FromUtc{get;set;}
    [BindProperty(SupportsGet=true)] public DateTime? ToUtc{get;set;}
    public IReadOnlyList<AuditEntity> Events{get;private set;}=Array.Empty<AuditEntity>();
    public async Task OnGetAsync(CancellationToken ct)
    {
        var q=db.Audits.AsNoTracking().AsQueryable();
        if(!string.IsNullOrWhiteSpace(Subject)){var s=Subject.Trim();q=q.Where(x=>x.SubjectId==s||x.ComputerNumber==s||x.AccountName==s);}
        if(!string.IsNullOrWhiteSpace(Actor)){var a=Actor.Trim();q=q.Where(x=>x.Actor.Contains(a));}
        if(!string.IsNullOrWhiteSpace(Event)){var e=Event.Trim();q=q.Where(x=>x.DetailCode==e);}
        if(!string.IsNullOrWhiteSpace(Outcome)){var o=Outcome.Trim();q=q.Where(x=>x.Outcome==o);}
        if(FromUtc.HasValue)q=q.Where(x=>x.TimestampUtc>=FromUtc.Value);
        if(ToUtc.HasValue)q=q.Where(x=>x.TimestampUtc<=ToUtc.Value);
        Events=await q.OrderByDescending(x=>x.TimestampUtc).Take(200).ToListAsync(ct);
    }
}
