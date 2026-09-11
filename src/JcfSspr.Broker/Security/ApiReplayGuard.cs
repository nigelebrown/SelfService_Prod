using System.Globalization;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Security;

public sealed class ApiReplayGuard(SecurityDbContext db, IOptions<BrokerSecurityOptions> options, TimeProvider timeProvider)
{
    public async Task<bool> AcceptAsync(HttpContext context, string clientId, CancellationToken cancellationToken)
    {
        var requestId = context.Request.Headers["X-Identity-Request-ID"].ToString();
        var timestampText = context.Request.Headers["X-Identity-Timestamp"].ToString();
        if (!Guid.TryParse(requestId, out _) || !DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp)) return false;
        var now = timeProvider.GetUtcNow();
        var window = TimeSpan.FromSeconds(Math.Clamp(options.Value.ApiReplayWindowSeconds, 30, 300));
        if ((now - timestamp).Duration() > window) return false;
        var key = clientId + ":" + requestId.ToLowerInvariant();
        if (await db.ApiReplayRequests.AsNoTracking().AnyAsync(x => x.RequestId == key, cancellationToken)) return false;
        db.ApiReplayRequests.Add(new ApiReplayEntity { RequestId = key, ExpiresUtc = now.Add(window).UtcDateTime });
        try { await db.SaveChangesAsync(cancellationToken); }
        catch (DbUpdateException) { return false; }
        return true;
    }
}
