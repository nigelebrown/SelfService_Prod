using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class SecurityAlertWorker(IServiceScopeFactory scopeFactory, IOptions<SecurityAlertOptions> options, TimeProvider timeProvider, ILogger<SecurityAlertWorker> logger) : BackgroundService
{
    private readonly SecurityAlertOptions _options = options.Value;
    private static readonly Action<ILogger, Exception?> WorkerFailed = LoggerMessage.Define(LogLevel.Error, new EventId(2501, "SecurityAlertWorkerFailed"), "Identity security alert worker failed.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { if (_options.Enabled) await DeliverAsync(stoppingToken); }
            catch (Exception ex) { WorkerFailed(logger, ex); }
            await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(_options.PollSeconds, 10, 300)), stoppingToken);
        }
    }

    private async Task DeliverAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        var notifier = scope.ServiceProvider.GetRequiredService<SecurityNotifier>();
        var codes = _options.CriticalDetailCodes.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (codes.Length == 0) return;
        var candidates = await db.Audits.AsNoTracking()
            .Where(x => codes.Contains(x.DetailCode))
            .Where(x => !db.SecurityAlertDeliveries.Any(d => d.AuditId == x.Id && d.DeliveredUtc != null))
            .OrderBy(x => x.TimestampUtc).Take(50).ToListAsync(ct);
        foreach (var audit in candidates)
        {
            var delivery = await db.SecurityAlertDeliveries.SingleOrDefaultAsync(x => x.AuditId == audit.Id, ct);
            if (delivery?.Attempts >= Math.Clamp(_options.MaximumDeliveryAttempts, 1, 50)) continue;
            delivery ??= new SecurityAlertDeliveryEntity { AuditId = audit.Id };
            if (db.Entry(delivery).State == EntityState.Detached) db.SecurityAlertDeliveries.Add(delivery);
            delivery.Attempts++;
            delivery.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
            try
            {
                if (await notifier.NotifySecurityEventAsync(audit, ct)) { delivery.DeliveredUtc = delivery.UpdatedUtc; delivery.LastError = string.Empty; }
                else delivery.LastError = "Notification channel is not configured or unavailable.";
            }
            catch (Exception ex) { delivery.LastError = ex.GetType().Name[..Math.Min(ex.GetType().Name.Length, 120)]; }
            await db.SaveChangesAsync(ct);
        }
    }
}
