using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class RetentionWorker(IServiceScopeFactory scopeFactory, IOptions<RetentionOptions> options, TimeProvider timeProvider, ILogger<RetentionWorker> logger) : BackgroundService
{
    private readonly RetentionOptions _options = options.Value;
    private static readonly Action<ILogger, Exception?> SweepFailed = LoggerMessage.Define(LogLevel.Error, new EventId(2502, "RetentionSweepFailed"), "Identity transient-data retention sweep failed.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await SweepAsync(stoppingToken); }
            catch (Exception ex) { SweepFailed(logger, ex); }
            await Task.Delay(TimeSpan.FromMinutes(Math.Clamp(_options.SweepMinutes, 5, 1440)), stoppingToken);
        }
    }

    private async Task SweepAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await db.ApiReplayRequests.Where(x => x.ExpiresUtc < now.AddHours(-1)).ExecuteDeleteAsync(ct);
        await db.ResetTransactions.Where(x => x.ExpiresUtc < now.AddDays(-Math.Clamp(_options.ResetTransactionDays, 1, 30))).ExecuteDeleteAsync(ct);
        await db.RecoveryCodes.Where(x => x.UsedUtc != null && x.UsedUtc < now.AddDays(-Math.Clamp(_options.UsedRecoveryCodeDays, 1, 365))).ExecuteDeleteAsync(ct);
        await db.Throttles.Where(x => x.WindowStartUtc < now.AddDays(-Math.Clamp(_options.ThrottleDays, 1, 90)) && (x.BlockUntilUtc == null || x.BlockUntilUtc < now)).ExecuteDeleteAsync(ct);
        await db.ProvisioningReviews.Where(x => x.Status != "Open" && x.ResolvedUtc != null && x.ResolvedUtc < now.AddDays(-Math.Clamp(_options.ClosedReviewDays, 30, 3650))).ExecuteDeleteAsync(ct);
        await db.SecurityAlertDeliveries.Where(x => x.DeliveredUtc != null && x.DeliveredUtc < now.AddDays(-Math.Clamp(_options.AlertDeliveryDays, 7, 3650))).ExecuteDeleteAsync(ct);
    }
}
