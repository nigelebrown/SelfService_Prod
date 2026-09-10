using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class ThrottleService(SecurityDbContext db, IOptions<BrokerSecurityOptions> options, TimeProvider timeProvider)
{
    public async Task<ThrottleDecision> BeforeAttemptAsync(string computerNumber, string sourceIp, CancellationToken cancellationToken)
    {
        var source = await GetAsync("src:" + NormalizeKey(sourceIp), cancellationToken);
        var account = await GetAsync("acct:" + NormalizeKey(computerNumber), cancellationToken);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (source?.BlockUntilUtc > now) return new ThrottleDecision(true, TimeSpan.Zero);
        var failures = Math.Max(source?.Failures ?? 0, account?.Failures ?? 0);
        var exponential = failures <= 1 ? 0 : Math.Min(options.Value.MaximumDelayMilliseconds, 250 * (1 << Math.Min(failures - 2, 4)));
        return new ThrottleDecision(false, TimeSpan.FromMilliseconds(exponential));
    }

    public async Task RecordFailureAsync(string computerNumber, string sourceIp, CancellationToken cancellationToken)
    {
        await IncrementAsync("src:" + NormalizeKey(sourceIp), isSource: true, cancellationToken);
        await IncrementAsync("acct:" + NormalizeKey(computerNumber), isSource: false, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task IncrementAsync(string key, bool isSource, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var window = TimeSpan.FromMinutes(options.Value.FailureWindowMinutes);
        var entity = await db.Throttles.SingleOrDefaultAsync(x => x.ThrottleKey == key, cancellationToken);
        if (entity is null)
        {
            entity = new ThrottleEntity { ThrottleKey = key, WindowStartUtc = now, Failures = 1 };
            db.Throttles.Add(entity);
        }
        else if (now - entity.WindowStartUtc >= window)
        {
            entity.WindowStartUtc = now;
            entity.Failures = 1;
            entity.BlockUntilUtc = null;
        }
        else entity.Failures++;
        if (isSource && entity.Failures >= options.Value.SourceFailureLimit) entity.BlockUntilUtc = now.Add(window);
    }

    private Task<ThrottleEntity?> GetAsync(string key, CancellationToken cancellationToken) => db.Throttles.AsNoTracking().SingleOrDefaultAsync(x => x.ThrottleKey == key, cancellationToken);
    private static string NormalizeKey(string value) => value.Trim().ToLowerInvariant()[..Math.Min(value.Trim().Length, 200)];
}

public sealed record ThrottleDecision(bool Blocked, TimeSpan Delay);
