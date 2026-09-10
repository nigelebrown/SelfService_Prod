using JcfSspr.Broker.Data;

namespace JcfSspr.Broker.Services;

public sealed class AuditService(SecurityDbContext db, TimeProvider timeProvider, ILogger<AuditService> logger)
{
    public async Task WriteAsync(string correlationId, string? computerNumber, string? accountName, string? sourceIp, string outcome, string detailCode, CancellationToken cancellationToken)
    {
        db.Audits.Add(new AuditEntity
        {
            Id = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = timeProvider.GetUtcNow().UtcDateTime,
            ComputerNumber = computerNumber, AccountName = accountName, SourceIp = sourceIp, Outcome = outcome, DetailCode = detailCode
        });
        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("SSPR event {Outcome} {DetailCode}; correlation {CorrelationId}; account {AccountName}; computer {ComputerNumber}; source {SourceIp}", outcome, detailCode, correlationId, accountName, computerNumber, sourceIp);
    }
}
