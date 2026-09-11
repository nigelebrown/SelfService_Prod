using System.Net.Mail;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class SecurityNotifier(IOptions<NotificationOptions> options, IOptions<SecurityAlertOptions> alertOptions, ILogger<SecurityNotifier> logger)
{
    private readonly NotificationOptions _options = options.Value;
    private readonly SecurityAlertOptions _alerts = alertOptions.Value;
    private static readonly Action<ILogger, string, Exception?> NotificationFailed = LoggerMessage.Define<string>(LogLevel.Warning, new EventId(2101, "PostResetNotificationFailed"), "Post-reset notification failed for account {AccountName}");

    public async Task NotifyResetAsync(MemberRecord member, DateTimeOffset timestamp, CancellationToken cancellationToken)
    {
        if (!_options.Enabled || string.IsNullOrWhiteSpace(member.EmailAddress)) return;
        try
        {
            using var message = new MailMessage(_options.From, member.EmailAddress)
            {
                Subject = "Your account password was reset",
                Body = $"Your directory account password was reset at {timestamp:yyyy-MM-dd HH:mm:ss} UTC. If you did not perform this reset, contact your identity-service administrator immediately."
            };
            using var client = CreateClient();
            await client.SendMailAsync(message, cancellationToken);
        }
        catch (Exception ex) { NotificationFailed(logger, member.AdAccountName, ex); }
    }

    public async Task<bool> NotifySecurityEventAsync(AuditEntity audit, CancellationToken cancellationToken)
    {
        logger.LogWarning("Identity security event {DetailCode}; outcome {Outcome}; actor {Actor}; subject {SubjectId}; correlation {CorrelationId}", audit.DetailCode, audit.Outcome, audit.Actor, audit.SubjectId, audit.CorrelationId);
        if (!_alerts.Enabled) return true;
        if (!_options.Enabled || string.IsNullOrWhiteSpace(_options.Host) || _alerts.Recipients.Length == 0) return false;
        try
        {
            using var message = new MailMessage { From = new MailAddress(_options.From), Subject = $"Identity security alert: {audit.DetailCode}", Body = $"Time (UTC): {audit.TimestampUtc:O}\nEvent: {audit.DetailCode}\nOutcome: {audit.Outcome}\nActor: {audit.Actor}\nSubject: {audit.SubjectId}\nAccount: {audit.AccountName}\nSource: {audit.SourceIp}\nCorrelation: {audit.CorrelationId}" };
            foreach (var recipient in _alerts.Recipients.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase)) message.To.Add(recipient);
            using var client = CreateClient();
            await client.SendMailAsync(message, cancellationToken);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Security alert delivery failed for audit event {AuditId}", audit.Id);
            return false;
        }
    }

    private SmtpClient CreateClient() => new(_options.Host, _options.Port) { EnableSsl = _options.EnableSsl, UseDefaultCredentials = true };
}
