using System.Net.Mail;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class SecurityNotifier(IOptions<NotificationOptions> options, ILogger<SecurityNotifier> logger)
{
    private static readonly Action<ILogger, string, Exception?> NotificationFailed = LoggerMessage.Define<string>(
        LogLevel.Warning,
        new EventId(2101, "PostResetNotificationFailed"),
        "Post-reset notification failed for account {AccountName}");

    public async Task NotifyResetAsync(MemberRecord member, DateTimeOffset timestamp, CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled || string.IsNullOrWhiteSpace(member.EmailAddress)) return;
        try
        {
            using var message = new MailMessage(options.Value.From, member.EmailAddress)
            {
                Subject = "Your account password was reset",
                Body = $"Your directory account password was reset at {timestamp:yyyy-MM-dd HH:mm:ss} UTC. If you did not perform this reset, contact your identity-service administrator immediately."
            };
            using var client = new SmtpClient(options.Value.Host, options.Value.Port)
            {
                EnableSsl = options.Value.EnableSsl,
                UseDefaultCredentials = true
            };
            await client.SendMailAsync(message, cancellationToken);
        }
        catch (Exception ex)
        {
            NotificationFailed(logger, member.AdAccountName, ex);
        }
    }
}
