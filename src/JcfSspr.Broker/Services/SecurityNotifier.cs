using System.Net.Mail;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class SecurityNotifier(IOptions<NotificationOptions> options, ILogger<SecurityNotifier> logger)
{
    public async Task NotifyResetAsync(MemberRecord member, DateTimeOffset timestamp, CancellationToken cancellationToken)
    {
        if (!options.Value.Enabled || string.IsNullOrWhiteSpace(member.EmailAddress)) return;
        try
        {
            using var message = new MailMessage(options.Value.From, member.EmailAddress)
            {
                Subject = "Your JCF account password was reset",
                Body = $"Your JCF account password was reset at {timestamp:yyyy-MM-dd HH:mm:ss} UTC. If you did not perform this reset, contact ICTD immediately."
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
            logger.LogWarning(ex, "Post-reset notification failed for account {AccountName}", member.AdAccountName);
        }
    }
}
