using System.DirectoryServices.Protocols;
using System.Text;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class ActiveDirectoryResetService(IOptions<DirectoryOptions> options, ILogger<ActiveDirectoryResetService> logger)
{
    private static readonly Action<ILogger, string, Exception?> ResetCompleted = LoggerMessage.Define<string>(
        LogLevel.Information,
        new EventId(2401, "AdPasswordResetCompleted"),
        "AD password reset completed for account {AccountName}");

    private readonly DirectoryOptions _options = options.Value;

    public Task ResetAsync(MemberRecord member, string newPassword, CancellationToken cancellationToken) => Task.Run(() => Reset(member, newPassword), cancellationToken);

    private void Reset(MemberRecord member, string newPassword)
    {
        if (_options.DeniedAccountNames.Contains(member.AdAccountName, StringComparer.OrdinalIgnoreCase)) throw new ProtectedAccountException();
        var identifier = new LdapDirectoryIdentifier(_options.Server, _options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        using var connection = new LdapConnection(identifier)
        {
            AuthType = AuthType.Negotiate,
            Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds)
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        connection.Bind();

        var filter = "(objectGUID=" + EscapeGuid(member.AdObjectGuid) + ")";
        var search = new SearchRequest(_options.BaseDn, filter, SearchScope.Subtree, "distinguishedName", "sAMAccountName", "adminCount", "memberOf");
        search.TimeLimit = TimeSpan.FromSeconds(_options.TimeoutSeconds);
        var response = (SearchResponse)connection.SendRequest(search, TimeSpan.FromSeconds(_options.TimeoutSeconds));
        if (response.Entries.Count != 1) throw new InvalidOperationException("Authoritative AD object was not found uniquely inside the configured member OU.");
        var entry = response.Entries[0];
        var account = Convert.ToString(entry.Attributes["sAMAccountName"]?[0], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        if (!account.Equals(member.AdAccountName, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Authoritative account mapping does not match the AD object.");
        if (Convert.ToString(entry.Attributes["adminCount"]?[0], System.Globalization.CultureInfo.InvariantCulture) == "1") throw new ProtectedAccountException();
        if (entry.Attributes["memberOf"] is DirectoryAttribute groups)
        {
            foreach (var value in groups)
            {
                var group = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                if (_options.DeniedGroupDns.Contains(group, StringComparer.OrdinalIgnoreCase)) throw new ProtectedAccountException();
            }
        }

        var dn = entry.DistinguishedName;
        var password = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Replace };
        password.Add(Encoding.Unicode.GetBytes($"\"{newPassword}\""));
        var request = new ModifyRequest(dn, password);
        if (_options.RequireChangeAtNextLogon)
        {
            var pwdLastSet = new DirectoryAttributeModification { Name = "pwdLastSet", Operation = DirectoryAttributeOperation.Replace };
            pwdLastSet.Add("0");
            request.Modifications.Add(pwdLastSet);
        }
        connection.SendRequest(request, TimeSpan.FromSeconds(_options.TimeoutSeconds));
        ResetCompleted(logger, member.AdAccountName, null);
    }

    private static string EscapeGuid(Guid guid) => string.Concat(guid.ToByteArray().Select(b => $"\\{b:X2}"));
}

public sealed class ProtectedAccountException : Exception
{
    public ProtectedAccountException() : base("Protected accounts cannot be reset by self-service.") { }
}
