using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using JcfSspr.Broker.Options;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public static class ProvisioningGroupSafetyRegistry
{
    private static readonly ConcurrentDictionary<string, DateTime> SafeGroups = new(StringComparer.OrdinalIgnoreCase);
    public static void MarkSafe(string groupDn, DateTime validatedUtc) => SafeGroups[groupDn] = validatedUtc;
    public static void MarkUnsafe(string groupDn) => SafeGroups.TryRemove(groupDn, out _);
    public static bool IsValidatedSafe(string groupDn, DateTime nowUtc, TimeSpan maximumAge) => SafeGroups.TryGetValue(groupDn, out var validated) && validated <= nowUtc.AddMinutes(1) && nowUtc - validated <= maximumAge;
}

public sealed class ProvisioningGroupSafetyMonitor(IOptions<DirectoryOptions> directoryOptions, IOptions<ProvisioningOptions> provisioningOptions, TimeProvider timeProvider, ILogger<ProvisioningGroupSafetyMonitor> logger) : BackgroundService
{
    private readonly DirectoryOptions _directory = directoryOptions.Value;
    private readonly ProvisioningOptions _provisioning = provisioningOptions.Value;
    private static readonly Action<ILogger, string, Exception?> UnsafeGroup = LoggerMessage.Define<string>(LogLevel.Critical, new EventId(2503, "UnsafeProvisioningGroup"), "Provisioning group {GroupDn} is blocked or nested under a blocked privileged group.");
    private static readonly Action<ILogger, string, Exception?> GroupValidationFailed = LoggerMessage.Define<string>(LogLevel.Error, new EventId(2504, "ProvisioningGroupValidationFailed"), "Could not validate provisioning group safety for {GroupDn}; provisioning through this group is fail-closed.");
    private static readonly Action<ILogger, Exception?> DirectoryValidationFailed = LoggerMessage.Define(LogLevel.Error, new EventId(2505, "ProvisioningDirectoryValidationFailed"), "Could not connect to Active Directory for provisioning group safety validation; group provisioning is fail-closed.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            ValidateConfiguredGroups();
            await Task.Delay(TimeSpan.FromMinutes(Math.Clamp(_provisioning.GroupValidationRefreshMinutes, 1, 60)), stoppingToken);
        }
    }

    private void ValidateConfiguredGroups()
    {
        var groups = _provisioning.Profiles.SelectMany(x => x.GroupDns).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (groups.Length == 0) return;
        try
        {
            using var connection = OpenConnection();
            foreach (var group in groups)
            {
                try
                {
                    if (HasBlockedAncestor(connection, group)) { ProvisioningGroupSafetyRegistry.MarkUnsafe(group); UnsafeGroup(logger, group, null); }
                    else ProvisioningGroupSafetyRegistry.MarkSafe(group, timeProvider.GetUtcNow().UtcDateTime);
                }
                catch (Exception ex) { ProvisioningGroupSafetyRegistry.MarkUnsafe(group); GroupValidationFailed(logger, group, ex); }
            }
        }
        catch (Exception ex)
        {
            foreach (var group in groups) ProvisioningGroupSafetyRegistry.MarkUnsafe(group);
            DirectoryValidationFailed(logger, ex);
        }
    }

    private bool HasBlockedAncestor(LdapConnection connection, string startingGroupDn)
    {
        var blocked = _provisioning.BlockedGroupDns.Concat(_directory.DeniedGroupDns).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>(); var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase); pending.Push(startingGroupDn);
        while (pending.Count > 0)
        {
            var current = pending.Pop(); if (!visited.Add(current)) continue;
            if (visited.Count > 64) throw new InvalidOperationException("Group nesting depth/graph exceeds the safe validation limit.");
            if (blocked.Contains(current)) return true;
            var request = new SearchRequest(current, "(objectClass=group)", SearchScope.Base, "memberOf");
            var response = (SearchResponse)connection.SendRequest(request, TimeSpan.FromSeconds(_directory.TimeoutSeconds));
            if (response.Entries.Count != 1) throw new InvalidOperationException("Configured provisioning group could not be resolved uniquely.");
            if (response.Entries[0].Attributes["memberOf"] is not DirectoryAttribute parents) continue;
            foreach (var parent in parents) { var parentDn = Convert.ToString(parent, System.Globalization.CultureInfo.InvariantCulture); if (!string.IsNullOrWhiteSpace(parentDn)) pending.Push(parentDn); }
        }
        return false;
    }

    private LdapConnection OpenConnection()
    {
        var identifier = new LdapDirectoryIdentifier(_directory.Server, _directory.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        var connection = new LdapConnection(identifier) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(_directory.TimeoutSeconds) };
        connection.SessionOptions.ProtocolVersion = 3; connection.SessionOptions.SecureSocketLayer = true; connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None; connection.Bind(); return connection;
    }
}
