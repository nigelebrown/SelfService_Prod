using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed partial class InternalDependenciesHealthCheck(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    IOptions<MemberDirectoryOptions> memberDirectory,
    IOptions<DirectoryOptions> directory,
    IOptions<JcfSspr.Broker.Options.DataProtectionOptions> dataProtection) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using (var scope = scopeFactory.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
                if (!await db.Database.CanConnectAsync(cancellationToken)) return HealthCheckResult.Unhealthy("Security store unavailable.");
            }

            var hrConnection = configuration.GetConnectionString("MemberDirectory") ?? throw new InvalidOperationException("HR connection string missing.");
            await using (var connection = new SqlConnection(hrConnection))
            {
                await connection.OpenAsync(cancellationToken);
                var view = memberDirectory.Value.ViewName;
                if (!SafeSqlObjectName().IsMatch(view)) return HealthCheckResult.Unhealthy("HR view name is invalid.");
                await using var command = new SqlCommand($"SELECT TOP (1) 1 FROM {view};", connection);
                command.CommandTimeout = 5;
                await command.ExecuteScalarAsync(cancellationToken);
            }

            await Task.Run(() => CheckDirectory(directory.Value), cancellationToken);
            if (!Directory.Exists(dataProtection.Value.KeyPath)) return HealthCheckResult.Unhealthy("Data Protection key path unavailable.");
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex) { return HealthCheckResult.Unhealthy("One or more internal dependencies are unavailable.", ex); }
    }

    private static void CheckDirectory(DirectoryOptions options)
    {
        var identifier = new LdapDirectoryIdentifier(options.Server, options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        using var connection = new LdapConnection(identifier) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 3, 30)) };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        connection.Bind();
        var request = new SearchRequest(options.BaseDn, "(objectClass=*)", SearchScope.Base, "distinguishedName");
        connection.SendRequest(request, TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 3, 30)));
    }

    [GeneratedRegex("^[A-Za-z0-9_]+\\.[A-Za-z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeSqlObjectName();
}
