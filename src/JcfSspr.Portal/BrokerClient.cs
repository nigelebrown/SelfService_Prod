using System.Net.Http.Json;
using JcfSspr.Core.Contracts;

namespace JcfSspr.Portal;

public sealed class BrokerClient(HttpClient httpClient, ILogger<BrokerClient> logger)
{
    public async Task<VerificationResponse> VerifyAsync(VerificationRequest request, CancellationToken ct)
    {
        try
        {
            using var response = await httpClient.PostAsJsonAsync("api/v1/verify", request, ct);
            if (!response.IsSuccessStatusCode) return VerificationResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
            return await response.Content.ReadFromJsonAsync<VerificationResponse>(cancellationToken: ct)
                ?? VerificationResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(ex, "Broker verification request failed");
            return VerificationResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
        }
    }

    public async Task<ResetResponse> ResetAsync(PasswordResetRequest request, CancellationToken ct)
    {
        try
        {
            using var response = await httpClient.PostAsJsonAsync("api/v1/reset", request, ct);
            if (!response.IsSuccessStatusCode) return ResetResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
            return await response.Content.ReadFromJsonAsync<ResetResponse>(cancellationToken: ct)
                ?? ResetResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(ex, "Broker password reset request failed");
            return ResetResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable.");
        }
    }
}
