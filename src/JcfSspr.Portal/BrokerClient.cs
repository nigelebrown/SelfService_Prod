using System.Net.Http.Json;
using JcfSspr.Core.Contracts;

namespace JcfSspr.Portal;

public sealed class BrokerClient(HttpClient httpClient, ILogger<BrokerClient> logger)
{
    private static readonly Action<ILogger, string, Exception?> BrokerFailure = LoggerMessage.Define<string>(LogLevel.Warning, new EventId(1001, "BrokerRequestFailed"), "Internal identity API request failed for {Operation}");

    public Task<IdentityVerificationResponse> VerifyIdentityAsync(IdentityVerificationRequest request, CancellationToken ct) =>
        PostAsync("api/v1/identity/verify", request, () => IdentityVerificationResponse.Rejected(Guid.NewGuid().ToString("N"), "The identity service is temporarily unavailable."), "identity-verify", ct);

    public Task<ProfileConfirmationResponse> ConfirmProfileAsync(ProfileConfirmationRequest request, CancellationToken ct) =>
        PostAsync("api/v1/identity/profile/confirm", request, () => new ProfileConfirmationResponse { Message = "The identity service is temporarily unavailable." }, "profile-confirm", ct);

    public Task<TotpEnrollmentStartResponse> StartEnrollmentAsync(TotpEnrollmentStartRequest request, CancellationToken ct) =>
        PostAsync("api/v1/identity/enroll/start", request, () => new TotpEnrollmentStartResponse { Message = "The identity service is temporarily unavailable." }, "enrollment-start", ct);

    public Task<TotpEnrollmentConfirmResponse> ConfirmEnrollmentAsync(TotpEnrollmentConfirmRequest request, CancellationToken ct) =>
        PostAsync("api/v1/identity/enroll/confirm", request, () => new TotpEnrollmentConfirmResponse { Message = "The identity service is temporarily unavailable." }, "enrollment-confirm", ct);

    public Task<ResetResponse> ResetAsync(PasswordResetRequest request, CancellationToken ct) =>
        PostAsync("api/v1/identity/reset", request, () => ResetResponse.Rejected(Guid.NewGuid().ToString("N"), "The reset service is temporarily unavailable."), "password-reset", ct);

    private async Task<TResponse> PostAsync<TRequest, TResponse>(string path, TRequest payload, Func<TResponse> fallback, string operation, CancellationToken ct)
    {
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(payload) };
            message.Headers.Add("X-Identity-Request-ID", Guid.NewGuid().ToString("D"));
            message.Headers.Add("X-Identity-Timestamp", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
            using var response = await httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) return fallback();
            return await response.Content.ReadFromJsonAsync<TResponse>(cancellationToken: ct) ?? fallback();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            BrokerFailure(logger, operation, ex);
            return fallback();
        }
    }
}
