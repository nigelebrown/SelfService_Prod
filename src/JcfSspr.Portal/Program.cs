using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using System.Threading.RateLimiting;
using JcfSspr.Portal;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var portalSection = builder.Configuration.GetSection("Portal");
builder.Services.Configure<PortalOptions>(portalSection);
var initialOptions = portalSection.Get<PortalOptions>() ?? new PortalOptions();
builder.WebHost.UseUrls(initialOptions.ListenUrl);

builder.Services.AddRazorPages();
if (!string.IsNullOrWhiteSpace(initialOptions.TrustedProxyIp))
{
    if (!IPAddress.TryParse(initialOptions.TrustedProxyIp, out var trustedProxy))
        throw new InvalidOperationException("Portal:TrustedProxyIp must be a valid IP address.");
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Add(trustedProxy);
        o.ForwardLimit = 1;
    });
}
builder.Services.Configure<CookieTempDataProviderOptions>(o =>
{
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.Name = "__Host-JcfSsprTxn";
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("reset", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 8,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});

builder.Services.AddHttpClient<BrokerClient>((sp, client) =>
{
    var options = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
    client.BaseAddress = new Uri(options.BrokerUrl, UriKind.Absolute);
    client.Timeout = TimeSpan.FromSeconds(options.RequestTimeoutSeconds);
}).ConfigurePrimaryHttpMessageHandler(sp =>
{
    var options = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
    var handler = new HttpClientHandler();
    handler.ClientCertificates.Add(CertificateLoader.FindByThumbprint(options.ClientCertificateThumbprint));
    return handler;
});

var app = builder.Build();
ValidateProductionConfiguration(app, initialOptions);
if (!string.IsNullOrWhiteSpace(initialOptions.TrustedProxyIp)) app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
    context.Response.Headers.CacheControl = "no-store, max-age=0";
    context.Response.Headers.Pragma = "no-cache";
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.MapRazorPages().RequireRateLimiting("reset");
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));
app.Run();

static void ValidateProductionConfiguration(WebApplication app, PortalOptions options)
{
    if (!app.Environment.IsProduction()) return;
    var errors = new List<string>();
    if (!Uri.TryCreate(options.BrokerUrl, UriKind.Absolute, out var broker) || broker.Scheme != Uri.UriSchemeHttps)
        errors.Add("Portal:BrokerUrl must be an HTTPS URL.");
    if (string.IsNullOrWhiteSpace(options.ClientCertificateThumbprint) || options.ClientCertificateThumbprint.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
        errors.Add("Portal:ClientCertificateThumbprint must identify an installed client certificate.");
    if (!options.ListenUrl.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase) && !options.ListenUrl.Contains("localhost", StringComparison.OrdinalIgnoreCase))
        errors.Add("Portal:ListenUrl must bind to loopback when deployed behind IIS/reverse proxy.");
    var allowedHosts = app.Configuration["AllowedHosts"] ?? string.Empty;
    if (string.IsNullOrWhiteSpace(allowedHosts) || allowedHosts == "*" || allowedHosts.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
        errors.Add("AllowedHosts must be the real portal hostname.");
    if (errors.Count > 0) throw new InvalidOperationException("Unsafe production configuration: " + string.Join(" ", errors));
}

public partial class Program;
