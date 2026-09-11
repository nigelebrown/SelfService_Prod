using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using JcfSspr.Portal;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var portalSection = builder.Configuration.GetSection("Portal");
builder.Services.Configure<PortalOptions>(portalSection);
var initialOptions = portalSection.Get<PortalOptions>() ?? new PortalOptions();
builder.WebHost.UseUrls(initialOptions.ListenUrl);

if (!string.IsNullOrWhiteSpace(initialOptions.DataProtectionKeyPath))
{
    Directory.CreateDirectory(initialOptions.DataProtectionKeyPath);
    var dp = builder.Services.AddDataProtection().SetApplicationName("IdentityRecovery.DmzPortal")
        .PersistKeysToFileSystem(new DirectoryInfo(initialOptions.DataProtectionKeyPath));
    if (!string.IsNullOrWhiteSpace(initialOptions.DataProtectionCertificateThumbprint))
        dp.ProtectKeysWithCertificate(FindCertificate(initialOptions.DataProtectionCertificateThumbprint));
}

builder.Services.AddRazorPages();
if (!string.IsNullOrWhiteSpace(initialOptions.TrustedProxyIp))
{
    if (!IPAddress.TryParse(initialOptions.TrustedProxyIp, out var trustedProxy)) throw new InvalidOperationException("Portal:TrustedProxyIp must be a valid IP address.");
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.KnownProxies.Clear(); o.KnownIPNetworks.Clear(); o.KnownProxies.Add(trustedProxy); o.ForwardLimit = 1;
    });
}
builder.Services.Configure<CookieTempDataProviderOptions>(o =>
{
    o.Cookie.HttpOnly = true; o.Cookie.SameSite = SameSiteMode.Strict; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.Name = "__Host-IdentityRecoveryTxn";
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("identity", context => RateLimitPartition.GetFixedWindowLimiter(context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions { PermitLimit = 8, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
});
builder.Services.AddHttpClient<BrokerClient>((sp, client) =>
{
    var options = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
    client.BaseAddress = new Uri(options.BrokerUrl, UriKind.Absolute); client.Timeout = TimeSpan.FromSeconds(options.RequestTimeoutSeconds);
}).ConfigurePrimaryHttpMessageHandler(sp =>
{
    var options = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
    var handler = new HttpClientHandler(); handler.ClientCertificates.Add(CertificateLoader.FindByThumbprint(options.ClientCertificateThumbprint)); return handler;
});

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 32 * 1024);
var app = builder.Build();
ValidateProductionConfiguration(app, initialOptions);
if (!string.IsNullOrWhiteSpace(initialOptions.TrustedProxyIp)) app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler("/Error"); app.UseHsts(); }
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff"; context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer"; context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
    context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow, noarchive";
    context.Response.Headers.CacheControl = "no-store, max-age=0"; context.Response.Headers.Pragma = "no-cache"; await next();
});
app.UseStaticFiles(); app.UseRouting(); app.UseRateLimiter();
app.MapRazorPages().RequireRateLimiting("identity");
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (BrokerClient broker, CancellationToken ct) => await broker.IsReadyAsync(ct) ? Results.Ok(new { status = "ready" }) : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));
app.Run();

static X509Certificate2 FindCertificate(string thumbprint)
{
    var normalized = thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    return store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: true).OfType<X509Certificate2>().SingleOrDefault(c => c.HasPrivateKey)
        ?? throw new InvalidOperationException("Configured portal Data Protection certificate was not found with a private key in LocalMachine/My.");
}

static void ValidateProductionConfiguration(WebApplication app, PortalOptions options)
{
    if (!app.Environment.IsProduction()) return;
    var errors = new List<string>();
    if (!Uri.TryCreate(options.BrokerUrl, UriKind.Absolute, out var broker) || broker.Scheme != Uri.UriSchemeHttps) errors.Add("Portal:BrokerUrl must be HTTPS.");
    if (string.IsNullOrWhiteSpace(options.ClientCertificateThumbprint) || options.ClientCertificateThumbprint.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)) errors.Add("Portal client certificate is not configured.");
    if (!options.ListenUrl.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase) && !options.ListenUrl.Contains("localhost", StringComparison.OrdinalIgnoreCase)) errors.Add("Portal must bind to loopback behind the reverse proxy.");
    var allowedHosts = app.Configuration["AllowedHosts"] ?? string.Empty;
    if (string.IsNullOrWhiteSpace(allowedHosts) || allowedHosts == "*" || allowedHosts.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)) errors.Add("AllowedHosts must be configured.");
    if (options.RequirePersistentDataProtection && string.IsNullOrWhiteSpace(options.DataProtectionKeyPath)) errors.Add("Persistent portal Data Protection is required but no key path is configured.");
    if (options.RequirePersistentDataProtection && string.IsNullOrWhiteSpace(options.DataProtectionCertificateThumbprint)) errors.Add("Persistent portal Data Protection must use a key-encryption certificate.");
    if (options.KioskMode && options.KioskIdleMinutes is < 1 or > 15) errors.Add("Portal:KioskIdleMinutes must be 1-15 minutes in kiosk mode.");
    if (errors.Count > 0) throw new InvalidOperationException("Unsafe production configuration: " + string.Join(" ", errors));
}

public partial class Program;
