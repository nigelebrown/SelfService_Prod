using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Security;
using JcfSspr.Broker.Services;
using JcfSspr.Core.Contracts;
using JcfSspr.Core.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<MemberDirectoryOptions>(builder.Configuration.GetSection("MemberDirectory"));
builder.Services.Configure<DirectoryOptions>(builder.Configuration.GetSection("Directory"));
builder.Services.Configure<BrokerSecurityOptions>(builder.Configuration.GetSection("BrokerSecurity"));
builder.Services.Configure<PinSecurityOptions>(builder.Configuration.GetSection("PinSecurity"));
builder.Services.Configure<LocalAdminSecurityOptions>(builder.Configuration.GetSection("LocalAdminSecurity"));
builder.Services.Configure<AuthenticatorOptions>(builder.Configuration.GetSection("Authenticator"));
builder.Services.Configure<ProvisioningOptions>(builder.Configuration.GetSection("Provisioning"));
builder.Services.Configure<AdminAuthorizationOptions>(builder.Configuration.GetSection("AdminAuthorization"));
builder.Services.Configure<JcfSspr.Broker.Options.DataProtectionOptions>(builder.Configuration.GetSection("DataProtection"));
builder.Services.Configure<NotificationOptions>(builder.Configuration.GetSection("Notification"));
builder.Services.Configure<SecurityAlertOptions>(builder.Configuration.GetSection("SecurityAlerts"));
builder.Services.Configure<RetentionOptions>(builder.Configuration.GetSection("Retention"));
builder.Services.Configure<PasswordPolicyOptions>(builder.Configuration.GetSection("PasswordPolicy"));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AuditAppendOnlyInterceptor>();

var securityConnection = builder.Configuration.GetConnectionString("SecurityStore")
    ?? throw new InvalidOperationException("ConnectionStrings:SecurityStore is required.");
builder.Services.AddDbContext<SecurityDbContext>((sp, o) => o.UseSqlServer(securityConnection).AddInterceptors(sp.GetRequiredService<AuditAppendOnlyInterceptor>()));

var dataProtectionOptions = builder.Configuration.GetSection("DataProtection").Get<JcfSspr.Broker.Options.DataProtectionOptions>() ?? new();
Directory.CreateDirectory(dataProtectionOptions.KeyPath);
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("IdentityRecovery.Internal")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(Math.Clamp(dataProtectionOptions.KeyLifetimeDays, 7, 365)))
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionOptions.KeyPath));
if (!string.IsNullOrWhiteSpace(dataProtectionOptions.KeyEncryptionCertificateThumbprint))
    dataProtection.ProtectKeysWithCertificate(FindCertificate(dataProtectionOptions.KeyEncryptionCertificateThumbprint));
else if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);

const string combinedAdminScheme = "IdentityRecovery.AdminCombined";
const string localAdminCookieName = "__Host-IdentityRecovery.LocalAdmin";
var adminOptions = builder.Configuration.GetSection("AdminAuthorization").Get<AdminAuthorizationOptions>() ?? new();
var platformSids = adminOptions.PlatformAdminGroupSids.Length > 0 ? adminOptions.PlatformAdminGroupSids : adminOptions.AllowedGroupSids;
var allAdminSids = platformSids.Concat(adminOptions.HelpdeskGroupSids).Concat(adminOptions.ProvisioningAdminGroupSids).Concat(adminOptions.SecurityAdminGroupSids).Concat(adminOptions.AuditorGroupSids).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
var localAdminOptions = builder.Configuration.GetSection("LocalAdminSecurity").Get<LocalAdminSecurityOptions>() ?? new LocalAdminSecurityOptions();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = combinedAdminScheme;
    options.DefaultAuthenticateScheme = combinedAdminScheme;
    options.DefaultChallengeScheme = combinedAdminScheme;
})
.AddPolicyScheme(combinedAdminScheme, combinedAdminScheme, options =>
{
    options.ForwardDefaultSelector = context => context.Request.Cookies.ContainsKey(localAdminCookieName) ? LocalAdminAuthDefaults.Scheme : NegotiateDefaults.AuthenticationScheme;
})
.AddNegotiate()
.AddCookie(LocalAdminAuthDefaults.Scheme, options =>
{
    options.Cookie.Name = localAdminCookieName;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(Math.Clamp(localAdminOptions.SessionMinutes, 5, 30));
    options.SlidingExpiration = false;
    options.LoginPath = "/Admin/LocalLogin";
    options.AccessDeniedPath = "/Admin/LocalLogin";
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DirectoryAdminOnly", policy =>
    {
        policy.AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => HasAnyGroup(context.User, platformSids));
    });
    options.AddPolicy("IdentityAdmin", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsLocalBreakGlass(context.User) || HasAnyGroup(context.User, allAdminSids));
    });
    options.AddPolicy("Helpdesk", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsLocalBreakGlass(context.User) || HasAnyGroup(context.User, platformSids.Concat(adminOptions.HelpdeskGroupSids)));
    });
    options.AddPolicy("ProvisioningAdmin", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsLocalBreakGlass(context.User) || HasAnyGroup(context.User, platformSids.Concat(adminOptions.ProvisioningAdminGroupSids)));
    });
    options.AddPolicy("SecurityAdmin", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsLocalBreakGlass(context.User) || HasAnyGroup(context.User, platformSids.Concat(adminOptions.SecurityAdminGroupSids)));
    });
    options.AddPolicy("AuditReader", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context => IsLocalBreakGlass(context.User) || HasAnyGroup(context.User, platformSids.Concat(adminOptions.SecurityAdminGroupSids).Concat(adminOptions.AuditorGroupSids)));
    });
});

builder.Services.AddRazorPages(options => options.Conventions.AuthorizeFolder("/Admin", "IdentityAdmin"));
builder.Services.AddScoped<HrIdentityDirectoryService>();
builder.Services.AddScoped<PinCredentialService>();
builder.Services.AddScoped<LocalAdminService>();
builder.Services.AddScoped<TotpEnrollmentService>();
builder.Services.AddScoped<ThrottleService>();
builder.Services.AddScoped<ProvisioningPolicyService>();
builder.Services.AddScoped<DirectoryProvisioningService>();
builder.Services.AddScoped<ActiveDirectoryResetService>();
builder.Services.AddScoped<ResetTransactionService>();
builder.Services.AddScoped<SecurityNotifier>();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<IdentityRecoveryOrchestrator>();
builder.Services.AddScoped<AdminIdentityService>();
builder.Services.AddScoped<ApiReplayGuard>();
builder.Services.AddSingleton<ClientCertificateValidator>();
builder.Services.AddSingleton<ProvisioningGroupSafetyMonitor>();
builder.Services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<ProvisioningGroupSafetyMonitor>());
builder.Services.AddHostedService<SecurityAlertWorker>();
builder.Services.AddHostedService<RetentionWorker>();
builder.Services.AddHealthChecks().AddCheck<InternalDependenciesHealthCheck>("internal-dependencies");

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 32 * 1024);
var app = builder.Build();
ValidateProductionConfiguration(app, platformSids, dataProtectionOptions);

if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler("/Error"); app.UseHsts(); }
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
    context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow, noarchive";
    context.Response.Headers.CacheControl = "no-store, max-age=0";
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/v1/identity/verify", async (HttpContext context, IdentityVerificationRequest request, ClientCertificateValidator validator, ApiReplayGuard replay, IdentityRecoveryOrchestrator orchestrator, CancellationToken ct) =>
{
    var clientId = await validator.GetValidatedClientIdAsync(context);
    if (clientId is null || !await replay.AcceptAsync(context, clientId, ct)) return Results.Unauthorized();
    return Results.Ok(await orchestrator.VerifyAsync(request, clientId, ct));
}).AllowAnonymous();
app.MapPost("/api/v1/identity/profile/confirm", async (HttpContext context, ProfileConfirmationRequest request, ClientCertificateValidator validator, ApiReplayGuard replay, IdentityRecoveryOrchestrator orchestrator, CancellationToken ct) =>
{
    var clientId = await validator.GetValidatedClientIdAsync(context);
    if (clientId is null || !await replay.AcceptAsync(context, clientId, ct)) return Results.Unauthorized();
    return Results.Ok(await orchestrator.ConfirmProfileAsync(request, clientId, ct));
}).AllowAnonymous();
app.MapPost("/api/v1/identity/enroll/start", async (HttpContext context, TotpEnrollmentStartRequest request, ClientCertificateValidator validator, ApiReplayGuard replay, IdentityRecoveryOrchestrator orchestrator, CancellationToken ct) =>
{
    var clientId = await validator.GetValidatedClientIdAsync(context);
    if (clientId is null || !await replay.AcceptAsync(context, clientId, ct)) return Results.Unauthorized();
    return Results.Ok(await orchestrator.StartAuthenticatorEnrollmentAsync(request, clientId, ct));
}).AllowAnonymous();
app.MapPost("/api/v1/identity/enroll/confirm", async (HttpContext context, TotpEnrollmentConfirmRequest request, ClientCertificateValidator validator, ApiReplayGuard replay, IdentityRecoveryOrchestrator orchestrator, CancellationToken ct) =>
{
    var clientId = await validator.GetValidatedClientIdAsync(context);
    if (clientId is null || !await replay.AcceptAsync(context, clientId, ct)) return Results.Unauthorized();
    return Results.Ok(await orchestrator.ConfirmAuthenticatorEnrollmentAsync(request, clientId, ct));
}).AllowAnonymous();
app.MapPost("/api/v1/identity/reset", async (HttpContext context, PasswordResetRequest request, ClientCertificateValidator validator, ApiReplayGuard replay, IdentityRecoveryOrchestrator orchestrator, CancellationToken ct) =>
{
    var clientId = await validator.GetValidatedClientIdAsync(context);
    if (clientId is null || !await replay.AcceptAsync(context, clientId, ct)) return Results.Unauthorized();
    return Results.Ok(await orchestrator.ResetAsync(request, clientId, ct));
}).AllowAnonymous();

app.MapRazorPages();
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    ResponseWriter = static (context, report) => context.Response.WriteAsJsonAsync(new { status = report.Status.ToString() })
}).AllowAnonymous();
app.Run();

static bool IsLocalBreakGlass(ClaimsPrincipal user) => user.HasClaim(LocalAdminAuthDefaults.ClaimType, "true");
static bool HasAnyGroup(ClaimsPrincipal user, IEnumerable<string> sids)
{
    var allowed = sids.Where(x => !string.IsNullOrWhiteSpace(x)).ToHashSet(StringComparer.OrdinalIgnoreCase);
    return user.Claims.Any(c => c.Type == ClaimTypes.GroupSid && allowed.Contains(c.Value));
}

static X509Certificate2 FindCertificate(string thumbprint)
{
    var normalized = thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    var cert = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: true).OfType<X509Certificate2>().SingleOrDefault();
    if (cert is null || !cert.HasPrivateKey) throw new InvalidOperationException("Configured Data Protection certificate was not found with a private key in LocalMachine/My.");
    return cert;
}

static void ValidateProductionConfiguration(WebApplication app, string[] platformSids, JcfSspr.Broker.Options.DataProtectionOptions dataProtectionOptions)
{
    if (!app.Environment.IsProduction()) return;
    var errors = new List<string>();
    foreach (var name in new[] { "MemberDirectory", "SecurityStore" })
    {
        var cs = app.Configuration.GetConnectionString(name) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(cs) || cs.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)) errors.Add($"ConnectionStrings:{name} is not configured.");
        if (cs.Contains("Password=", StringComparison.OrdinalIgnoreCase) || cs.Contains("Pwd=", StringComparison.OrdinalIgnoreCase)) errors.Add($"ConnectionStrings:{name} must use integrated authentication.");
        if (!cs.Contains("TrustServerCertificate=False", StringComparison.OrdinalIgnoreCase)) errors.Add($"ConnectionStrings:{name} must validate the SQL certificate.");
    }
    var server = app.Configuration["Directory:Server"] ?? string.Empty;
    var baseDn = app.Configuration["Directory:BaseDn"] ?? string.Empty;
    if (server.Contains("REPLACE", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(server)) errors.Add("Directory:Server is not configured.");
    if (!baseDn.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) && !baseDn.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)) errors.Add("Directory:BaseDn must be a valid search base.");
    var certs = app.Configuration.GetSection("BrokerSecurity:AllowedClientCertificateThumbprints").Get<string[]>() ?? [];
    if (certs.Length == 0 || certs.Any(x => x.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))) errors.Add("Broker client certificate allowlist is not configured.");
    var hosts = app.Configuration["AllowedHosts"] ?? string.Empty;
    if (hosts == "*" || hosts.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)) errors.Add("AllowedHosts must be the real internal-service hostname.");
    if (platformSids.Length == 0 || platformSids.Any(x => x.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))) errors.Add("AdminAuthorization:PlatformAdminGroupSids must contain a dedicated AD security-group SID.");
    var pinOptions = app.Configuration.GetSection("PinSecurity").Get<PinSecurityOptions>() ?? new PinSecurityOptions();
    if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(pinOptions.PepperEnvironmentVariable))) errors.Add("PIN pepper environment variable is not configured.");
    var localOptions = app.Configuration.GetSection("LocalAdminSecurity").Get<LocalAdminSecurityOptions>() ?? new LocalAdminSecurityOptions();
    if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(localOptions.PepperEnvironmentVariable))) errors.Add("Local administrator pepper environment variable is not configured.");
    if (dataProtectionOptions.RequireCertificateProtection && string.IsNullOrWhiteSpace(dataProtectionOptions.KeyEncryptionCertificateThumbprint)) errors.Add("Data Protection certificate protection is required but no certificate thumbprint is configured.");
    var passwordOptions = app.Configuration.GetSection("PasswordPolicy").Get<PasswordPolicyOptions>() ?? new PasswordPolicyOptions();
    if (!PasswordPolicy.BlocklistAvailable(passwordOptions)) errors.Add("Required offline password blocklist is unavailable.");
    if (!OperatingSystem.IsWindows()) errors.Add("Production internal service is designed for Windows/gMSA integrated authentication.");
    if (errors.Count > 0) throw new InvalidOperationException("Unsafe production configuration: " + string.Join(" ", errors));
}

public partial class Program;
