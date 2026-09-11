using System.Security.Claims;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using JcfSspr.Broker.Security;
using JcfSspr.Broker.Services;
using JcfSspr.Core.Contracts;
using JcfSspr.Core.Security;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<MemberDirectoryOptions>(builder.Configuration.GetSection("MemberDirectory"));
builder.Services.Configure<DirectoryOptions>(builder.Configuration.GetSection("Directory"));
builder.Services.Configure<BrokerSecurityOptions>(builder.Configuration.GetSection("BrokerSecurity"));
builder.Services.Configure<PinSecurityOptions>(builder.Configuration.GetSection("PinSecurity"));
builder.Services.Configure<AuthenticatorOptions>(builder.Configuration.GetSection("Authenticator"));
builder.Services.Configure<ProvisioningOptions>(builder.Configuration.GetSection("Provisioning"));
builder.Services.Configure<AdminAuthorizationOptions>(builder.Configuration.GetSection("AdminAuthorization"));
builder.Services.Configure<JcfSspr.Broker.Options.DataProtectionOptions>(builder.Configuration.GetSection("DataProtection"));
builder.Services.Configure<NotificationOptions>(builder.Configuration.GetSection("Notification"));
builder.Services.Configure<PasswordPolicyOptions>(builder.Configuration.GetSection("PasswordPolicy"));
builder.Services.AddSingleton(TimeProvider.System);

var securityConnection = builder.Configuration.GetConnectionString("SecurityStore")
    ?? throw new InvalidOperationException("ConnectionStrings:SecurityStore is required.");
builder.Services.AddDbContext<SecurityDbContext>(o => o.UseSqlServer(securityConnection));

var keyPath = builder.Configuration["DataProtection:KeyPath"] ?? @"C:\ProgramData\IdentityRecovery\keys";
Directory.CreateDirectory(keyPath);
var dataProtection = builder.Services.AddDataProtection().SetApplicationName("IdentityRecovery.Internal").PersistKeysToFileSystem(new DirectoryInfo(keyPath));
if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);

var adminSids = builder.Configuration.GetSection("AdminAuthorization:AllowedGroupSids").Get<string[]>() ?? [];
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options => options.AddPolicy("IdentityAdmin", policy =>
{
    policy.RequireAuthenticatedUser();
    policy.RequireAssertion(context => context.User.Claims.Any(c => c.Type == ClaimTypes.GroupSid && adminSids.Contains(c.Value, StringComparer.OrdinalIgnoreCase)));
}));
builder.Services.AddRazorPages(options => options.Conventions.AuthorizeFolder("/Admin", "IdentityAdmin"));
builder.Services.AddScoped<HrIdentityDirectoryService>();
builder.Services.AddScoped<PinCredentialService>();
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

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 32 * 1024);
var app = builder.Build();
ValidateProductionConfiguration(app, adminSids);

if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler("/Error"); app.UseHsts(); }
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
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
app.Run();

static void ValidateProductionConfiguration(WebApplication app, string[] adminSids)
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
    if (adminSids.Length == 0 || adminSids.Any(x => x.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))) errors.Add("AdminAuthorization:AllowedGroupSids must contain a dedicated admin group SID.");
    var pinOptions = app.Configuration.GetSection("PinSecurity").Get<PinSecurityOptions>() ?? new PinSecurityOptions();
    var pepper = Environment.GetEnvironmentVariable(pinOptions.PepperEnvironmentVariable);
    if (string.IsNullOrWhiteSpace(pepper)) errors.Add("PIN pepper environment variable is not configured.");
    if (!OperatingSystem.IsWindows()) errors.Add("Production internal service is designed for Windows/gMSA integrated authentication.");
    if (errors.Count > 0) throw new InvalidOperationException("Unsafe production configuration: " + string.Join(" ", errors));
}

public partial class Program;
