using System.Security.Cryptography;
using System.Text;
using JcfSspr.Broker.Data;
using JcfSspr.Broker.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JcfSspr.Broker.Services;

public sealed class AdminIdentityService(
    SecurityDbContext db,
    HrIdentityDirectoryService hr,
    PinCredentialService pins,
    TotpEnrollmentService totp,
    DirectoryProvisioningService provisioning,
    IOptions<PinSecurityOptions> pinOptions,
    TimeProvider timeProvider)
{
    private readonly PinSecurityOptions _pinOptions = pinOptions.Value;

    public async Task<AdminSubjectView?> FindAsync(string identifier, CancellationToken cancellationToken)
    {
        HrPersonRecord? person;
        try { person = await hr.FindByIdentifierAsync(identifier, cancellationToken); }
        catch (AmbiguousIdentityException) { return null; }
        if (person is null) return null;
        var pin = await db.PinCredentials.AsNoTracking().SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, cancellationToken);
        var link = await db.SubjectIdentities.AsNoTracking().SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, cancellationToken);
        var status = await db.SelfServiceStatuses.AsNoTracking().SingleOrDefaultAsync(x => x.SubjectId == person.SubjectId, cancellationToken);
        var pending = await db.ProvisioningReviews.AsNoTracking().CountAsync(x => x.SubjectId == person.SubjectId && x.Status == "Open", cancellationToken);
        return new AdminSubjectView(
            person.SubjectId, person.DisplayName, person.ComputerNumber, person.RegulationNumber, person.EmailAddress,
            person.EmploymentStatus, !string.IsNullOrWhiteSpace(person.PhotoBase64) ? $"data:{person.PhotoContentType};base64,{person.PhotoBase64}" : string.Empty,
            await totp.IsEnrolledAsync(person.ComputerNumber, cancellationToken), pin?.Enabled == true, pin?.Locked == true,
            pin?.FailedAttempts ?? 0, status?.Disabled == true, link?.AdAccountName ?? string.Empty, link?.AdObjectGuid,
            link?.ProvisioningState ?? "Unlinked", link?.ProvisioningProfileCode ?? string.Empty, pending);
    }

    public async Task<string> IssuePinAsync(string subjectId, string actor, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        var length = Math.Clamp(10, _pinOptions.MinimumDigits, _pinOptions.MaximumDigits);
        var builder = new StringBuilder(length);
        for (var index = 0; index < length; index++) builder.Append(RandomNumberGenerator.GetInt32(10));
        var pin = builder.ToString();
        await pins.SetAsync(subjectId, pin, cancellationToken);
        await AuditAsync(person, actor, "PinIssued", cancellationToken);
        return pin;
    }

    public async Task UnlockPinAsync(string subjectId, string actor, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        await pins.UnlockAsync(subjectId, cancellationToken);
        await AuditAsync(person, actor, "PinUnlocked", cancellationToken);
    }

    public async Task ResetAuthenticatorAsync(string subjectId, string actor, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the HR directory.");
        await totp.DisableAsync(person.ComputerNumber, cancellationToken);
        await AuditAsync(person, actor, "AuthenticatorRevoked", cancellationToken);
    }

    public async Task SetSelfServiceDisabledAsync(string subjectId, bool disabled, string reason, string actor, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        var entity = await db.SelfServiceStatuses.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (entity is null)
        {
            entity = new SelfServiceStatusEntity { SubjectId = subjectId };
            db.SelfServiceStatuses.Add(entity);
        }
        entity.Disabled = disabled;
        entity.DisabledReason = disabled ? reason[..Math.Min(reason.Length, 200)] : string.Empty;
        entity.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        db.Audits.Add(BuildAudit(person, actor, disabled ? "SelfServiceDisabled" : "SelfServiceEnabled"));
        await db.SaveChangesAsync(cancellationToken);
    }

    public Task ApplyProfileAsync(string subjectId, string profileCode, string actor, CancellationToken cancellationToken) => provisioning.ApplyAdminProfileAsync(subjectId, profileCode, actor, cancellationToken);

    private async Task AuditAsync(HrPersonRecord person, string actor, string detailCode, CancellationToken cancellationToken)
    {
        db.Audits.Add(BuildAudit(person, actor, detailCode));
        await db.SaveChangesAsync(cancellationToken);
    }

    private AuditEntity BuildAudit(HrPersonRecord person, string actor, string detailCode)
    {
        var link = db.SubjectIdentities.Local.FirstOrDefault(x => x.SubjectId == person.SubjectId);
        return new AuditEntity
        {
            Id = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = timeProvider.GetUtcNow().UtcDateTime,
            SubjectId = person.SubjectId, ComputerNumber = person.ComputerNumber, AccountName = link?.AdAccountName,
            Actor = actor[..Math.Min(actor.Length, 256)], Category = "Administration", Outcome = "Success", DetailCode = detailCode
        };
    }
}

public sealed record AdminSubjectView(
    string SubjectId, string DisplayName, string ComputerNumber, string RegulationNumber, string EmailAddress, string EmploymentStatus,
    string PhotoDataUri, bool AuthenticatorEnrolled, bool PinEnrolled, bool PinLocked, int PinFailedAttempts, bool SelfServiceDisabled,
    string AdAccountName, Guid? AdObjectGuid, string ProvisioningState, string ProvisioningProfileCode, int PendingReviews);
