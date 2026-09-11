using JcfSspr.Broker.Data;
using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Services;

public sealed class AdminIdentityService(
    SecurityDbContext db,
    HrIdentityDirectoryService hr,
    PinCredentialService pins,
    TotpEnrollmentService totp,
    DirectoryProvisioningService provisioning,
    TimeProvider timeProvider)
{
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

    public Task UnlockPinAsync(string subjectId, CancellationToken cancellationToken) => pins.UnlockAsync(subjectId, cancellationToken);

    public async Task ResetAuthenticatorAsync(string subjectId, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the HR directory.");
        await totp.DisableAsync(person.ComputerNumber, cancellationToken);
    }

    public async Task SetSelfServiceDisabledAsync(string subjectId, bool disabled, string reason, CancellationToken cancellationToken)
    {
        var entity = await db.SelfServiceStatuses.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (entity is null)
        {
            entity = new SelfServiceStatusEntity { SubjectId = subjectId };
            db.SelfServiceStatuses.Add(entity);
        }
        entity.Disabled = disabled;
        entity.DisabledReason = disabled ? reason[..Math.Min(reason.Length, 200)] : string.Empty;
        entity.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);
    }

    public Task ApplyProfileAsync(string subjectId, string profileCode, string actor, CancellationToken cancellationToken) => provisioning.ApplyAdminProfileAsync(subjectId, profileCode, actor, cancellationToken);
}

public sealed record AdminSubjectView(
    string SubjectId, string DisplayName, string ComputerNumber, string RegulationNumber, string EmailAddress, string EmploymentStatus,
    string PhotoDataUri, bool AuthenticatorEnrolled, bool PinEnrolled, bool PinLocked, int PinFailedAttempts, bool SelfServiceDisabled,
    string AdAccountName, Guid? AdObjectGuid, string ProvisioningState, string ProvisioningProfileCode, int PendingReviews);
