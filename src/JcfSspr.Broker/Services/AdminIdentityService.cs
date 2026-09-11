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

    public async Task SetMemberChosenPinAsync(string subjectId, string pin, string actor, string supportReference, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(supportReference) || supportReference.Trim().Length is < 3 or > 100)
            throw new InvalidOperationException("Enter a valid support/reference number or reason before registering the member PIN.");
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        await pins.SetAsync(subjectId, pin, cancellationToken);
        await AuditAsync(person, actor, "AssistedPinRegistered", SanitizeDetail(supportReference), cancellationToken);
    }

    public async Task<string> IssuePinAsync(string subjectId, string actor, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        var length = Math.Clamp(10, _pinOptions.MinimumDigits, _pinOptions.MaximumDigits);
        var builder = new StringBuilder(length);
        for (var index = 0; index < length; index++) builder.Append(RandomNumberGenerator.GetInt32(10));
        var pin = builder.ToString();
        await pins.SetAsync(subjectId, pin, cancellationToken);
        await AuditAsync(person, actor, "PinIssued", "Administrator-generated fallback PIN", cancellationToken);
        return pin;
    }

    public async Task UnlockPinAsync(string subjectId, string actor, string supportReference, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        await pins.UnlockAsync(subjectId, cancellationToken);
        await AuditAsync(person, actor, "PinUnlocked", RequireReference(supportReference), cancellationToken);
    }

    public async Task ResetAuthenticatorAsync(string subjectId, string actor, string supportReference, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the HR directory.");
        await totp.DisableAsync(person.ComputerNumber, cancellationToken);
        await AuditAsync(person, actor, "AuthenticatorRevoked", RequireReference(supportReference), cancellationToken);
    }

    public async Task SetSelfServiceDisabledAsync(string subjectId, bool disabled, string reason, string actor, string supportReference, CancellationToken cancellationToken)
    {
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        var reference = RequireReference(supportReference);
        var entity = await db.SelfServiceStatuses.SingleOrDefaultAsync(x => x.SubjectId == subjectId, cancellationToken);
        if (entity is null)
        {
            entity = new SelfServiceStatusEntity { SubjectId = subjectId };
            db.SelfServiceStatuses.Add(entity);
        }
        entity.Disabled = disabled;
        entity.DisabledReason = disabled ? reason[..Math.Min(reason.Length, 200)] : string.Empty;
        entity.UpdatedUtc = timeProvider.GetUtcNow().UtcDateTime;
        db.Audits.Add(BuildAudit(person, actor, disabled ? "SelfServiceDisabled" : "SelfServiceEnabled", reference));
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ApplyProfileAsync(string subjectId, string profileCode, string actor, string changeReference, CancellationToken cancellationToken)
    {
        var reference = RequireReference(changeReference);
        await provisioning.ApplyAdminProfileAsync(subjectId, profileCode, actor, cancellationToken);
        var person = await hr.FindBySubjectIdAsync(subjectId, cancellationToken) ?? throw new InvalidOperationException("Subject was not found in the active HR directory.");
        await AuditAsync(person, actor, "ProvisioningProfileApproved", $"{reference}; profile={profileCode[..Math.Min(profileCode.Length, 64)]}", cancellationToken);
    }

    public async Task<IReadOnlyList<AdminReviewView>> GetOpenReviewsAsync(CancellationToken cancellationToken)
    {
        var reviews = await db.ProvisioningReviews.AsNoTracking().Where(x => x.Status == "Open").OrderBy(x => x.CreatedUtc).Take(200).ToListAsync(cancellationToken);
        var output = new List<AdminReviewView>(reviews.Count);
        foreach (var review in reviews)
        {
            var person = await hr.FindBySubjectIdAsync(review.SubjectId, cancellationToken);
            output.Add(new AdminReviewView(review.Id, review.SubjectId, person?.DisplayName ?? "Unavailable HR record", person?.ComputerNumber ?? string.Empty,
                review.ReasonCode, review.Details, review.CreatedUtc));
        }
        return output;
    }

    public async Task<ReviewResolutionResult> RetryReviewAsync(Guid reviewId, string actor, string changeReference, CancellationToken cancellationToken)
    {
        var reference = RequireReference(changeReference);
        var review = await db.ProvisioningReviews.SingleOrDefaultAsync(x => x.Id == reviewId && x.Status == "Open", cancellationToken)
            ?? throw new InvalidOperationException("Open review was not found.");
        var person = await hr.FindBySubjectIdAsync(review.SubjectId, cancellationToken) ?? throw new InvalidOperationException("The HR identity is no longer active or available.");
        var retryStarted = timeProvider.GetUtcNow().UtcDateTime;
        var resolution = await provisioning.ResolveOrProvisionAsync(person, string.Empty, cancellationToken);
        if (resolution.AdminReviewRequired || resolution.Member is null)
        {
            var duplicateReviews = await db.ProvisioningReviews.Where(x => x.SubjectId == review.SubjectId && x.Id != review.Id && x.Status == "Open" && x.CreatedUtc >= retryStarted).ToListAsync(cancellationToken);
            db.ProvisioningReviews.RemoveRange(duplicateReviews);
            review.Details = "Retry remains unresolved. Correct the underlying HR/AD conflict and retry.";
            await db.SaveChangesAsync(cancellationToken);
            await AuditAsync(person, actor, "ProvisioningReviewRetryPending", reference, cancellationToken);
            return new ReviewResolutionResult(false, "The conflict is still present. No directory identity was changed.");
        }
        review.Status = "Resolved";
        review.ResolvedUtc = timeProvider.GetUtcNow().UtcDateTime;
        review.ResolvedBy = actor[..Math.Min(actor.Length, 256)];
        review.ResolutionNotes = SanitizeDetail(reference);
        await db.SaveChangesAsync(cancellationToken);
        await AuditAsync(person, actor, "ProvisioningReviewResolved", reference, cancellationToken);
        return new ReviewResolutionResult(true, "The identity was safely resolved and the review is closed.");
    }

    public async Task CloseReviewAsync(Guid reviewId, string actor, string resolutionNotes, CancellationToken cancellationToken)
    {
        var notes = RequireReference(resolutionNotes);
        var review = await db.ProvisioningReviews.SingleOrDefaultAsync(x => x.Id == reviewId && x.Status == "Open", cancellationToken)
            ?? throw new InvalidOperationException("Open review was not found.");
        review.Status = "Closed";
        review.ResolvedUtc = timeProvider.GetUtcNow().UtcDateTime;
        review.ResolvedBy = actor[..Math.Min(actor.Length, 256)];
        review.ResolutionNotes = notes;
        var person = await hr.FindBySubjectIdAsync(review.SubjectId, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if (person is not null) await AuditAsync(person, actor, "ProvisioningReviewClosed", notes, cancellationToken);
    }

    private async Task AuditAsync(HrPersonRecord person, string actor, string detailCode, string detail, CancellationToken cancellationToken)
    {
        db.Audits.Add(BuildAudit(person, actor, detailCode, detail));
        await db.SaveChangesAsync(cancellationToken);
    }

    private AuditEntity BuildAudit(HrPersonRecord person, string actor, string detailCode, string detail)
    {
        var link = db.SubjectIdentities.Local.FirstOrDefault(x => x.SubjectId == person.SubjectId);
        return new AuditEntity
        {
            Id = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("N"), TimestampUtc = timeProvider.GetUtcNow().UtcDateTime,
            SubjectId = person.SubjectId, ComputerNumber = person.ComputerNumber, AccountName = link?.AdAccountName,
            Actor = actor[..Math.Min(actor.Length, 256)], Category = "Administration", Outcome = "Success", DetailCode = detailCode,
            Detail = SanitizeDetail(detail)
        };
    }

    private static string RequireReference(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length is < 3 or > 100) throw new InvalidOperationException("A support/change reference of 3-100 characters is required.");
        return SanitizeDetail(trimmed);
    }

    private static string SanitizeDetail(string value)
    {
        var safe = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return safe[..Math.Min(safe.Length, 500)];
    }
}

public sealed record AdminSubjectView(
    string SubjectId, string DisplayName, string ComputerNumber, string RegulationNumber, string EmailAddress, string EmploymentStatus,
    string PhotoDataUri, bool AuthenticatorEnrolled, bool PinEnrolled, bool PinLocked, int PinFailedAttempts, bool SelfServiceDisabled,
    string AdAccountName, Guid? AdObjectGuid, string ProvisioningState, string ProvisioningProfileCode, int PendingReviews);

public sealed record AdminReviewView(Guid Id, string SubjectId, string DisplayName, string ComputerNumber, string ReasonCode, string Details, DateTime CreatedUtc);
public sealed record ReviewResolutionResult(bool Resolved, string Message);
