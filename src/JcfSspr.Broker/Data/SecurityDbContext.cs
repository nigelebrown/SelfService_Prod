using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Data;

public sealed class SecurityDbContext(DbContextOptions<SecurityDbContext> options) : DbContext(options)
{
    public DbSet<TotpEnrollmentEntity> TotpEnrollments => Set<TotpEnrollmentEntity>();
    public DbSet<RecoveryCodeEntity> RecoveryCodes => Set<RecoveryCodeEntity>();
    public DbSet<PinCredentialEntity> PinCredentials => Set<PinCredentialEntity>();
    public DbSet<LocalAdminEntity> LocalAdmins => Set<LocalAdminEntity>();
    public DbSet<SelfServiceStatusEntity> SelfServiceStatuses => Set<SelfServiceStatusEntity>();
    public DbSet<SubjectIdentityEntity> SubjectIdentities => Set<SubjectIdentityEntity>();
    public DbSet<ThrottleEntity> Throttles => Set<ThrottleEntity>();
    public DbSet<ApiReplayEntity> ApiReplayRequests => Set<ApiReplayEntity>();
    public DbSet<AuditEntity> Audits => Set<AuditEntity>();
    public DbSet<ResetTransactionEntity> ResetTransactions => Set<ResetTransactionEntity>();
    public DbSet<ProvisioningReviewEntity> ProvisioningReviews => Set<ProvisioningReviewEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TotpEnrollmentEntity>().ToTable("IdentityTotpEnrollment").HasKey(x => x.ComputerNumber);
        modelBuilder.Entity<RecoveryCodeEntity>().ToTable("IdentityRecoveryCode").HasKey(x => x.Id);
        modelBuilder.Entity<RecoveryCodeEntity>().HasIndex(x => x.ComputerNumber);
        modelBuilder.Entity<PinCredentialEntity>().ToTable("IdentityPinCredential").HasKey(x => x.SubjectId);
        modelBuilder.Entity<LocalAdminEntity>().ToTable("IdentityLocalAdmin").HasKey(x => x.Id);
        modelBuilder.Entity<LocalAdminEntity>().HasIndex(x => x.Username).IsUnique();
        modelBuilder.Entity<SelfServiceStatusEntity>().ToTable("IdentitySelfServiceStatus").HasKey(x => x.SubjectId);
        modelBuilder.Entity<SubjectIdentityEntity>().ToTable("IdentitySubjectLink").HasKey(x => x.SubjectId);
        modelBuilder.Entity<SubjectIdentityEntity>().HasIndex(x => x.AdObjectGuid).IsUnique().HasFilter("[AdObjectGuid] IS NOT NULL");
        modelBuilder.Entity<ThrottleEntity>().ToTable("IdentityThrottle").HasKey(x => x.ThrottleKey);
        modelBuilder.Entity<ApiReplayEntity>().ToTable("IdentityApiReplay").HasKey(x => x.RequestId);
        modelBuilder.Entity<ResetTransactionEntity>().ToTable("IdentityResetTransaction").HasKey(x => x.TokenHash);
        modelBuilder.Entity<ProvisioningReviewEntity>().ToTable("IdentityProvisioningReview").HasKey(x => x.Id);
        modelBuilder.Entity<ProvisioningReviewEntity>().HasIndex(x => new { x.SubjectId, x.Status });
        modelBuilder.Entity<AuditEntity>().ToTable("IdentityAudit").HasKey(x => x.Id);
        modelBuilder.Entity<AuditEntity>().HasIndex(x => x.TimestampUtc);
        modelBuilder.Entity<AuditEntity>().HasIndex(x => new { x.SubjectId, x.TimestampUtc });
    }
}
