using Microsoft.EntityFrameworkCore;

namespace JcfSspr.Broker.Data;

public sealed class SecurityDbContext(DbContextOptions<SecurityDbContext> options) : DbContext(options)
{
    public DbSet<TotpEnrollmentEntity> TotpEnrollments => Set<TotpEnrollmentEntity>();
    public DbSet<RecoveryCodeEntity> RecoveryCodes => Set<RecoveryCodeEntity>();
    public DbSet<ThrottleEntity> Throttles => Set<ThrottleEntity>();
    public DbSet<AuditEntity> Audits => Set<AuditEntity>();
    public DbSet<ResetTransactionEntity> ResetTransactions => Set<ResetTransactionEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TotpEnrollmentEntity>().ToTable("SsprTotpEnrollment").HasKey(x => x.ComputerNumber);
        modelBuilder.Entity<RecoveryCodeEntity>().ToTable("SsprRecoveryCode").HasKey(x => x.Id);
        modelBuilder.Entity<RecoveryCodeEntity>().HasIndex(x => x.ComputerNumber);
        modelBuilder.Entity<ThrottleEntity>().ToTable("SsprThrottle").HasKey(x => x.ThrottleKey);
        modelBuilder.Entity<ResetTransactionEntity>().ToTable("SsprResetTransaction").HasKey(x => x.TokenHash);
        modelBuilder.Entity<AuditEntity>().ToTable("SsprAudit").HasKey(x => x.Id);
        modelBuilder.Entity<AuditEntity>().HasIndex(x => x.TimestampUtc);
        modelBuilder.Entity<AuditEntity>().HasIndex(x => new { x.ComputerNumber, x.TimestampUtc });
    }
}
