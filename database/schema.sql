SET XACT_ABORT ON;
GO

IF OBJECT_ID(N'dbo.IdentityTotpEnrollment', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityTotpEnrollment (ComputerNumber nvarchar(32) NOT NULL CONSTRAINT PK_IdentityTotpEnrollment PRIMARY KEY, ProtectedSecret nvarchar(max) NOT NULL, LastAcceptedTimeStep bigint NOT NULL CONSTRAINT DF_IdentityTotpEnrollment_LastStep DEFAULT(-1), Enabled bit NOT NULL CONSTRAINT DF_IdentityTotpEnrollment_Enabled DEFAULT(1), UpdatedUtc datetime2(0) NOT NULL);
END;
GO
IF OBJECT_ID(N'dbo.IdentityRecoveryCode', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityRecoveryCode (Id uniqueidentifier NOT NULL CONSTRAINT PK_IdentityRecoveryCode PRIMARY KEY, ComputerNumber nvarchar(32) NOT NULL, CodeHash varbinary(32) NOT NULL, CreatedUtc datetime2(0) NOT NULL, UsedUtc datetime2(0) NULL);
    CREATE INDEX IX_IdentityRecoveryCode_ComputerNumber ON dbo.IdentityRecoveryCode(ComputerNumber) INCLUDE(CodeHash, UsedUtc);
END;
GO
IF OBJECT_ID(N'dbo.IdentityPinCredential', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityPinCredential (SubjectId nvarchar(128) NOT NULL CONSTRAINT PK_IdentityPinCredential PRIMARY KEY, Salt varbinary(32) NOT NULL, Verifier varbinary(32) NOT NULL, Iterations int NOT NULL, FailedAttempts int NOT NULL CONSTRAINT DF_IdentityPinCredential_Failures DEFAULT(0), Locked bit NOT NULL CONSTRAINT DF_IdentityPinCredential_Locked DEFAULT(0), LockedUtc datetime2(0) NULL, Enabled bit NOT NULL CONSTRAINT DF_IdentityPinCredential_Enabled DEFAULT(1), UpdatedUtc datetime2(0) NOT NULL);
END;
GO
IF OBJECT_ID(N'dbo.IdentityLocalAdmin', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityLocalAdmin (Id int NOT NULL CONSTRAINT PK_IdentityLocalAdmin PRIMARY KEY, Username nvarchar(64) NOT NULL, PasswordSalt varbinary(32) NOT NULL, PasswordVerifier varbinary(32) NOT NULL, Iterations int NOT NULL, ProtectedTotpSecret nvarchar(max) NOT NULL, LastAcceptedTimeStep bigint NOT NULL CONSTRAINT DF_IdentityLocalAdmin_LastStep DEFAULT(-1), FailedAttempts int NOT NULL CONSTRAINT DF_IdentityLocalAdmin_Failures DEFAULT(0), BlockedUntilUtc datetime2(0) NULL, Enabled bit NOT NULL CONSTRAINT DF_IdentityLocalAdmin_Enabled DEFAULT(1), UpdatedUtc datetime2(0) NOT NULL);
    CREATE UNIQUE INDEX UX_IdentityLocalAdmin_Username ON dbo.IdentityLocalAdmin(Username);
END;
GO
IF OBJECT_ID(N'dbo.IdentitySelfServiceStatus', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentitySelfServiceStatus (SubjectId nvarchar(128) NOT NULL CONSTRAINT PK_IdentitySelfServiceStatus PRIMARY KEY, Disabled bit NOT NULL CONSTRAINT DF_IdentitySelfServiceStatus_Disabled DEFAULT(0), DisabledReason nvarchar(200) NOT NULL CONSTRAINT DF_IdentitySelfServiceStatus_Reason DEFAULT(''), UpdatedUtc datetime2(0) NOT NULL);
END;
GO
IF OBJECT_ID(N'dbo.IdentitySubjectLink', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentitySubjectLink (SubjectId nvarchar(128) NOT NULL CONSTRAINT PK_IdentitySubjectLink PRIMARY KEY, ComputerNumber nvarchar(32) NOT NULL, RegulationNumber nvarchar(64) NOT NULL, EmailAddress nvarchar(320) NOT NULL, AdAccountName nvarchar(128) NOT NULL, AdObjectGuid uniqueidentifier NULL, ProvisioningState nvarchar(32) NOT NULL, ProvisioningProfileCode nvarchar(64) NOT NULL CONSTRAINT DF_IdentitySubjectLink_Profile DEFAULT(''), CreatedUtc datetime2(0) NOT NULL, UpdatedUtc datetime2(0) NOT NULL);
    CREATE UNIQUE INDEX UX_IdentitySubjectLink_AdObjectGuid ON dbo.IdentitySubjectLink(AdObjectGuid) WHERE AdObjectGuid IS NOT NULL;
    CREATE INDEX IX_IdentitySubjectLink_ComputerNumber ON dbo.IdentitySubjectLink(ComputerNumber);
END;
GO
IF OBJECT_ID(N'dbo.IdentityThrottle', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityThrottle (ThrottleKey nvarchar(300) NOT NULL CONSTRAINT PK_IdentityThrottle PRIMARY KEY, WindowStartUtc datetime2(0) NOT NULL, Failures int NOT NULL, BlockUntilUtc datetime2(0) NULL);
END;
GO
IF OBJECT_ID(N'dbo.IdentityApiReplay', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityApiReplay (RequestId nvarchar(300) NOT NULL CONSTRAINT PK_IdentityApiReplay PRIMARY KEY, ExpiresUtc datetime2(0) NOT NULL);
    CREATE INDEX IX_IdentityApiReplay_ExpiresUtc ON dbo.IdentityApiReplay(ExpiresUtc);
END;
GO
IF OBJECT_ID(N'dbo.IdentityResetTransaction', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityResetTransaction (TokenHash varbinary(32) NOT NULL CONSTRAINT PK_IdentityResetTransaction PRIMARY KEY, SubjectId nvarchar(128) NOT NULL CONSTRAINT DF_IdentityResetTransaction_Subject DEFAULT(''), ComputerNumber nvarchar(32) NOT NULL, AccountName nvarchar(128) NOT NULL, ObjectGuid uniqueidentifier NOT NULL, SourceIp nvarchar(64) NOT NULL, ClientCertificateId nvarchar(128) NOT NULL, ProfileConfirmed bit NOT NULL CONSTRAINT DF_IdentityResetTransaction_ProfileConfirmed DEFAULT(0), RequiresTotpEnrollment bit NOT NULL CONSTRAINT DF_IdentityResetTransaction_Totp DEFAULT(0), ExpiresUtc datetime2(0) NOT NULL, UsedUtc datetime2(0) NULL, PasswordAttempts int NOT NULL CONSTRAINT DF_IdentityResetTransaction_Attempts DEFAULT(0));
    CREATE INDEX IX_IdentityResetTransaction_ExpiresUtc ON dbo.IdentityResetTransaction(ExpiresUtc) INCLUDE(UsedUtc);
END;
GO
IF OBJECT_ID(N'dbo.IdentityProvisioningReview', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityProvisioningReview (Id uniqueidentifier NOT NULL CONSTRAINT PK_IdentityProvisioningReview PRIMARY KEY, SubjectId nvarchar(128) NOT NULL, ReasonCode nvarchar(64) NOT NULL, Details nvarchar(500) NOT NULL, Status nvarchar(32) NOT NULL CONSTRAINT DF_IdentityProvisioningReview_Status DEFAULT('Open'), CreatedUtc datetime2(0) NOT NULL, ResolvedUtc datetime2(0) NULL, ResolvedBy nvarchar(256) NOT NULL CONSTRAINT DF_IdentityProvisioningReview_ResolvedBy DEFAULT(''), ResolutionNotes nvarchar(500) NOT NULL CONSTRAINT DF_IdentityProvisioningReview_Notes DEFAULT(''));
    CREATE INDEX IX_IdentityProvisioningReview_Subject_Status ON dbo.IdentityProvisioningReview(SubjectId, Status);
END;
ELSE IF COL_LENGTH('dbo.IdentityProvisioningReview', 'ResolutionNotes') IS NULL
    ALTER TABLE dbo.IdentityProvisioningReview ADD ResolutionNotes nvarchar(500) NOT NULL CONSTRAINT DF_IdentityProvisioningReview_Notes2 DEFAULT('');
GO
IF OBJECT_ID(N'dbo.IdentityAudit', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentityAudit (Id uniqueidentifier NOT NULL CONSTRAINT PK_IdentityAudit PRIMARY KEY, CorrelationId nvarchar(64) NOT NULL, TimestampUtc datetime2(0) NOT NULL, SubjectId nvarchar(128) NULL, ComputerNumber nvarchar(32) NULL, AccountName nvarchar(128) NULL, SourceIp nvarchar(64) NULL, Actor nvarchar(256) NOT NULL CONSTRAINT DF_IdentityAudit_Actor DEFAULT('SelfService'), Category nvarchar(64) NOT NULL CONSTRAINT DF_IdentityAudit_Category DEFAULT('Identity'), Outcome nvarchar(32) NOT NULL, DetailCode nvarchar(64) NOT NULL, Detail nvarchar(500) NOT NULL CONSTRAINT DF_IdentityAudit_Detail DEFAULT(''));
    CREATE INDEX IX_IdentityAudit_TimestampUtc ON dbo.IdentityAudit(TimestampUtc DESC);
    CREATE INDEX IX_IdentityAudit_SubjectId ON dbo.IdentityAudit(SubjectId, TimestampUtc DESC);
END;
ELSE IF COL_LENGTH('dbo.IdentityAudit', 'Detail') IS NULL
    ALTER TABLE dbo.IdentityAudit ADD Detail nvarchar(500) NOT NULL CONSTRAINT DF_IdentityAudit_Detail2 DEFAULT('');
GO
IF OBJECT_ID(N'dbo.IdentitySecurityAlertDelivery', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.IdentitySecurityAlertDelivery (AuditId uniqueidentifier NOT NULL CONSTRAINT PK_IdentitySecurityAlertDelivery PRIMARY KEY, Attempts int NOT NULL CONSTRAINT DF_IdentitySecurityAlertDelivery_Attempts DEFAULT(0), DeliveredUtc datetime2(0) NULL, UpdatedUtc datetime2(0) NOT NULL, LastError nvarchar(200) NOT NULL CONSTRAINT DF_IdentitySecurityAlertDelivery_Error DEFAULT(''));
END;
GO
CREATE OR ALTER TRIGGER dbo.TR_IdentityAudit_AppendOnly ON dbo.IdentityAudit
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 51001, 'IdentityAudit is append-only. UPDATE and DELETE are prohibited.', 1;
END;
GO
