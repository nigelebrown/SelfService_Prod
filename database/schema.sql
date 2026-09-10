SET XACT_ABORT ON;
GO

IF OBJECT_ID(N'dbo.SsprTotpEnrollment', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SsprTotpEnrollment
    (
        ComputerNumber       nvarchar(32)  NOT NULL CONSTRAINT PK_SsprTotpEnrollment PRIMARY KEY,
        ProtectedSecret      nvarchar(max) NOT NULL,
        LastAcceptedTimeStep bigint        NOT NULL CONSTRAINT DF_SsprTotpEnrollment_LastStep DEFAULT(-1),
        Enabled              bit           NOT NULL CONSTRAINT DF_SsprTotpEnrollment_Enabled DEFAULT(1),
        UpdatedUtc           datetime2(0)  NOT NULL
    );
END;
GO

IF OBJECT_ID(N'dbo.SsprRecoveryCode', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SsprRecoveryCode
    (
        Id uniqueidentifier NOT NULL CONSTRAINT PK_SsprRecoveryCode PRIMARY KEY,
        ComputerNumber nvarchar(32) NOT NULL,
        CodeHash varbinary(32) NOT NULL,
        CreatedUtc datetime2(0) NOT NULL,
        UsedUtc datetime2(0) NULL
    );
    CREATE INDEX IX_SsprRecoveryCode_ComputerNumber ON dbo.SsprRecoveryCode(ComputerNumber) INCLUDE(CodeHash, UsedUtc);
END;
GO

IF OBJECT_ID(N'dbo.SsprThrottle', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SsprThrottle
    (
        ThrottleKey nvarchar(300) NOT NULL CONSTRAINT PK_SsprThrottle PRIMARY KEY,
        WindowStartUtc datetime2(0) NOT NULL,
        Failures int NOT NULL,
        BlockUntilUtc datetime2(0) NULL
    );
END;
GO

IF OBJECT_ID(N'dbo.SsprResetTransaction', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SsprResetTransaction
    (
        TokenHash varbinary(32) NOT NULL CONSTRAINT PK_SsprResetTransaction PRIMARY KEY,
        ComputerNumber nvarchar(32) NOT NULL,
        AccountName nvarchar(128) NOT NULL,
        ObjectGuid uniqueidentifier NOT NULL,
        SourceIp nvarchar(64) NOT NULL,
        ClientCertificateId nvarchar(128) NOT NULL,
        ExpiresUtc datetime2(0) NOT NULL,
        UsedUtc datetime2(0) NULL,
        PasswordAttempts int NOT NULL CONSTRAINT DF_SsprResetTransaction_Attempts DEFAULT(0)
    );
    CREATE INDEX IX_SsprResetTransaction_ExpiresUtc ON dbo.SsprResetTransaction(ExpiresUtc) INCLUDE(UsedUtc);
END;
GO

IF OBJECT_ID(N'dbo.SsprAudit', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SsprAudit
    (
        Id uniqueidentifier NOT NULL CONSTRAINT PK_SsprAudit PRIMARY KEY,
        CorrelationId nvarchar(64) NOT NULL,
        TimestampUtc datetime2(0) NOT NULL,
        ComputerNumber nvarchar(32) NULL,
        AccountName nvarchar(128) NULL,
        SourceIp nvarchar(64) NULL,
        Outcome nvarchar(32) NOT NULL,
        DetailCode nvarchar(64) NOT NULL
    );
    CREATE INDEX IX_SsprAudit_TimestampUtc ON dbo.SsprAudit(TimestampUtc DESC);
    CREATE INDEX IX_SsprAudit_ComputerNumber ON dbo.SsprAudit(ComputerNumber, TimestampUtc DESC);
END;
GO
