# Database requirements

No new database product is required. Use an existing supported SQL Server instance. The broker uses Windows integrated authentication and expects two logical data sources.

## 1. Authoritative member view

The current reset view must be extended so the application never guesses an account from a typed email/name. It needs these columns:

```text
Computer No
First Name
Last Name
TRN
Date of Birth
AD Account Name
AD Object GUID
Email Address
```

`AD Account Name` must be the exact issued `sAMAccountName`. `AD Object GUID` must be the immutable GUID of that AD user. `Email Address` is for post-reset notification only and is never an authentication factor.

The lookup account/gMSA requires `SELECT` on this view only.

## 2. SSPR security database

Run `database/schema.sql` on an existing supported SQL Server instance to create the tables used for encrypted TOTP enrollment metadata, hashed recovery codes, throttling, and audit events.

The broker protects TOTP secrets with ASP.NET Core Data Protection. The database never stores the raw secret. Recovery codes are random and only SHA-256 hashes are retained.
