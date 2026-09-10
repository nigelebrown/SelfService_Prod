# JCF Self-Service Password Reset — hardened redesign

This repository contains the source for the redesigned JCF self-service password reset service. It intentionally does **not** reproduce the original all-in-one deployment.

## Topology

- **JcfSspr.Portal** — unprivileged presentation tier. Deploy the same application in the DMZ and, if desired, on the internal network. It has no SQL or Active Directory credentials and no direct route to AD or the personnel database.
- **JcfSspr.Broker** — internal-only reset authority. It verifies the member against the authoritative view, validates the pre-enrolled TOTP/recovery factor, applies durable throttling, selects the AD object from the server-side authoritative mapping, and performs the reset over validated LDAPS while running as a gMSA/service identity.
- **JcfSspr.Core** — shared contracts and security primitives.

The DMZ portal reaches only the broker HTTPS endpoint. The broker requires an allow-listed client certificate. Network policy should additionally restrict the connection to the portal host(s) and broker TCP/443 only.

## Security invariants

1. Static personnel attributes are lookup data, **not authentication**.
2. A pre-enrolled possession factor is required for every self-service reset.
3. The browser never chooses the AD object to reset. The broker gets `AD Object GUID` and `AD Account Name` from the authoritative member record and resets that exact object.
4. No AD or SQL passwords belong in configuration or source. The broker is designed for Windows integrated authentication/gMSA.
5. LDAPS certificate validation is never bypassed.
6. The AD search base must be the member OU, not the domain root.
7. Protected/admin accounts are refused in code in addition to AD ACLs.
8. Reset requests and member claims have redacted `ToString()` implementations and must never be logged as objects.
9. TOTP codes are replay-protected; recovery codes are one-time and stored only as hashes.
10. Production refuses placeholder/insecure configuration at startup.

## Build

```powershell
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release --no-build
```

Target runtime is .NET 10 LTS. CI also scans committed configuration for likely plaintext secrets and reports vulnerable NuGet dependencies.

## Deployment order

Read `docs/DEPLOYMENT.md`, `docs/DATABASE.md`, and `docs/ARCHITECTURE.md` before installing. The existing exposed SQL and AD passwords from the previous published ZIP must be rotated before this replacement is deployed.
