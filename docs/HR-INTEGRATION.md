# HR integration contract

The Internal Identity Service is the only component permitted to query the HR/personnel source. The DMZ portal must never connect directly to HR or SQL.

The configured `MemberDirectory:ViewName` must expose one row per active employee with these columns:

- `EmployeeId` — immutable HR subject identifier. This is the authoritative identity anchor.
- `ComputerNumber`
- `RegulationNumber`
- `Username`
- `FirstName`
- `MiddleName`
- `LastName`
- `TRN`
- `DateOfBirth`
- `EmailAddress`
- `EmploymentStatus`
- `PhotoBase64` — optional base64 image payload. Keep images reasonably sized; the service rejects oversized payloads.
- `PhotoContentType` — for example `image/jpeg`.

The view account is read-only and uses Windows integrated authentication with SQL certificate validation. No PIN should be returned by this view.

## Identity semantics

Employee attributes resolve a claimed person; they do not authenticate the person. Initial external bootstrap uses the secure PIN and, by default, at least two matching HR corroboration attributes. After bootstrap, TOTP is the preferred authentication mechanism.

The photograph and profile are released to the DMZ only after successful PIN/TOTP authentication and are marked no-store by the portal.
