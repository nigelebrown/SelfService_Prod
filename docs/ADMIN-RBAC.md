# Administrative RBAC and assisted registration

## AD security-group authorization

Do not add individual administrators inside the application. Create dedicated AD security groups, record their immutable SIDs in `AdminAuthorization`, and manage membership in AD.

- `PlatformAdminGroupSids`: full platform administration and break-glass rotation. Keep membership very small.
- `HelpdeskGroupSids`: member search, PIN unlock, authenticator revocation and assisted registration.
- `ProvisioningAdminGroupSids`: apply approved OU/group profiles and resolve provisioning review cases.
- `SecurityAdminGroupSids`: enable/disable self-service and security response functions.
- `AuditorGroupSids`: read-only audit search.

Platform admins inherit the operational roles. The local break-glass identity can enter the internal console when AD web authentication is unavailable but must not be used for routine administration.

## Assisted registration

1. Helpdesk authenticates using its AD account and opens **Assisted registration**.
2. Search the employee through the HR source.
3. Compare the employee in person against the authoritative HR photograph/profile.
4. Record the visit/support/ticket reference and confirm the member is physically present.
5. Turn the input device to the member or otherwise provide privacy. The member types and confirms their own 8–12 digit PIN into masked fields. The administrator must not ask the member to say the PIN aloud.
6. The service stores only the salted/peppered verifier and clears the request model fields.
7. The member uses the PIN through the ordinary portal to establish TOTP. TOTP is the preferred factor thereafter.

The assisted-registration screen does not reveal the chosen PIN after submission. Administrators cannot retrieve PINs or TOTP secrets.

## Support actions

PIN unlock and authenticator revocation require a support reference. Provisioning changes require a change/ticket reference. Self-service disable/enable requires the Security Admin role and a security/change reference. These references are written to append-only audit events.
