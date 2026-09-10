# Deployment

## Before deployment

- Rotate the SQL and AD credentials exposed in the previous published build.
- Correct the domain controller certificate and remove every certificate-validation bypass.
- Ensure the member view includes authoritative AD account name and AD object GUID.
- Create the SSPR security tables using `database/schema.sql`.
- Create/delegate a gMSA (preferred) for the broker. Grant password-reset rights only on the member OU. Do not grant Domain Admin or broad directory rights.
- Issue three certificates from the existing internal PKI: broker server certificate, DMZ portal client certificate, internal portal client certificate.

## Internal broker

1. Install .NET 10 ASP.NET Core Hosting Bundle on the Windows/IIS host.
2. Run the broker IIS application pool as the gMSA.
3. Configure both SQL connection strings for `Integrated Security=True;Encrypt=True;TrustServerCertificate=False`.
4. Configure the LDAPS server by DNS name, port 636, and member OU search base.
5. Put only the two portal client-certificate thumbprints in `BrokerSecurity:AllowedClientCertificateThumbprints`.
6. Set `DataProtection:KeyPath` to an ACL-protected directory accessible only to the broker gMSA and administrators.
7. Configure IIS to accept client certificates on the API binding and use Windows Authentication for `/enroll`.
8. Firewall the broker API so only the two portal hosts can reach it.

## Portal instances

Deploy `JcfSspr.Portal` twice if external and internal access are both required. Each instance:

- runs behind IIS/reverse proxy on loopback;
- has a unique client certificate installed in LocalMachine/My with the app-pool identity granted private-key read permission;
- is configured only with the broker URL and its certificate thumbprint;
- has no SQL/LDAP configuration;
- accepts no direct traffic to the Kestrel loopback port.

The DMZ firewall permits only portal -> broker TCP/443. It must not permit portal -> DC or portal -> SQL.

## Production startup gates

Both applications intentionally refuse to start in `Production` if critical settings still contain `REPLACE-...`, wildcard hosts are used, the broker URL is not HTTPS, the broker client-certificate allowlist is empty, or the AD search base is not an OU.

## Monitoring

Collect broker structured logs and the `SsprAudit` SQL table into the existing SOC/SIEM workflow. Alert on unusual reset volume, repeated failures, blocked source addresses, enrollment changes, certificate failures, and any attempted protected-account reset.
