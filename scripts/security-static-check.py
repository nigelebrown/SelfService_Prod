#!/usr/bin/env python3
from pathlib import Path
import json, re, sys

root = Path(__file__).resolve().parents[1]
errors = []
text_files = [p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in {'.cs','.json','.yml','.yaml','.cshtml'} and '.git' not in p.parts and 'bin' not in p.parts and 'obj' not in p.parts]

banned = {
    r'TrustAnyCertificate\s*[:=]\s*true': 'certificate validation bypass',
    r'TrustServerCertificate\s*=\s*True': 'SQL certificate validation bypass',
    r'ServerCertificateCustomValidationCallback\s*=.*=>\s*true': 'HTTP certificate validation bypass',
    r'VerifyServerCertificate.*return\s+true': 'LDAP certificate validation bypass',
}
for path in text_files:
    data = path.read_text(encoding='utf-8', errors='ignore')
    for pattern, label in banned.items():
        if re.search(pattern, data, flags=re.I|re.S): errors.append(f'{path.relative_to(root)}: {label}')

portal = root / 'src' / 'JcfSspr.Portal'
for path in portal.rglob('*.cs'):
    data = path.read_text(encoding='utf-8', errors='ignore')
    for forbidden in ('System.DirectoryServices', 'Microsoft.Data.SqlClient', 'LdapConnection', 'SqlConnection'):
        if forbidden in data: errors.append(f'{path.relative_to(root)}: DMZ package directly references internal data/directory API {forbidden}')

broker_program = (root/'src/JcfSspr.Broker/Program.cs').read_text(encoding='utf-8')
for old_route in ('"/api/v1/verify"', '"/api/v1/reset"'):
    if old_route in broker_program: errors.append(f'src/JcfSspr.Broker/Program.cs: legacy API route still exposed: {old_route}')
for required_policy in ('Helpdesk','ProvisioningAdmin','SecurityAdmin','AuditReader','DirectoryAdminOnly'):
    if f'"{required_policy}"' not in broker_program: errors.append(f'src/JcfSspr.Broker/Program.cs: required admin RBAC policy missing: {required_policy}')

for config_path in (root/'src/JcfSspr.Broker/appsettings.json', root/'src/JcfSspr.Portal/appsettings.json'):
    cfg = json.loads(config_path.read_text(encoding='utf-8'))
    if cfg.get('AllowedHosts') == '*': errors.append(f'{config_path.relative_to(root)}: wildcard AllowedHosts')

broker_cfg = json.loads((root/'src/JcfSspr.Broker/appsettings.json').read_text(encoding='utf-8'))
prov = broker_cfg.get('Provisioning',{})
blocked = {x.lower() for x in prov.get('BlockedGroupDns',[])}
allowed_codes = {x.lower() for x in prov.get('SelfServiceAllowedProfileCodes',[])}
allowed_groups = {x.lower() for x in prov.get('SelfServiceAllowedGroupDns',[])}
for profile in prov.get('Profiles',[]):
    code = str(profile.get('Code',''))
    groups = profile.get('GroupDns',[])
    for group in groups:
        if group.lower() in blocked: errors.append(f'appsettings.json: provisioning profile {code} contains blocked group {group}')
    if profile.get('UserSelectable'):
        if code.lower() not in allowed_codes: errors.append(f'appsettings.json: user-selectable profile {code} is not on positive self-service profile allow-list')
        for group in groups:
            if group.lower() not in allowed_groups: errors.append(f'appsettings.json: self-service profile {code} contains group not on positive allow-list: {group}')
if not prov.get('RequireNestedGroupValidation', False): errors.append('appsettings.json: nested/transitive provisioning-group validation must remain enabled')

schema = (root/'database/schema.sql').read_text(encoding='utf-8', errors='ignore')
if 'TR_IdentityAudit_AppendOnly' not in schema: errors.append('database/schema.sql: append-only audit trigger is missing')

assisted = root/'src/JcfSspr.Broker/Pages/Admin/AssistedRegistration.cshtml'
if not assisted.exists() or 'type="password"' not in assisted.read_text(encoding='utf-8', errors='ignore'):
    errors.append('assisted registration must use masked member-entered PIN fields')

if errors:
    print('SECURITY STATIC CHECK FAILED')
    for error in errors: print(' -', error)
    sys.exit(1)
print('Security static checks passed.')
