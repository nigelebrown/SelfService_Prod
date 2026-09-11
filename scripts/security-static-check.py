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
        if re.search(pattern, data, flags=re.I|re.S):
            errors.append(f'{path.relative_to(root)}: {label}')

portal = root / 'src' / 'JcfSspr.Portal'
for path in portal.rglob('*.cs'):
    data = path.read_text(encoding='utf-8', errors='ignore')
    for forbidden in ('System.DirectoryServices', 'Microsoft.Data.SqlClient', 'LdapConnection', 'SqlConnection'):
        if forbidden in data:
            errors.append(f'{path.relative_to(root)}: DMZ package directly references internal data/directory API {forbidden}')

broker_program = (root/'src/JcfSspr.Broker/Program.cs').read_text(encoding='utf-8')
for old_route in ('"/api/v1/verify"', '"/api/v1/reset"'):
    if old_route in broker_program:
        errors.append(f'src/JcfSspr.Broker/Program.cs: legacy API route still exposed: {old_route}')

for config_path in (root/'src/JcfSspr.Broker/appsettings.json', root/'src/JcfSspr.Portal/appsettings.json'):
    cfg = json.loads(config_path.read_text(encoding='utf-8'))
    if cfg.get('AllowedHosts') == '*': errors.append(f'{config_path.relative_to(root)}: wildcard AllowedHosts')

broker_cfg = json.loads((root/'src/JcfSspr.Broker/appsettings.json').read_text(encoding='utf-8'))
blocked = {x.lower() for x in broker_cfg.get('Provisioning',{}).get('BlockedGroupDns',[])}
for profile in broker_cfg.get('Provisioning',{}).get('Profiles',[]):
    for group in profile.get('GroupDns',[]):
        if group.lower() in blocked:
            errors.append(f'appsettings.json: provisioning profile {profile.get("Code")} contains blocked group {group}')

if errors:
    print('SECURITY STATIC CHECK FAILED')
    for error in errors: print(' -', error)
    sys.exit(1)
print('Security static checks passed.')
