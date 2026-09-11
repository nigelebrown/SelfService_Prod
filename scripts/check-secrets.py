from pathlib import Path
import json, re, sys

bad=[]
metadata_markers=('file','path','variable','length','policy','algorithm','iterations','enabled','minutes','days','issuer','code')
for path in Path('.').rglob('*.json'):
    if any(part in {'bin','obj'} for part in path.parts): continue
    try: obj=json.loads(path.read_text(encoding='utf-8'))
    except Exception: continue
    def walk(value, prefix=''):
        if isinstance(value, dict):
            for k,v in value.items():
                key=f'{prefix}:{k}' if prefix else k
                lower=k.lower()
                looks_sensitive=any(x in lower for x in ('password','secret','token'))
                is_metadata=any(x in lower for x in metadata_markers)
                if isinstance(v,str) and looks_sensitive and not is_metadata:
                    if v and 'REPLACE' not in v.upper() and v not in ('false','true'):
                        bad.append((str(path), key))
                walk(v,key)
        elif isinstance(value,list):
            for i,v in enumerate(value): walk(v,f'{prefix}[{i}]')
    walk(obj)

patterns=[
    re.compile(r'(?i)(password|secret|token)\s*[=:]\s*["\'](?!REPLACE)[^"\']{6,}["\']'),
    re.compile(r'(?i)(User Id|Uid)\s*=.+;\s*(Password|Pwd)\s*=')
]
text_extensions={'.json','.yml','.yaml','.config','.xml','.env','.ps1','.sh','.md'}
for path in Path('.').rglob('*'):
    if not path.is_file() or path.suffix.lower() not in text_extensions: continue
    if any(part in {'.git','bin','obj'} for part in path.parts): continue
    text=path.read_text(encoding='utf-8',errors='ignore')
    for pattern in patterns:
        if pattern.search(text): bad.append((str(path),'pattern'))

if bad:
    print('Potential committed secret(s) detected:')
    for item in sorted(set(bad)): print(' -', item[0], item[1])
    sys.exit(1)
print('No likely plaintext production secrets detected.')
