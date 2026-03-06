import re
import sys
from pathlib import Path

BASE = Path.home() / "Downloads" / "ubuntu-powershell-vm"
SCRIPT_PATH = BASE / "Build-UbuntuAutoinstallVM15.ps1"

def read_file(path):
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            with open(path, encoding=enc) as f:
                return f.readlines()
        except (UnicodeDecodeError, UnicodeError):
            continue
    sys.exit("ERROR: Could not decode file")

lines = read_file(SCRIPT_PATH)
SEP = "=" * 70

print(SEP)
print("1. CURLY BRACE BALANCE  { }")
print(SEP)
oc = sum(l.count("{") for l in lines)
cc = sum(l.count("}") for l in lines)
print(f"  Opening braces:  {oc}")
print(f"  Closing braces:  {cc}")
bal_curly = oc - cc
if bal_curly == 0:
    print("  Balance: OK (0)")
else:
    print(f"  *** IMBALANCE: {bal_curly:+d}")

print()
print("  Running brace depth (transitions):")
depth = 0
for i, line in enumerate(lines, 1):
    o2 = line.count("{")
    c2 = line.count("}")
    if o2 or c2:
        old = depth
        depth += o2 - c2
        s = line.rstrip()
        if len(s) > 90:
            s = s[:87] + "..."
        print(f"    Line {i:4d}: depth {old:+d} -> {depth:+d}  | {s}")
if depth != 0:
    print(f"  *** Final depth = {depth} (should be 0)")

print()
print(SEP)
print("2. PARENTHESIS BALANCE  ( )")
print(SEP)
op = sum(l.count("(") for l in lines)
cp = sum(l.count(")") for l in lines)
print(f"  Opening parens:  {op}")
print(f"  Closing parens:  {cp}")
bal_paren = op - cp
if bal_paren == 0:
    print("  Balance: OK (0)")
else:
    print(f"  *** IMBALANCE: {bal_paren:+d}")

print()
print(SEP)
print("3. HERE-STRING BALANCE")
print(SEP)

hs_opens = []
hs_closes = []
sq_opens = []
sq_closes = []

for i, line in enumerate(lines, 1):
    stripped = line.rstrip()
    if re.search(r'@"[ \t]*$', stripped):
        hs_opens.append(i)
    if re.match(r'^[ \t]*"@', line):
        hs_closes.append(i)
    if re.search(r"@'[ \t]*$", stripped):
        sq_opens.append(i)
    if re.match(r"^[ \t]*'@", line):
        sq_closes.append(i)

print('  Double-quote here-strings @"..."@:')
print(f'    Openers (@"): {len(hs_opens)}')
for ln in hs_opens:
    print(f"      Line {ln:4d}: {lines[ln-1].rstrip()}")
print(f'    Closers ("@): {len(hs_closes)}')
for ln in hs_closes:
    print(f"      Line {ln:4d}: {lines[ln-1].rstrip()}")
hb = len(hs_opens) - len(hs_closes)
if hb == 0:
    print(f"    Balance: OK (0) -- {len(hs_opens)} pairs")
else:
    print(f"    *** IMBALANCE: {hb:+d}")

sb = 0
if sq_opens or sq_closes:
    print()
    print("  Single-quote here-strings @'...'@:")
    print(f"    Openers (@'): {len(sq_opens)}")
    for ln in sq_opens:
        print(f"      Line {ln:4d}: {lines[ln-1].rstrip()}")
    print(f"    Closers ('@): {len(sq_closes)}")
    for ln in sq_closes:
        print(f"      Line {ln:4d}: {lines[ln-1].rstrip()}")
    sb = len(sq_opens) - len(sq_closes)
    if sb == 0:
        print(f"    Balance: OK (0) -- {len(sq_opens)} pairs")
    else:
        print(f"    *** IMBALANCE: {sb:+d}")

print()
print(SEP)
print("4. TOTAL LINES")
print(SEP)
print(f"  Total lines in file: {len(lines)}")

print()
print(SEP)
print("5. AUTOINSTALL YAML SECTION")
print(SEP)

yaml_sections = []
in_yaml = False
current_yaml = []
yaml_start = None

for i, line in enumerate(lines, 1):
    if "#cloud-config" in line and not in_yaml:
        in_yaml = True
        yaml_start = i
        current_yaml = [(i, line.rstrip())]
    elif in_yaml:
        if re.match(r'^[ \t]*"@', line) or re.match(r"^[ \t]*'@", line):
            in_yaml = False
            yaml_sections.append((yaml_start, current_yaml))
            current_yaml = []
        else:
            current_yaml.append((i, line.rstrip()))

if in_yaml:
    yaml_sections.append((yaml_start, current_yaml))
    print("  *** WARNING: YAML not closed by EOF!")

if not yaml_sections:
    print("  No autoinstall YAML section found.")
else:
    for idx, (start, ylines) in enumerate(yaml_sections, 1):
        print(f"  --- YAML Section {idx} (starts line {start}, {len(ylines)} lines) ---")
        print()
        for lineno, content in ylines:
            print(f"    {lineno:4d} | {content}")
        print()

print()
print(SEP)
print("6. DUPLICATE VMX SETTINGS CHECK")
print(SEP)

vmx_pattern = re.compile(r'([a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+)\s*=\s*')
vmx_settings = {}

skip_prefixes = [
    "system.", "net.", "io.", "microsoft.", "windows.",
    "console.", "threading.", "collections.",
    "text.", "runtime.", "security.", "diagnostics.",
    "environment.", "math.", "convert.",
]

for i, line in enumerate(lines, 1):
    for m in vmx_pattern.finditer(line):
        key = m.group(1).lower()
        if key.startswith("$"):
            continue
        if any(key.startswith(p) for p in skip_prefixes):
            continue
        vmx_settings.setdefault(key, []).append((i, line.rstrip()))

dupes = {k: v for k, v in vmx_settings.items() if len(v) > 1}

if not dupes:
    print(f"  No duplicate VMX settings found among {len(vmx_settings)} unique keys.")
else:
    print(f"  *** FOUND {len(dupes)} DUPLICATE VMX SETTING(S):")
    print()
    for key in sorted(dupes):
        occs = dupes[key]
        print(f"    Key: {key}  ({len(occs)} occurrences)")
        for lineno, text in occs:
            t = text.strip()
            if len(t) > 110:
                t = t[:107] + "..."
            print(f"      Line {lineno:4d}: {t}")
        print()

print(f"  Total unique VMX-style keys found: {len(vmx_settings)}")
if vmx_settings:
    print("  All VMX keys detected:")
    for key in sorted(vmx_settings):
        lns = [str(ln) for ln, _ in vmx_settings[key]]
        cnt_label = "lines" if len(lns) > 1 else "line "
        print(f"    {key:45s} ({cnt_label} {', '.join(lns)})")

print()
print(SEP)
print("SUMMARY")
print(SEP)
issues = []
if bal_curly != 0:
    issues.append(f"Curly brace imbalance: {bal_curly:+d}")
if bal_paren != 0:
    issues.append(f"Parenthesis imbalance: {bal_paren:+d}")
if hb != 0:
    issues.append(f"Here-string double-quote imbalance: {hb:+d}")
if sb != 0:
    issues.append(f"Here-string single-quote imbalance: {sb:+d}")
if dupes:
    issues.append(f"Duplicate VMX settings: {len(dupes)} key(s)")
if issues:
    print("  ISSUES FOUND:")
    for iss in issues:
        print(f"    - {iss}")
else:
    print("  No structural issues found. Script looks balanced.")
print(f"  Total lines: {len(lines)}")
print(SEP)
