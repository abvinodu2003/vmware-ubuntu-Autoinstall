#!/usr/bin/env python3
import re, sys, os

SCRIPT_PATH = os.path.join("C:\\", "Users", "OPTIMUS PRIME", "Downloads", "ubuntu-powershell-vm", "Build-UbuntuAutoinstallVM15.ps1")

def read_file(path):
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    sys.exit("ERROR: Cannot decode file.")

def find_herestrings(text):
    open_pat = re.compile(r'@"[ \t]*\r?\n')
    close_pat = re.compile(r'^\s*"@', re.MULTILINE)
    opens = list(open_pat.finditer(text))
    closes = list(close_pat.finditer(text))
    return opens, closes

def extract_yaml_herestring(text):
    open_pat = re.compile(r'@"[ \t]*\r?\n')
    close_pat = re.compile(r'^\s*"@', re.MULTILINE)
    opens = list(open_pat.finditer(text))
    closes = list(close_pat.finditer(text))
    pairs = []
    ci = 0
    for o in opens:
        while ci < len(closes) and closes[ci].start() < o.end():
            ci += 1
        if ci < len(closes):
            content = text[o.end():closes[ci].start()]
            pairs.append(content)
            ci += 1
    for content in pairs:
        if "#cloud-config" in content:
            return content
    return None

def extract_late_commands(yaml_text):
    lines = yaml_text.splitlines()
    in_late = False
    late_lines = []
    late_indent = None
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("late-commands:"):
            in_late = True
            late_lines.append(line)
            continue
        if in_late:
            if not stripped:
                late_lines.append(line)
                continue
            current_indent = len(line) - len(stripped)
            if late_indent is None:
                late_indent = current_indent
            if current_indent < late_indent and not stripped.startswith("#"):
                break
            late_lines.append(line)
    return "\n".join(late_lines) if late_lines else None

def find_suspects(text):
    suspects = []
    single = re.compile(r'(?<!`)(\$[a-z])\b')
    bash_env = re.compile(r'(?<!`)(\$(?:USER|HOME|SHELL|PATH|PWD|HOSTNAME|LANG|TERM|DISPLAY|XDG_[A-Z_]+|SUDO_[A-Z_]+|DEBIAN_FRONTEND|DBUS_[A-Z_]+))\b')
    braced = re.compile(r'(?<!`)(\$\{[^}]+\})')
    parens = re.compile(r'(?<!`)(\$\([^)]+\))')
    lines_list = text.splitlines()
    for i, line in enumerate(lines_list, 1):
        for m in single.finditer(line):
            suspects.append((i, m.group(1), line.strip(), "single-letter var (likely bash)"))
        for m in bash_env.finditer(line):
            suspects.append((i, m.group(1), line.strip(), "common bash/env variable"))
        for m in braced.finditer(line):
            suspects.append((i, m.group(1), line.strip(), "braced variable ${...}"))
        for m in parens.finditer(line):
            suspects.append((i, m.group(1), line.strip(), "command substitution $(...)"))
    return suspects

def main():
    text = read_file(SCRIPT_PATH)
    all_lines = text.splitlines()
    sep = "=" * 78
    dash = "-" * 78

    print(sep)
    print("  POWERSHELL SCRIPT VALIDATION REPORT")
    print(sep)

    print(f"\n[1] TOTAL LINES: {len(all_lines)}")

    ob = text.count("{")
    cb = text.count("}")
    bal = ob - cb
    st = "BALANCED" if bal == 0 else f"UNBALANCED (diff={bal:+d})"
    print(f"\n[2] CURLY BRACES")
    print(f"    Open  : {ob}")
    print(f"    Close : {cb}")
    print(f"    Status: {st}")

    op = text.count("(")
    cp = text.count(")")
    bal = op - cp
    st = "BALANCED" if bal == 0 else f"UNBALANCED (diff={bal:+d})"
    print(f"\n[3] PARENTHESES")
    print(f"    Open  : {op}")
    print(f"    Close : {cp}")
    print(f"    Status: {st}")

    hs_o, hs_c = find_herestrings(text)
    bal = len(hs_o) - len(hs_c)
    st = "BALANCED" if bal == 0 else f"UNBALANCED (diff={bal:+d})"
    print(f"\n[4] HERE-STRINGS @\"...\"@")
    print(f"    Open  @\" : {len(hs_o)}")
    print(f"    Close \"@ : {len(hs_c)}")
    print(f"    Status   : {st}")

    print(f"\n[5] YAML late-commands SECTION")
    print(dash)
    yaml_text = extract_yaml_herestring(text)
    late_cmds = None
    if yaml_text is None:
        print("    ERROR: No here-string with #cloud-config found")
    else:
        late_cmds = extract_late_commands(yaml_text)
        if late_cmds is None:
            print("    WARNING: No late-commands section found")
        else:
            for i, line in enumerate(late_cmds.splitlines(), 1):
                print(f"  {i:4d} | {line}")

    print(f"\n{sep}")
    print("[6] UNESCAPED VARIABLE CHECK IN late-commands")
    print(dash)
    if late_cmds:
        suspects = find_suspects(late_cmds)
        if not suspects:
            print("    No suspect unescaped variables found.")
        else:
            seen = set()
            unique = []
            for item in suspects:
                key = (item[0], item[1])
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            print(f"    Found {len(unique)} suspect unescaped variable(s):\n")
            for lno, var, ctx, reason in unique:
                ctx_short = ctx if len(ctx) <= 110 else ctx[:107] + "..."
                print(f"    Line {lno:3d} | Var: {var:<20s} | {reason}")
                print(f"            | {ctx_short}")
                print()
    else:
        print("    SKIPPED (no late-commands found)")

    print(sep)
    print("  END OF REPORT")
    print(sep)

if __name__ == "__main__":
    main()
