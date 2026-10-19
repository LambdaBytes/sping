"""Checks the three rendered WinGet manifests (render.sh) together before
they are proposed to microsoft/winget-pkgs.

    python3 -I check.py <manifest dir> <owner/repo> <X.Y.Z> <sha256>

`winget validate` only runs on Windows: this checks what changes from one
release to the next (version, URLs, hash), that the three files agree with
each other and that nothing is left unfilled. The templates were validated and
installed with a real winget on Windows; a change to them is tried there
again, and winget-pkgs validates every pull request.

It reads the templates' own flat layout (`Key: value`, `Key:` followed by
`- item` lines, and installer entries indented under `Installers:`), not
arbitrary YAML: any other line is an error.
"""

import os
import re
import sys

IDENTIFIER = "LambdaBytes.Sping"
FILES = {
    f"{IDENTIFIER}.yaml": "version",
    f"{IDENTIFIER}.installer.yaml": "installer",
    f"{IDENTIFIER}.locale.en-US.yaml": "defaultLocale",
}
SCHEMA = re.compile(
    r"^# yaml-language-server: \$schema=https://aka\.ms/winget-manifest\.(\w+)\.([0-9.]+)\.schema\.json$"
)


KEY = r"([A-Za-z][A-Za-z0-9]*)"
VALUE = r"(\S(?:.*\S)?)"
PAIR = re.compile(rf"^{KEY}: {VALUE}$")
LIST = re.compile(rf"^{KEY}:$")
ITEM = re.compile(rf"^- {VALUE}$")
# An installer entry's next fields: exactly two spaces in.
ITEM_PAIR = re.compile(rf"^  {KEY}: {VALUE}$")


def parse(path):
    """The fields of one manifest, and the type and version its schema line names.

    A key given twice, at the top or within an entry, is an error, as it is
    for winget."""
    fields, schema, key, item = {}, None, None, None

    def put(where, k, v, n):
        if k in where:
            raise ValueError(f"line {n}: {k} given twice")
        where[k] = v

    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f.read().splitlines(), 1):
            if not line.strip():
                continue
            if line.startswith("#"):
                m = SCHEMA.match(line)
                if m:
                    schema = m.groups()
                continue
            if m := ITEM.match(line):
                if key is None:
                    raise ValueError(f"line {n}: a list item outside a list")
                if p := PAIR.match(m.group(1)):
                    item = {p.group(1): p.group(2)}
                    fields[key].append(item)
                else:
                    item = None
                    fields[key].append(m.group(1))
            elif (m := ITEM_PAIR.match(line)) and item is not None:
                put(item, m.group(1), m.group(2), n)
            elif m := LIST.match(line):
                key, item = m.group(1), None
                put(fields, key, [], n)
            elif m := PAIR.match(line):
                key, item = None, None
                put(fields, m.group(1), m.group(2), n)
            else:
                raise ValueError(f"line {n}: not in the templates' layout: {line!r}")
    return fields, schema


def problems(directory, repo, version, sha):
    found = []
    names = sorted(os.listdir(directory))
    if names != sorted(FILES):
        return [f"files {names}, expected {sorted(FILES)}"]
    base = f"https://github.com/{repo}"
    manifests = {}
    for name, kind in FILES.items():
        path = os.path.join(directory, name)
        with open(path, encoding="utf-8") as f:
            if re.search(r"@[A-Z0-9_]+@", f.read()):
                found.append(f"{name}: a placeholder is left")
        try:
            fields, schema = parse(path)
        except ValueError as e:
            found.append(f"{name}: {e}")
            continue
        manifests[kind] = fields

        def expect(key, want, fields=fields, name=name):
            got = fields.get(key)
            if got != want:
                found.append(f"{name}: {key} is {got!r}, expected {want!r}")

        expect("PackageIdentifier", IDENTIFIER)
        expect("PackageVersion", version)
        expect("ManifestType", kind)
        if schema != (kind, fields.get("ManifestVersion")):
            found.append(
                f"{name}: schema line {schema}, expected ({kind!r}, ManifestVersion)"
            )
        if kind == "installer":
            expect("InstallerType", "portable")
            expect("Commands", ["sping"])
            expect(
                "Installers",
                [
                    {
                        "Architecture": "x64",
                        "InstallerUrl": f"{base}/releases/download/v{version}/sping-v{version}-windows-x86_64.exe",
                        "InstallerSha256": sha.upper(),
                    }
                ],
            )
        elif kind == "defaultLocale":
            expect("PackageUrl", base)
            expect("PublisherUrl", f"https://github.com/{repo.split('/')[0]}")
            expect("LicenseUrl", f"{base}/blob/v{version}/LICENSE")
            expect("ReleaseNotesUrl", f"{base}/releases/tag/v{version}")
            for key in ("Publisher", "PackageName", "License", "ShortDescription"):
                if not isinstance(fields.get(key), str) or not fields[key]:
                    found.append(f"{name}: {key} is missing")
    if len(manifests) == len(FILES):
        versions = {kind: m.get("ManifestVersion") for kind, m in manifests.items()}
        if len(set(versions.values())) != 1:
            found.append(f"ManifestVersion differs between the files: {versions}")
        locale = manifests["defaultLocale"].get("PackageLocale")
        if manifests["version"].get("DefaultLocale") != locale or locale != "en-US":
            found.append(
                f"DefaultLocale {manifests['version'].get('DefaultLocale')!r}, PackageLocale {locale!r}: expected en-US in both"
            )
    return found


def main(argv):
    if len(argv) != 5:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    found = problems(*argv[1:])
    for p in found:
        print(f"{argv[1]}: {p}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
