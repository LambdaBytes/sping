"""Checks a rendered Scoop manifest (render.sh) before it is published.

    python3 -I check.py <sping.json> <owner/repo> <X.Y.Z> <sha256>

Scoop itself only runs on Windows: this checks what changes from one release
to the next (version, URLs, hash) and that nothing is left unfilled. The
template was tried with a real Scoop on Windows; a change to it is tried
there again.
"""

import json
import re
import sys


def problems(path, repo, version, sha):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    found = []
    if re.search(r"@[A-Z0-9_]+@", text):
        found.append("a placeholder is left")
    try:
        manifest = json.loads(text)
    except ValueError as e:
        return found + [f"not JSON: {e}"]

    def expect(key, want):
        got = manifest.get(key)
        if got != want:
            found.append(f"{key}: {got!r}, expected {want!r}")

    base = f"https://github.com/{repo}"
    asset = "sping-v{v}-windows-x86_64.exe#/sping.exe"
    expect("version", version)
    expect("homepage", base)
    expect("license", "MIT")
    expect(
        "architecture",
        {
            "64bit": {
                "url": f"{base}/releases/download/v{version}/"
                + asset.format(v=version),
                "hash": sha,
            }
        },
    )
    expect("bin", "sping.exe")
    expect("checkver", {"github": base})
    expect(
        "autoupdate",
        {
            "architecture": {
                "64bit": {
                    "url": f"{base}/releases/download/v$version/"
                    + asset.format(v="$version"),
                }
            }
        },
    )
    if not isinstance(manifest.get("description"), str) or not manifest["description"]:
        found.append("description: missing")
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
