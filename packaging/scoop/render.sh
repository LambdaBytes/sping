#!/usr/bin/env bash
# Renders the Scoop manifest of a published release into <out dir>/sping.json
# and checks it (check.py). The hash is the Windows asset's line in that
# release's SHA256SUMS: the caller has verified the asset against it.
#
#   render.sh <owner/repo> <X.Y.Z> <SHA256SUMS> <out dir>
#
# The asset is downloaded as sping.exe (the "#/sping.exe" URL fragment), so
# `bin` stays the same from one version to the next.
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: render.sh <owner/repo> <X.Y.Z> <SHA256SUMS> <out dir>" >&2
  exit 2
fi
repo="$1" version="$2" sums="$3" out="$4"
here="$(cd "$(dirname "$0")" && pwd)"

[[ "$repo" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || { echo "not a repository: $repo" >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a version: $version" >&2; exit 2; }

asset="sping-v$version-windows-x86_64.exe"
sha="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$sums")"
# Two lines for the asset would leave a newline in $sha and fail here too.
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "$asset: not exactly one SHA-256 in $sums" >&2; exit 1; }

mkdir -p "$out"
sed -e "s|@REPOSITORY@|$repo|g" -e "s|@VERSION@|$version|g" -e "s|@SHA256@|$sha|g" \
  "$here/sping.json" > "$out/sping.json"
python3 -I "$here/check.py" "$out/sping.json" "$repo" "$version" "$sha"
