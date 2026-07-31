#!/usr/bin/env bash
# Regenerate THIRD_PARTY_NOTICES from the modules actually linked into the
# released binaries. Scoped to ./cmd/switchboard on purpose: test-only
# dependencies are not redistributed, so they carry no attribution obligation.
#
# Uses only the Go toolchain — no license-scanning tool to install or trust.
#
# The module set is the UNION across every platform we release (see
# $platforms below, which must match .goreleaser.yaml's build matrix).
# `go list -deps` is GOOS-dependent — darwin pulls in howett.net/plist,
# linux pulls in github.com/prometheus/procfs — and both platforms happen to
# report the same *count*, so a per-host generation looks fine and is quietly
# wrong. Two things depend on the union:
#
#   1. GoReleaser puts this one committed file into *every* archive, so a
#      darwin-only file under-attributes the Linux binary (procfs is
#      genuinely linked into it).
#   2. CI regenerates and diffs this file on both ubuntu and macos runners.
#      That gate is only meaningful if the output is byte-identical
#      regardless of which OS runs the script.
#
# Hence also LC_ALL=C: `sort -u` is locale-sensitive, and the ordering of the
# uppercase module paths (AndreasBriese, BurntSushi, KimMachineGun,
# Masterminds) differs between the C and en_US.UTF-8 collations.
set -euo pipefail
export LC_ALL=C

out="${1:-THIRD_PARTY_NOTICES}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Must match .goreleaser.yaml: goos [darwin, linux] x goarch [amd64, arm64],
# CGO_ENABLED=0. (Architecture makes no difference to the module set today,
# but enumerating it costs nothing and keeps this honest if that changes.)
platforms="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64"

{
  echo "THIRD-PARTY SOFTWARE NOTICES"
  echo
  echo "Switchboard is distributed as a single statically-linked binary that"
  echo "includes the following third-party modules. Each module's license text"
  echo "is reproduced in full below, as those licenses require."
  echo
  echo "This file covers the union of the modules linked into every released"
  echo "platform (macOS and Linux, amd64 and arm64). A few modules are"
  echo "platform-specific — howett.net/plist is linked only into the macOS"
  echo "binary, github.com/prometheus/procfs only into the Linux one — so any"
  echo "single binary links a subset of what is listed here. Listing the union"
  echo "keeps one file correct for every archive."
  echo
  echo "The Go standard library is also statically compiled into this binary;"
  echo "it is covered separately by the Go project's own BSD-3-Clause license"
  echo "and is not listed below as a third-party module."
  echo
  echo "Regenerate with: make notices"
  echo
} >"$tmp"

all=""
for p in $platforms; do
  goos="${p%%/*}"
  goarch="${p##*/}"
  listed="$(CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go list -deps -f '{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}' \
    ./cmd/switchboard)"
  all="${all}${listed}"$'\n'
done

mods="$(printf '%s\n' "$all" | grep -v '^github.com/alsey89/switchboard' | grep -v '^$' | sort -u)"

count=0
missing=""
while read -r path version; do
  [ -n "$path" ] || continue
  dir="$(go list -m -f '{{.Dir}}' "$path" 2>/dev/null || true)"
  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    if [ -z "$missing" ]; then missing="$path"; else missing="$missing $path"; fi
    continue
  fi
  # Case-insensitive match on the known names at the module root first...
  lic=""
  for name in LICENSE LICENSE.txt LICENSE.md LICENCE COPYING COPYING.txt LICENSE-MIT; do
    match="$(find "$dir" -maxdepth 1 -iname "$name" 2>/dev/null | sort | head -n1)"
    if [ -n "$match" ]; then lic="$match"; break; fi
  done
  # ...failing that, a shallow search for anything license-shaped, preferring
  # the shortest (i.e. shallowest) path so a root-level file always wins over
  # one nested in a subpackage.
  if [ -z "$lic" ]; then
    best=""
    bestlen=0
    while IFS= read -r -d '' f; do
      len=${#f}
      if [ -z "$best" ] || [ "$len" -lt "$bestlen" ] || { [ "$len" -eq "$bestlen" ] && [ "$f" \< "$best" ]; }; then
        best="$f"
        bestlen=$len
      fi
    done < <(find "$dir" -maxdepth 2 \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'LICENCE*' \) -print0 2>/dev/null)
    lic="$best"
  fi
  if [ -z "$lic" ]; then
    if [ -z "$missing" ]; then missing="$path"; else missing="$missing $path"; fi
    continue
  fi
  {
    echo "================================================================================"
    echo "$path $version"
    echo "================================================================================"
    echo
    cat "$lic"
    echo
  } >>"$tmp"
  count=$((count + 1))
done <<<"$mods"

if [ -n "$missing" ]; then
  echo "ERROR: no license file found for: $missing" >&2
  echo "Vendor the license by hand or add its filename to the search list." >&2
  exit 1
fi

mv "$tmp" "$out"
trap - EXIT
echo "wrote $out ($count modules, union of: $platforms)"
