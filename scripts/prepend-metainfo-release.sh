#!/usr/bin/env bash
# Prepend a fresh <release> block to metainfo.xml after the <releases> tag.
# Preserves all prior <release> entries verbatim. Replaces the previous
# sed-based approach that silently rewrote the first existing entry's
# attributes (see Sprint 24 retro / v0.3.1 incident).
#
# Usage: prepend-metainfo-release.sh <version> <date> <metainfo-path>

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <version> <date> <metainfo-path>" >&2
    exit 2
fi

V="$1"
D="$2"
F="$3"

if [ ! -f "$F" ]; then
    echo "error: metainfo file not found: $F" >&2
    exit 1
fi

if ! grep -q '^  <releases>$' "$F"; then
    echo "error: <releases> tag not found at expected indentation in $F" >&2
    exit 1
fi

awk -v V="$V" -v D="$D" '
  /^  <releases>$/ {
    print
    print "    <release version=\"" V "\" date=\"" D "\">"
    print "      <description>"
    print "        <p>TBD — fill in before commit</p>"
    print "      </description>"
    print "    </release>"
    next
  }
  { print }
' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
