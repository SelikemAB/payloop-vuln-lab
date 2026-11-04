#!/usr/bin/env bash
# Build build/fixed = baseline app + every patch applied in order (F1..F9).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build/fixed && mkdir -p build && cp -r app build/fixed
for p in patches/F*.patch; do
  patch -p1 -d build/fixed --quiet < "$p"
  echo "applied $(basename "$p")"
done
