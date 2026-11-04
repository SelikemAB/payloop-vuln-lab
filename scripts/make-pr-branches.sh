#!/usr/bin/env bash
# Turn the patches into a reviewable Git history: one branch + commit per finding, as PR-style changes.
# Run once in a fresh clone of YOUR repo. Commits are authored by you (git config user.name/email).
set -euo pipefail
cd "$(dirname "$0")/.."
git rev-parse --git-dir >/dev/null 2>&1 || { echo "run 'git init' and commit the baseline first"; exit 1; }
base=$(git rev-parse --abbrev-ref HEAD)
for p in patches/F*.patch; do
  id=$(basename "$p" | cut -d- -f1)               # F1
  slug=$(basename "$p" .patch | cut -d- -f2-)     # sql-injection
  lid=$(printf '%s' "$id" | tr 'A-Z' 'a-z')       # f1 (portable; avoids bash 4 ${id,,})
  title=$(sed -n '1s/^# //p' "pull-requests/${id}-${slug}.md")
  git checkout -q -b "fix/${lid}-${slug}" "$base"
  patch -p1 -d app --quiet < "$p"
  git add -A app
  git commit -q -m "$title" -m "See pull-requests/${id}-${slug}.md for root cause, verification and detection coverage."
  echo "created fix/${lid}-${slug}"
done
git checkout -q "$base"
echo "Open one PR per branch and paste the matching pull-requests/*.md as the description."
