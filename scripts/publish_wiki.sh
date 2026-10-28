#!/usr/bin/env bash
# Publish docs/wiki/ to the GitHub wiki (https://github.com/<owner>/<repo>/wiki).
#
# The wiki is a separate git repository (<repo>.wiki.git). GitHub creates it
# only after the first page exists, so create any page once in the web UI first.
#
# Usage:
#   scripts/publish_wiki.sh            # publish
#   scripts/publish_wiki.sh --dry-run  # show what would change, push nothing
#
# docs/wiki/ is the source of truth: wiki pages that no longer exist there are
# removed, and pages edited directly on GitHub are overwritten.
set -euo pipefail

DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 64 ;;
esac

ROOT="$(git rev-parse --show-toplevel)"
SRC="$ROOT/docs/wiki"
[ -d "$SRC" ] || { echo "error: $SRC not found" >&2; exit 1; }

ORIGIN="$(git -C "$ROOT" remote get-url origin)"
WIKI_URL="${ORIGIN%.git}.wiki.git"
SOURCE_REV="$(git -C "$ROOT" rev-parse --short HEAD)"

if [ -n "$(git -C "$ROOT" status --porcelain -- docs/wiki)" ]; then
  echo "warning: docs/wiki has uncommitted changes; publishing the working tree" >&2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Cloning $WIKI_URL"
if ! git clone --quiet --depth 1 "$WIKI_URL" "$WORK/wiki"; then
  echo "error: could not clone the wiki. Create the first page in the GitHub web UI" >&2
  echo "       (Wiki tab -> Create the first page -> Save), then run this again." >&2
  exit 1
fi

# Mirror: drop pages that were removed from docs/wiki, then copy everything.
# README.md describes the folder in the main repo and isn't a wiki page.
find "$WORK/wiki" -maxdepth 1 -name '*.md' -delete
find "$SRC" -maxdepth 1 -name '*.md' ! -name 'README.md' -exec cp {} "$WORK/wiki/" \;

cd "$WORK/wiki"
git add -A
if git diff --cached --quiet; then
  echo "Wiki is already up to date."
  exit 0
fi

git diff --cached --stat
if [ "$DRY_RUN" -eq 1 ]; then
  echo "Dry run: nothing pushed."
  exit 0
fi

git commit --quiet -m "Publish wiki from docs/wiki at $SOURCE_REV"
git push --quiet origin HEAD
echo "Published to $WIKI_URL"
