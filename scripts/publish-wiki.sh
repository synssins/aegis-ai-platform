#!/usr/bin/env bash
# Mirror docs/ into the GitHub wiki of this repository. Docs in the repo are the source of truth; the wiki is a
# published copy. Requires push credentials for github.com (SSH key or token) on the machine that runs it.
# Usage: scripts/publish-wiki.sh [wiki-remote-url]   (default: <origin>.wiki.git)
set -euo pipefail; cd "$(dirname "$0")/.."
origin=$(git remote get-url origin); wiki="${1:-${origin%.git}.wiki.git}"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git clone -q "$wiki" "$tmp/wiki" 2>/dev/null || { mkdir -p "$tmp/wiki"; git -C "$tmp/wiki" init -q -b master; git -C "$tmp/wiki" remote add origin "$wiki"; }
rm -f "$tmp"/wiki/*.md
# page name = file name without extension; GitHub wiki links use [[Page]]
for f in docs/*.md docs/designs/*.md; do
  n=$(basename "$f" .md); cp "$f" "$tmp/wiki/$n.md"
done
cp README.md "$tmp/wiki/Home.md"
{
  echo "**Aegis AI Platform**"
  echo "- [[Home]]"
  for n in INSTALL CONFIG ARCHITECTURE SAFETY EVIDENCE HUB OPERATIONS TESTING SECURITY HARDWARE-REBAR ROADMAP CHANGELOG; do [ -f "$tmp/wiki/$n.md" ] && echo "- [[$n]]"; done
  echo "- Designs:"; for f in docs/designs/*.md; do echo "  - [[$(basename "$f" .md)]]"; done
} > "$tmp/wiki/_Sidebar.md"
# rewrite relative repo links (docs/X.md, X.md) into wiki links
sed -i -E 's#\]\((docs/)?([A-Za-z0-9_-]+)\.md\)#](\2)#g; s#`docs/([A-Za-z0-9_-]+)\.md`#[[\1]]#g' "$tmp"/wiki/*.md
git -C "$tmp/wiki" add -A
git -C "$tmp/wiki" -c user.name="Aegis Docs" -c user.email="docs@aegis.invalid" commit -q -m "Publish docs $(date -u +%F)" || { echo "wiki unchanged"; exit 0; }
git -C "$tmp/wiki" push -q origin HEAD:master && echo "wiki published to $wiki"
