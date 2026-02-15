#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.1.0"
  exit 1
fi

VERSION="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Validate semver format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Error: version must be in semver format (e.g. 1.2.3)"
  exit 1
fi

echo "Bumping version to $VERSION..."

# Update pyproject.toml
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$REPO_ROOT/pyproject.toml"
rm -f "$REPO_ROOT/pyproject.toml.bak"

# Update npm/package.json
cd "$REPO_ROOT/npm"
npm version "$VERSION" --no-git-tag-version --allow-same-version

# Commit and tag
cd "$REPO_ROOT"
git add pyproject.toml npm/package.json
git commit -m "chore: bump version to $VERSION"
git tag "v$VERSION"

echo ""
echo "Done! Version bumped to $VERSION and tagged v$VERSION."
echo "Run 'git push origin main --tags' to trigger the release workflow."
