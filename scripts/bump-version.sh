#!/usr/bin/env bash
# Bump version across all crates and bindings.
# Usage: ./scripts/bump-version.sh 0.6.0
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.6.0"
  exit 1
fi

# Validate semver format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: '$VERSION' is not valid semver (expected X.Y.Z)"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "Bumping to $VERSION in $ROOT"

# 1. Cargo workspace (Cargo.toml)
sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$VERSION\"/" "$ROOT/Cargo.toml"
echo "  Cargo.toml (workspace)"

# 2. Node.js package.json
sed -i "s/\"version\": \"[0-9]*\.[0-9]*\.[0-9]*\"/\"version\": \"$VERSION\"/" "$ROOT/crates/node/package.json"
echo "  crates/node/package.json"

# 3. Python pyproject.toml
sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$VERSION\"/" "$ROOT/crates/python/pyproject.toml"
echo "  crates/python/pyproject.toml"

# 4. R DESCRIPTION
sed -i "s/^Version: [0-9]*\.[0-9]*\.[0-9]*/Version: $VERSION/" "$ROOT/crates/r/DESCRIPTION"
echo "  crates/r/DESCRIPTION"

# 5. R koon-r Cargo.toml
sed -i "s/^version = \"[0-9]*\.[0-9]*\.[0-9]*\"/version = \"$VERSION\"/" "$ROOT/crates/r/src/rust/Cargo.toml"
echo "  crates/r/src/rust/Cargo.toml"

echo ""
echo "Done. Verify with: git diff"
