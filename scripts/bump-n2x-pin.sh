#!/usr/bin/env bash
#
# Point N2X's go.mod replace directive at the current commit of this fork.
#
# N2X consumes this repo as a Go library, not as a subprocess:
#   replace github.com/xtls/xray-core => github.com/Designdocs/Xray-core <pseudo>
# so nothing reaches the nodes until this pin moves.
#
# Requires the commit to be pushed already — the Go module proxy resolves it
# over the network.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N2X_DIR="${1:-$REPO_ROOT/../V2bX后端备份/N2X}"

# N2X needs these to compile at all; its Dockerfile uses the same set.
N2X_BUILD_ENV=(GOEXPERIMENT=jsonv2)
N2X_BUILD_TAGS="xray with_quic with_grpc with_utls with_acme"

info() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mSTOP: %s\033[0m\n' "$*" >&2; exit 1; }

[[ -d "$N2X_DIR" ]] || fail "N2X not found at $N2X_DIR (pass the path as \$1)"

cd "$REPO_ROOT"
COMMIT="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short=12 HEAD)"

git merge-base --is-ancestor "$COMMIT" "$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || echo HEAD)" 2>/dev/null \
  || info "note: HEAD may not be pushed yet — the module proxy needs it on the remote"

info "pinning N2X to $SHORT"
cd "$N2X_DIR"

if [[ -n "$(git status --porcelain go.mod go.sum)" ]]; then
  info "N2X go.mod/go.sum already have uncommitted changes — they will be built on, not replaced"
fi

VERSION="$(go list -m -f '{{.Version}}' "github.com/Designdocs/Xray-core@$COMMIT")" \
  || fail "could not resolve a pseudo-version. Is $SHORT pushed to origin?"

info "resolved: $VERSION"
go mod edit -replace "github.com/xtls/xray-core=github.com/Designdocs/Xray-core@$VERSION"
go mod tidy

info "building N2X"
env "${N2X_BUILD_ENV[@]}" go build -tags "$N2X_BUILD_TAGS" ./... \
  || fail "N2X build failed. An upstream API change is the usual cause — fix it the way upstream did rather than reverting the pin."

# -p 1 is not optional: N2X's suites bind fixed ports and watch the filesystem,
# so running packages in parallel fails on port contention and fsnotify rather
# than on anything the pin changed.
info "testing N2X"
env "${N2X_BUILD_ENV[@]}" go test -p 1 -tags "$N2X_BUILD_TAGS" ./... || fail "N2X tests failed."

# Name the commit the nodes will actually run. Upstream publishes no tags and
# a pseudo-version is not something anyone recognises six months later, so
# without this "which core is on my nodes" is answered by hash archaeology.
# Tagging happens only after the build and tests pass: a tag is a claim.
cd "$REPO_ROOT"
tag_date="$(date -u +%Y-%m-%d)"
tag="n2x/$tag_date"
attempt=2
while git rev-parse -q --verify "refs/tags/$tag" >/dev/null; do
  if [[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$COMMIT" ]]; then
    info "already tagged: $tag"
    tag=""
    break
  fi
  # Same day, different commit — a second bump, not a re-run.
  tag="n2x/$tag_date.$attempt"
  attempt=$((attempt + 1))
done
if [[ -n "$tag" ]]; then
  git tag -a "$tag" "$COMMIT" -m "N2X pinned $VERSION"
  info "tagged: $tag"
fi

info "N2X pinned to $VERSION and verified"
cat <<NEXT
Review and commit inside $N2X_DIR — this script never commits or pushes.

The tag is local too:

  git -C "$REPO_ROOT" push origin ${tag:-<tag>}
NEXT
