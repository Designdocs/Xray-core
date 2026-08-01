#!/usr/bin/env bash
#
# Sync this fork with upstream (wyx2685/Xray-core).
#
# Does the mechanical part of the merge and stops as soon as human judgement
# is needed. Never pushes, never resolves a conflict, never edits ArtX code.
#
#   ./scripts/sync-upstream.sh check    report what is waiting upstream
#   ./scripts/sync-upstream.sh merge    back up, merge, build, vet, test
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# This repo has a main/ directory, so a bare "main" is ambiguous to git and
# some commands fail with "fatal: ambiguous argument". Always use full refs.
BRANCH_REF="refs/heads/main"
UPSTREAM_REF="refs/remotes/upstream/main"

# Packages carrying this fork's code or its core hook points. decoyfallback is
# here because it owns the origin validation and bounded transport that
# proxy/artx now shares, so a regression there reaches both features.
ARTX_PACKAGES=(./proxy/artx/... ./common/session/... ./proxy/freedom/... ./transport/internet/decoyfallback/...)

# infra/conf holds the ArtX config loader, but its TestGeodataConfig needs
# resources/geoip.dat, which is not in the tree. Run only the ArtX cases there.
ARTX_CONF_PACKAGE=./infra/conf/
ARTX_CONF_RUN='ArtX'

info() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mSTOP: %s\033[0m\n' "$*" >&2; exit 1; }

require_clean_tree() {
  if [[ -n "$(git status --porcelain)" ]]; then
    git status --short
    fail "working tree is dirty. Commit or stash first — a merge here would mix uncommitted work into conflict resolution."
  fi
}

behind_count() {
  git rev-list --count "HEAD..$UPSTREAM_REF"
}

report_pending() {
  git fetch upstream --quiet
  local behind ahead
  behind="$(behind_count)"
  ahead="$(git rev-list --count "$UPSTREAM_REF..HEAD")"

  info "upstream status"
  printf 'branch:   %s\n' "$(git rev-parse --abbrev-ref HEAD)"
  printf 'behind:   %s commits\n' "$behind"
  printf 'ahead:    %s commits (our ArtX work)\n' "$ahead"

  info "release commits waiting (upstream publishes no tags, only these)"
  git log --oneline "HEAD..$UPSTREAM_REF" --grep='^Xray-core v' || true

  info "files we touch that upstream also changed (conflict candidates)"
  comm -12 \
    <(git diff --name-only "$UPSTREAM_REF...HEAD" | sort) \
    <(git log --format="" --name-only "HEAD..$UPSTREAM_REF" | sort -u) \
    || true
}

cmd_check() {
  report_pending
  info "done — nothing was modified"
}

cmd_merge() {
  require_clean_tree
  report_pending
  local behind
  behind="$(behind_count)"
  if [[ "$behind" == "0" ]]; then
    info "already up to date with upstream"
    return 0
  fi

  local backup="backup/pre-upstream-sync-$(date +%Y%m%d-%H%M%S)"
  git tag "$backup"
  info "backup tag created: $backup"
  echo "roll back at any point with: git reset --hard $backup"

  info "merging $UPSTREAM_REF"
  if ! git merge upstream/main --no-edit; then
    info "conflicts — resolve these, then run: git commit"
    git diff --name-only --diff-filter=U
    fail "merge stopped for manual resolution. Re-run the verify step afterwards."
  fi

  cmd_verify
}

cmd_verify() {
  info "gofmt (our files only; upstream ships some unformatted files)"
  local unformatted
  unformatted="$(git diff --name-only "$UPSTREAM_REF...HEAD" -- '*.go' | xargs -r gofmt -l || true)"
  [[ -z "$unformatted" ]] || fail "gofmt needed:\n$unformatted"

  info "go build ./..."
  go build ./... || fail "build failed. Upstream API changes are the usual cause — check what it renamed or removed before touching ArtX code."

  info "go vet"
  go vet "${ARTX_PACKAGES[@]}" "$ARTX_CONF_PACKAGE" || true

  info "go test -race"
  go test -race "${ARTX_PACKAGES[@]}" || fail "tests failed."
  go test -race "$ARTX_CONF_PACKAGE" -run "$ARTX_CONF_RUN" || fail "ArtX config tests failed."

  info "core sync verified"
  cat <<'NEXT'
Next, propagate to N2X (it pins this repo by pseudo-version):

  ./scripts/bump-n2x-pin.sh

Then review the merge before pushing:

  git show --stat HEAD
  git push origin HEAD
NEXT
}

case "${1:-check}" in
  check)  cmd_check  ;;
  merge)  cmd_merge  ;;
  verify) cmd_verify ;;
  *) fail "usage: $0 [check|merge|verify]" ;;
esac
