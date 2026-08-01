# Upstream sync

This fork carries the ArtX protocol on top of `wyx2685/Xray-core`. These
scripts keep that divergence cheap.

## Cadence

**Sync on every upstream release.** Upstream publishes **no git tags** — a
release shows up only as a commit titled `Xray-core vXX.X.X` on
`upstream/main`, roughly every two to four weeks.

```bash
./scripts/sync-upstream.sh check
```

Run that when you sit down to ArtX work. If it lists a release commit, sync
before writing new code.

Do not let this slide. The 2026-07-31 sync had accumulated 76 upstream
commits; only two things broke, but that was luck riding on how isolated ArtX
is, not on the merge being safe at that size.

## The two-repo pipeline

```
Xray-core (this repo)  →  N2X  →  nodes
```

N2X consumes this repo as a **Go library**, pinned by pseudo-version:

```
replace github.com/xtls/xray-core => github.com/Designdocs/Xray-core v0.0.0-<utc>-<sha12>
```

**Nothing reaches the nodes until that pin moves.** Merging upstream here and
stopping is a half-done sync.

That pin is also why this repo has one rule with no exceptions:

> **Never rebase `main`. Never force-push it.**

The pin is a commit hash, and N2X's `go.sum` records it. Rebasing orphans
every commit that has ever been pinned, and once GitHub garbage collects them
no older N2X version can be built again — there is no rolling back to the core
the nodes ran three months ago. The patch-queue model, where a fork rebases its
patches onto upstream to keep a clean diff, is the obvious idea here and it is
the one that breaks this. Merge instead, always.

`bump-n2x-pin.sh` tags each pinned commit `n2x/<date>`, because a
pseudo-version is not something anyone recognises later. To find out what a
node is running, read the pin in N2X's `go.mod` and look up the tag.

## Branch model

```
main            integration branch — always mergeable, never rebased
 ├─ feat/…      new protocols and features
 └─ fix/…       bug fixes
```

`main` carries the work; upstream merges land **on `main`** via
`sync-upstream.sh merge`, never on a feature branch. A feature branch that
lives more than a few days should merge `main` into itself periodically — again
merge, not rebase, since anything already pushed may have been pinned.

Work on a branch rather than directly on `main` for one concrete reason: the
history already contains `chore(artx): checkpoint rejected profile v2
experiment` and `chore(artx): checkpoint wire v3 h2 experiment`. Wire went
through four iterations before v4 stuck. Experiments are normal here, and they
should die with their branch instead of settling into the trunk.

`main` does not have to be perfect, because **the pin is the release gate**, not
the branch. A rough commit on `main` reaches nobody until `bump-n2x-pin.sh`
builds and tests N2X against it. Use that freedom to integrate early; do not use
it to skip `verify`.

## Two kinds of drift

Divergence from upstream comes in two kinds and they need opposite treatment.

| | Examples | Lifetime |
|---|---|---|
| **Feature hooks** | `proxy/artx/`, decoy fallback, the `freedom.go` readiness hook | permanent |
| **Upstream bug fixes** | the splithttp data races | **until upstream fixes it** |

The second kind rots if it is not tracked: a diverging fix in a file upstream
keeps editing, whose reason nobody remembers. Prefix those commits
`fix(upstream): …` and record them in
[upstream-patches.md](./upstream-patches.md). `sync-upstream.sh check` prints
the ledger so the question gets asked before the merge, not after.

Adding a whole protocol costs **two upstream lines** — one registration in
`infra/conf/xray.go`, one import in `main/distro/all/all.go`. If a new protocol
costs more than that, the design is reaching into core when it should be
appending to it.

## Procedure

```bash
./scripts/sync-upstream.sh check     # what is waiting, and what patches we carry
./scripts/sync-upstream.sh merge     # back up, merge, build, vet, test
git push origin HEAD                 # only after you have read the merge
./scripts/bump-n2x-pin.sh            # propagate to N2X, build, test, tag
git push origin n2x/<date>           # the tag is local until you push it
```

`merge` stops at the first conflict and prints the files. Resolve, `git
commit`, then `./scripts/sync-upstream.sh verify`.

Neither script commits or pushes. Both refuse to guess.

**`rerere` is enabled on this clone.** Git records how you resolve a conflict
and replays it the next time the same conflict shape appears, which is the
normal case for a fork that merges the same upstream files release after
release. It replays into the working tree but leaves the result unstaged on
purpose — read it before you `git add`. A clone made elsewhere needs it turned
on again:

```bash
git config rerere.enabled true
```

## Keep the divergence additive

ArtX is cheap to maintain because it is almost entirely **new files**. The
whole `proxy/artx/` tree has never conflicted. Everything that has ever
conflicted is a line we changed inside a file upstream also edits.

When you need a hook in core, **append, never restructure**. Extracting an
upstream block into a helper reads better and costs a conflict every release.
The readiness hook in `proxy/freedom/freedom.go` is the reference shape: one
appended call, upstream's own code untouched, invariant stated in a comment.

Check the cost of any core edit with:

```bash
git diff --numstat upstream/main -- <file>
```

Insertions with zero deletions merge forever. Deletions are the bill.

## Known hazards

- **`main` is ambiguous.** This repo has a `main/` directory, so `git log
  main` fails with *ambiguous argument*. Use `refs/heads/main`.
- **Commit before merging.** A dirty tree mixes unfinished work into conflict
  resolution. `merge` refuses to run on one.
- **`common/session/context.go` is the recurring conflict.** Both sides append
  `ctx.SessionKey` constants and collide on the next free number. When it
  conflicts, keep upstream's numbering and move the ArtX key.
- **Upstream removes APIs on purpose.** v26.7.11 deleted
  `shadowsocks.CipherType_NONE` to forbid unencrypted Shadowsocks. Follow the
  intent; do not re-add what upstream removed for security.
- **N2X needs its build flags.** `GOEXPERIMENT=jsonv2` plus
  `-tags "xray with_quic with_grpc with_utls with_acme"`. A plain `go build`
  fails on `encoding/json/v2` and tells you nothing useful.
- **`go test ./...` cannot pass here.** `TestGeodataConfig` needs
  `resources/geoip.dat`, which is not in the tree. `verify` runs the ArtX
  cases in `infra/conf` by name instead.
