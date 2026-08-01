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

## Procedure

```bash
./scripts/sync-upstream.sh check     # what is waiting
./scripts/sync-upstream.sh merge     # back up, merge, build, vet, test
git push origin HEAD                 # only after you have read the merge
./scripts/bump-n2x-pin.sh            # propagate to N2X, build and test it
```

`merge` stops at the first conflict and prints the files. Resolve, `git
commit`, then `./scripts/sync-upstream.sh verify`.

Neither script commits or pushes. Both refuse to guess.

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
