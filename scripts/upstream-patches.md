# Patches we carry for upstream

Drift in this fork comes in two kinds, and they need opposite treatment.

**Feature hooks** are permanent. `proxy/artx/`, the decoy fallback, the
readiness hook in `proxy/freedom/freedom.go` — we maintain those forever, and
[README.md](./README.md) covers how to keep them cheap.

**Upstream bug fixes are temporary.** They exist only until upstream fixes the
same defect, and then ours must go. Left unattended they become the worst kind
of drift: a diverging fix in a file upstream keeps editing, that nobody
remembers the reason for. This file is the ledger that stops that.

## Rules

- Prefix the commit `fix(upstream): …` so the two kinds are separable in `git
  log`.
- Add an entry here in the same commit. An unlisted upstream patch is a bug.
- **Check every entry during each sync**, before running
  `./scripts/sync-upstream.sh merge`. If upstream fixed it, drop ours and
  delete the entry — keep upstream's version even when ours reads better.
- Keep the regression tests when you drop a patch. They are new files, they
  cost nothing, and they catch a reintroduction.

---

## Open

### splithttp: two data races on the xhttp client path

| | |
|---|---|
| Ours | `044830c5` `fix(splithttp): repair two data races on the xhttp client path` |
| Files | `transport/internet/splithttp/client.go`, `transport/internet/splithttp/dialer.go` |
| Tests | `waitreadcloser_test.go`, `uploadwriter_test.go` (new files, keep either way) |
| Reported upstream | **No.** Deliberate — we are not opening a PR. |

Two independent defects, both reproducible on a clean upstream checkout with
`go test -race -run Test_maxUpload ./transport/internet/splithttp/`.

1. `WaitReadCloser.Read` checked the embedded `io.ReadCloser` before receiving
   on `Wait`, which skipped the only happens-before edge that made `Set`'s
   write visible. An interface value is two words, so a torn read there is a
   crash. Introduced by `f7bd98b13` (RPRX, 2024-11-27). The same rewrite also
   fixed a leak that is independent of scheduling: a body arriving after
   `Close` was closed *and* published, so a reader could read a closed body.
2. `uploadWriter.Write` read `buff.Len()` after `WriteMultiBuffer` had handed
   the buffer to the pipe, where the poster goroutine can drain and release it.
   Besides the race this undercounts and returns a short write. Introduced by
   `6fc0a40c2` (风扇滑翔翼, 2025-08-16).

**Why this one will conflict:** `client.go` and `dialer.go` are on the xhttp
path, which is both upstream's most active transport and the one our nodes lead
with. Expect to resolve this at most syncs. `rerere` is enabled, so the second
and later resolutions of the same shape replay automatically.

**Check at each sync:**

```bash
git log --oneline HEAD..upstream/main -- \
  transport/internet/splithttp/client.go \
  transport/internet/splithttp/dialer.go
```

Nothing listed means upstream has not touched either file and the patch stands
as is. If something is listed, read it before merging: upstream may have fixed
the same defect differently, in which case take theirs and delete this entry.
Our tests are the arbiter — they must still pass against upstream's version.

---

## Retired

Nothing yet. When an entry retires, move it here with the upstream commit that
replaced it, so the next person can tell "upstream fixed this" from "we gave
up".
