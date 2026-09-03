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

### splithttp: XmuxConfig copied by value, lock and all

| | |
|---|---|
| Ours | `fix(upstream): stop copying XmuxConfig by value` (find it with `git log --grep`) |
| Files | `transport/internet/splithttp/dialer.go`, `transport/internet/splithttp/mux.go`, `transport/internet/splithttp/mux_test.go` |
| Tests | `mux_test.go` (upstream's own, adjusted to the pointer signature) |
| Reported upstream | **No.** Deliberate — we are not opening a PR. |

`XmuxConfig` is a generated protobuf message, so it embeds
`protoimpl.MessageState`, which contains a `sync.Mutex`. `getHTTPClient`
dereferenced `transportConfig.Xmux` into a local and handed that copy to
`NewXmuxManager`, which stored another copy in the manager — copying the mutex
and the message's internal state twice per dial. `go vet` flags all four sites:

```
dialer.go:71: assignment copies lock value to xmuxConfig
mux.go:52:    NewXmuxManager passes lock by value
```

`NewXmuxManager` now takes `*XmuxConfig` and substitutes an empty config when
the caller passes nil, which is what the old value dance was for.

**Check at each sync:**

```bash
git log --oneline HEAD..upstream/main -- \
  transport/internet/splithttp/mux.go
```

Upstream fixing this means `NewXmuxManager` takes a pointer there too — take
theirs and delete this entry.

---

### infra/conf: unreachable code after the legacy reverse error

| | |
|---|---|
| Ours | `fix(upstream): drop unreachable code after the legacy reverse error` (find it with `git log --grep`) |
| Files | `infra/conf/xray.go` |
| Tests | none — `go vet ./infra/conf/` is the check |
| Reported upstream | **No.** Deliberate — we are not opening a PR. |

Upstream turned `"legacy reverse"` into a `PrintRemovedFeatureError` by adding a
`return` in front of the old body and leaving the body in place, so
`go vet ./infra/conf/` reports `xray.go:614:3: unreachable code`. We deleted the
five dead lines.

**This one is a five line deletion in the file that conflicts most.**
`infra/conf/xray.go` also carries the ArtX registration, and the README's rule
applies: insertions merge forever, deletions are the bill. It buys nothing but a
clean `go vet`, so if upstream ever edits that region, **drop ours and take
theirs** rather than resolving the conflict. Upstream will almost certainly
delete the block itself once the removal has been out for a release or two.

---

### splithttp: WaitReadCloser publishes the body outside the Wait channel

| | |
|---|---|
| Ours | `044830c5` `fix(splithttp): repair two data races on the xhttp client path` |
| Files | `transport/internet/splithttp/client.go` |
| Tests | `waitreadcloser_test.go` (new file, keep either way) |
| Reported upstream | **No.** Deliberate — we are not opening a PR. |

Reproducible on a clean upstream checkout with `go test -race -run Test_maxUpload
./transport/internet/splithttp/`.

`WaitReadCloser.Read` checked the embedded `io.ReadCloser` before receiving on
`Wait`, which skipped the only happens-before edge that made `Set`'s write
visible. An interface value is two words, so a torn read there is a crash.
Introduced by `f7bd98b13` (RPRX, 2024-11-27). The same rewrite also fixed a leak
that is independent of scheduling: a body arriving after `Close` was closed *and*
published, so a reader could read a closed body.

**Why this one will conflict:** `client.go` is on the xhttp path, which is both
upstream's most active transport and the one our nodes lead with. Expect to
resolve this at most syncs. `rerere` is enabled, so the second and later
resolutions of the same shape replay automatically.

**Check at each sync:**

```bash
git log --oneline HEAD..upstream/main -- \
  transport/internet/splithttp/client.go
```

Nothing listed means upstream has not touched the file and the patch stands as
is. If something is listed, read it before merging: upstream may have fixed the
same defect differently, in which case take theirs and delete this entry. Our
tests are the arbiter — they must still pass against upstream's version.

---

## Retired

### splithttp: uploadWriter counted a buffer it had already released

| | |
|---|---|
| Ours | `044830c5` (the `dialer.go` half) |
| Replaced by | `77f98eba` `XHTTP client: Fix a race condition and a data race (#6665)`, merged 2026-09-03 |
| Tests | `uploadwriter_test.go` — **kept**, and passes against upstream's version |

`uploadWriter.Write` read `buff.Len()` after `WriteMultiBuffer` had handed the
buffer to the pipe, where the poster goroutine can drain and release it. Besides
the race this undercounts and returns a short write. Introduced by `6fc0a40c2`
(风扇滑翔翼, 2025-08-16).

Upstream landed the identical fix — take the length before the write — with the
local named `n` instead of `length`. Ours was dropped at the 2026-09-03 sync in
favour of upstream's, per the rule above: keep upstream's version even when ours
reads better. `dialer.go` is now byte-identical to upstream again.

Upstream's commit also converts `DefaultDialerClient.closed` to an
`atomic.Bool`, a third defect we had not found. It merged without conflict.
