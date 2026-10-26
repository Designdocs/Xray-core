# REALITY compatibility copy

Source: XTLS/REALITY `83f621788ca88b83179810b12baa7ae518aacb83`
(`v0.0.0-20261014101318-83f621788ca8`, Go 1.27). `UPSTREAM.json`
records SHA-256 hashes of the original files. Original licenses are retained.
Self-imports use this package path so the source is part of the pinned Xray
module; builds do not depend on a local Go module replacement.

The upstream server requires a hybrid X25519MLKEM768 share even when a valid
X25519 share exists. This rejects sing-box REALITY clients, which intentionally
remove the hybrid share, before REALITY session authentication is attempted.

Local changes:

- Removed an unreachable tail after the unconditional return in the upstream
  server handshake, so this in-module copy passes `go vet`; runtime behavior
  is unchanged.
- `AllowLegacyX25519` defaults to false and is preserved by `Config.Clone`.
- `realityPeerPublicKey` accepts the authenticated X25519-only form only when
  compatibility is enabled. Duplicate, malformed and out-of-order supported
  shares are rejected. Existing hybrid clients retain their authentication key.
- The Xray adapter enables compatibility only for an explicit `minClientVer`
  of `0.0.0`, which N2X already sets to preserve its existing clients. All other
  configurations retain hybrid-only behavior. SNI, key, short ID, version,
  timestamp, TLS and VLESS user checks remain in place.

Do not replace this directory during an upstream merge without checking the
patch and running both legacy sing-box and modern Xray REALITY/Vision wire
regressions. A zero version floor alone is insufficient with upstream REALITY.
