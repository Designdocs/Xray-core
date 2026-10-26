package reality

import "crypto/mlkem"

// realityPeerPublicKey keeps the upstream hybrid-first ordering and rejects
// duplicate or malformed supported shares. Compatibility only permits the old
// X25519-only form; REALITY authentication and all validation still follow.
func realityPeerPublicKey(shares []keyShare, allowLegacy bool) []byte {
	var classical, hybrid []byte
	for _, share := range shares {
		switch share.group {
		case X25519MLKEM768:
			if len(share.data) != mlkem.EncapsulationKeySize768+32 || hybrid != nil || classical != nil {
				return nil
			}
			hybrid = share.data[mlkem.EncapsulationKeySize768:]
		case X25519:
			if len(share.data) != 32 || classical != nil {
				return nil
			}
			classical = share.data
		}
	}
	if hybrid == nil && !allowLegacy {
		return nil
	}
	if classical != nil {
		return classical
	}
	return hybrid
}
