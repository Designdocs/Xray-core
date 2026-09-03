//go:build !linux

package artx

import "net"

// sampleSocketRTT has no portable equivalent outside Linux. Reporting an
// invalid sample makes the auto policy fall back to the node maximum scale.
func sampleSocketRTT(net.Conn) autoRTTSample { return autoRTTSample{} }
