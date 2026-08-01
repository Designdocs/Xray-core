package internet

import (
	"net/http"

	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

// ServeDecoyOrNotFound answers a request that a transport refused, serving the
// configured decoy site instead of an empty 404, and the 404 itself when no
// decoy is configured.
//
// It lives in this package, rather than being called as decoyfallback directly
// from the hubs, purely to keep the diff against upstream to the rejection
// lines themselves. Every hub that needs it already imports this package for
// IsValidHTTPHost on the line above the rejection, so the call sites add no
// import. That matters most in splithttp/hub.go, whose import block upstream
// has grown three times in 2026 alone and which would conflict on nearly every
// sync. See scripts/decoy-transport-fallback.md.
func ServeDecoyOrNotFound(writer http.ResponseWriter, request *http.Request) {
	decoyfallback.ServeOrNotFound(writer, request)
}
