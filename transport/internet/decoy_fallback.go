package internet

import (
	"net/http"

	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

// ServeDecoyOrNotFound answers a request that a transport refused, serving the
// configured decoy site instead of an empty 404, and the 404 itself when no
// decoy is configured.
//
// Retained for callers using the legacy process-wide environment API.
// WS/XHTTP listeners now construct independent decoyfallback.NewHandler values.
func ServeDecoyOrNotFound(writer http.ResponseWriter, request *http.Request) {
	decoyfallback.ServeOrNotFound(writer, request)
}
