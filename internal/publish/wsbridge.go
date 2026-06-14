package publish

import (
	"context"
	"net/http"

	"github.com/coder/websocket"

	"github.com/juliuswwj/tbox/internal/control"
	"github.com/juliuswwj/tbox/internal/tunnel"
)

// serveWS upgrades the request to a WebSocket and bridges its binary payload to
// a raw reverse stream toward the location owner's local TCP service.
func (h *Handler) serveWS(w http.ResponseWriter, r *http.Request, entry *control.RouteEntry) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Published endpoints are reached by arbitrary public clients; origin
		// enforcement is out of scope for the tunnel.
		InsecureSkipVerify: true,
	})
	if err != nil {
		// Accept already wrote an error response.
		return
	}

	stream, err := entry.OpenStream(tunnel.ModeTCP, entry.Upstream)
	if err != nil {
		h.logger.Printf("publish: ws %s open stream to %s: %v", r.Host, entry.Upstream, err)
		_ = c.Close(websocket.StatusInternalError, "upstream unavailable")
		return
	}

	// Detach from the request context so the bridge lives for the connection's
	// lifetime rather than being cancelled when ServeHTTP would otherwise return.
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	tunnel.Pipe(nc, stream)
}
