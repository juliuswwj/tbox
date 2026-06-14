package app

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/juliuswwj/tbox/internal/control"
)

// AdminWhitelistRequest sets a service's source-IP allow list.
type AdminWhitelistRequest struct {
	Service string   `json:"service"`
	Allow   []string `json:"allow"`
}

// AdminWhitelistEntry is one service's current allow list.
type AdminWhitelistEntry struct {
	Service string   `json:"service"`
	Allow   []string `json:"allow"`
}

// serveAdmin runs the local admin HTTP API used by `tbox whitelist`.
//
//	GET  /whitelist                 -> list all services and allow lists
//	POST /whitelist {service,allow} -> replace a service's allow list
func serveAdmin(ln net.Listener, cc *control.Client, logger *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var out []AdminWhitelistEntry
			for _, id := range cc.Services() {
				allow, _ := cc.Whitelist(id)
				out = append(out, AdminWhitelistEntry{Service: id, Allow: allow})
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPost:
			var req AdminWhitelistRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := cc.UpdateWhitelist(req.Service, req.Allow); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Printf("admin server stopped: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
