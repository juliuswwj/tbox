package app

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/juliuswwj/tbox/internal/control"
)

// AdminWhitelistRequest sets a domain's source-IP allow list.
type AdminWhitelistRequest struct {
	Domain string   `json:"domain"`
	Allow  []string `json:"allow"`
}

// AdminWhitelistEntry is one domain's current allow list.
type AdminWhitelistEntry struct {
	Domain string   `json:"domain"`
	Allow  []string `json:"allow"`
}

// serveAdmin runs the local admin HTTP API used by `tbox whitelist`.
//
//	GET  /whitelist            -> list all domains and allow lists
//	POST /whitelist {domain,allow} -> replace a domain's allow list
func serveAdmin(ln net.Listener, cc *control.Client, logger *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var out []AdminWhitelistEntry
			for _, d := range cc.Domains() {
				allow, _ := cc.Whitelist(d)
				out = append(out, AdminWhitelistEntry{Domain: d, Allow: allow})
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPost:
			var req AdminWhitelistRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := cc.UpdateWhitelist(req.Domain, req.Allow); err != nil {
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
