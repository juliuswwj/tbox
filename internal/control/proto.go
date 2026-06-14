package control

// Control-plane wire protocol. Messages are JSON values streamed over the
// first yamux stream of a session (the "control stream"). The client sends a
// request and waits for an Ack before sending the next; the server replies to
// every request with an Ack.

// MsgType enumerates control message kinds.
type MsgType string

const (
	TypeAuth            MsgType = "auth"
	TypeRegister        MsgType = "register"
	TypeUpdateWhitelist MsgType = "update_whitelist"
	TypeHeartbeat       MsgType = "heartbeat"
	TypeAck             MsgType = "ack"
)

// Message is the single envelope used in both directions.
type Message struct {
	Type MsgType `json:"type"`

	// auth
	UUID string `json:"uuid,omitempty"`

	// register
	Certs    []CertReg    `json:"certs,omitempty"`
	Services []ServiceReg `json:"services,omitempty"`

	// update_whitelist
	ServiceID string   `json:"service_id,omitempty"`
	Allow     []string `json:"allow,omitempty"`

	// ack
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

// CertReg is a TLS certificate a client uploads. The covered names are read
// from the certificate itself.
type CertReg struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// ServiceReg is one published service registered by a client.
type ServiceReg struct {
	Mode     string   `json:"mode"` // http | ws | tcp
	Host     string   `json:"host"`
	Path     string   `json:"path,omitempty"` // http/ws only
	Upstream string   `json:"upstream"`
	Allow    []string `json:"allow,omitempty"`

	// http rewrite
	StripPrefix     bool              `json:"strip_prefix,omitempty"`
	AddPrefix       string            `json:"add_prefix,omitempty"`
	SetHost         string            `json:"set_host,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

// ID returns the canonical identifier for the service.
func (s ServiceReg) ID() string { return ServiceID(s.Mode, s.Host, s.Path) }

// ServiceID is the canonical URL-style identifier for a service.
func ServiceID(mode, host, path string) string {
	switch mode {
	case "tcp":
		return "tcp://" + host
	case "ws":
		return "wss://" + host + normPath(path)
	default:
		return "https://" + host + normPath(path)
	}
}

func normPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func ack(ok bool, errMsg string) Message {
	return Message{Type: TypeAck, OK: ok, Error: errMsg}
}
