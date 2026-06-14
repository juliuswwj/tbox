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
	Services []ServiceReg `json:"services,omitempty"`

	// update_whitelist
	Domain string   `json:"domain,omitempty"`
	Allow  []string `json:"allow,omitempty"`

	// ack
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
}

// ServiceReg is a single published service the client registers.
type ServiceReg struct {
	Domain  string   `json:"domain"`
	Mode    string   `json:"mode"` // http | ws
	CertPEM string   `json:"cert_pem"`
	KeyPEM  string   `json:"key_pem"`
	Allow   []string `json:"allow,omitempty"`

	// http mode
	Routes []RouteReg `json:"routes,omitempty"`

	// ws mode
	WSPath     string `json:"ws_path,omitempty"`
	WSUpstream string `json:"ws_upstream,omitempty"`
}

// RouteReg mirrors config.Route over the wire.
type RouteReg struct {
	Path            string            `json:"path"`
	Upstream        string            `json:"upstream"`
	StripPrefix     bool              `json:"strip_prefix,omitempty"`
	AddPrefix       string            `json:"add_prefix,omitempty"`
	SetHost         string            `json:"set_host,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

func ack(ok bool, errMsg string) Message {
	return Message{Type: TypeAck, OK: ok, Error: errMsg}
}
