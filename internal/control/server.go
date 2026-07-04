package control

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strings"

	"github.com/hashicorp/yamux"

	"github.com/juliuswwj/tbox/internal/tunnel"
)

// Server runs the control-plane listener on the VPS. It accepts carrier
// connections (delivered by the embedded sing-box via its direct outbound to
// the control address), authenticates each client, and maintains the registry.
type Server struct {
	reg          *Registry
	allowedUUIDs map[string]string // uuid -> client name
	hub          *TunHub           // optional L2 tunnel hub (nil = disabled)
	logger       *log.Logger
}

// NewServer creates a control server. clients maps uuid -> name. hub may be nil
// to disable the L2 tunnel data plane.
func NewServer(reg *Registry, clients map[string]string, hub *TunHub, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{reg: reg, allowedUUIDs: clients, hub: hub, logger: logger}
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleSession(conn)
	}
}

func (s *Server) handleSession(conn net.Conn) {
	sess, err := tunnel.Server(conn)
	if err != nil {
		_ = conn.Close()
		s.logger.Printf("control: yamux server: %v", err)
		return
	}
	defer func() {
		removed := s.reg.RemoveSession(sess)
		if len(removed) > 0 {
			s.logger.Printf("control: session closed, unpublished: %s", strings.Join(removed, ", "))
		}
		_ = sess.Close()
	}()

	control, err := sess.AcceptStream()
	if err != nil {
		s.logger.Printf("control: accept control stream: %v", err)
		return
	}

	// After auth, additional client-opened streams (the L2 tunnel data stream)
	// are accepted and dispatched here. The loop is gated on authed so the
	// client id is known before any data stream is wired into the hub.
	authed := make(chan string, 1)
	go s.acceptDataStreams(sess, authed)

	dec := json.NewDecoder(control)
	enc := json.NewEncoder(control)

	clientID := ""
	for {
		var msg Message
		if err := dec.Decode(&msg); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Printf("control: decode: %v", err)
			}
			return
		}

		if clientID == "" && msg.Type != TypeAuth {
			_ = enc.Encode(ack(false, "auth required first"))
			return
		}

		switch msg.Type {
		case TypeAuth:
			name, ok := s.allowedUUIDs[msg.UUID]
			if !ok {
				_ = enc.Encode(ack(false, "unknown client"))
				return
			}
			clientID = msg.UUID
			s.logger.Printf("control: client %q (%s) authenticated", name, shortID(clientID))
			select {
			case authed <- clientID:
			default:
			}
			_ = enc.Encode(ack(true, ""))

		case TypeRegister:
			if err := s.reg.Register(clientID, sess, msg.Certs, msg.Services); err != nil {
				_ = enc.Encode(ack(false, err.Error()))
				break
			}
			ids := make([]string, 0, len(msg.Services))
			for _, svc := range msg.Services {
				ids = append(ids, svc.ID())
			}
			s.logger.Printf("control: client %s registered %d cert(s), services: %s",
				shortID(clientID), len(msg.Certs), strings.Join(ids, ", "))
			_ = enc.Encode(ack(true, ""))

		case TypeUpdateWhitelist:
			if err := s.reg.UpdateWhitelist(clientID, msg.ServiceID, msg.Allow); err != nil {
				_ = enc.Encode(ack(false, err.Error()))
			} else {
				s.logger.Printf("control: client %s whitelist for %s -> %v", shortID(clientID), msg.ServiceID, msg.Allow)
				_ = enc.Encode(ack(true, ""))
			}

		case TypeHeartbeat:
			_ = enc.Encode(ack(true, ""))

		default:
			_ = enc.Encode(ack(false, "unknown message type"))
		}
	}
}

// acceptDataStreams waits for the client to authenticate, then accepts any
// further client-opened streams and dispatches them (currently only the L2
// tunnel data stream). It returns when the session closes.
func (s *Server) acceptDataStreams(sess *yamux.Session, authed <-chan string) {
	clientID, ok := <-authed
	if !ok {
		return
	}
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handleDataStream(clientID, stream)
	}
}

func (s *Server) handleDataStream(clientID string, stream net.Conn) {
	f, err := tunnel.ReadFrame(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	if f.Service != TunService || s.hub == nil {
		s.logger.Printf("control: client %s opened unexpected stream %q", shortID(clientID), f.Service)
		_ = stream.Close()
		return
	}
	s.hub.ServeClient(clientID, stream)
	_ = stream.Close()
}

func shortID(uuid string) string {
	if len(uuid) >= 8 {
		return uuid[:8]
	}
	return uuid
}
