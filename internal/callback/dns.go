package callback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/event"
	"github.com/miekg/dns"
)

// DNSServer listens for DNS queries and records interactions for matching tokens.
type DNSServer struct {
	store     *Store
	broadcast chan<- any
	bindAddr  string
	port      int
	udp       *dns.Server
	tcp       *dns.Server
}

// NewDNSServer creates a DNS callback server.
func NewDNSServer(store *Store, broadcast chan<- any, bindAddr string, port int) *DNSServer {
	return &DNSServer{
		store:     store,
		broadcast: broadcast,
		bindAddr:  bindAddr,
		port:      port,
	}
}

// Start begins listening on UDP and TCP. It blocks until ctx is cancelled.
func (d *DNSServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", d.bindAddr, d.port)
	handler := dns.HandlerFunc(d.handleDNS)

	d.udp = &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	d.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)
	go func() { errCh <- d.udp.ListenAndServe() }()
	go func() { errCh <- d.tcp.ListenAndServe() }()

	go func() {
		<-ctx.Done()
		d.udp.Shutdown() //nolint:errcheck
		d.tcp.Shutdown() //nolint:errcheck
	}()

	return <-errCh
}

func (d *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	cfg, _ := d.store.GetConfig()
	domain := cfg.Domain
	responseIP := net.ParseIP(cfg.ResponseIP)
	if responseIP == nil {
		responseIP = net.ParseIP("127.0.0.1")
	}

	for _, q := range r.Question {
		qname := strings.TrimSuffix(q.Name, ".")

		// Try to correlate with a token
		token, err := Correlate(d.store, qname, domain)
		if err == nil {
			sourceIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

			id := make([]byte, 16)
			rand.Read(id) //nolint:errcheck
			interaction := &Interaction{
				ID:        hex.EncodeToString(id),
				TokenID:   token.ID,
				Token:     token.Token,
				Type:      "dns",
				SourceIP:  sourceIP,
				Timestamp: time.Now().UTC(),
				QueryName: qname,
				QueryType: dns.TypeToString[q.Qtype],
			}
			if err := d.store.RecordInteraction(interaction); err != nil {
				log.Printf("callback dns: record interaction: %v", err)
			}
			d.broadcast <- event.WSEvent{Type: "callback.interaction", Data: interaction}
		}

		// Respond with A record for A queries
		if q.Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   responseIP.To4(),
			})
		}
	}

	w.WriteMsg(msg) //nolint:errcheck
}
