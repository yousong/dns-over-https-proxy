/*
dns-over-https-proxy is a DNS proxy server to serve DNS via the Google
HTTPS DNS endpoint.

Usage:
go run dns_reverse_proxy.go -debug=true -address=127.0.0.1:8500 -log.level=debug
*/
package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/wrouesnel/go.log"
	"net/http"
)

var (
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")
	subnet  = flag.String("subnet", "", "edns-subnet-client argument to pass")

	defaultServer = flag.String("default", "https://dns.google.com/resolve",
		"DNS-over-HTTPS service endpoint")

	debug = flag.Bool("debug", false, "Verbose debugging")
)

// Rough translation of the Google DNS over HTTP API
type DNSResponseJson struct {
	Status             int32         `json:"Status,omitempty"`
	TC                 bool          `json:"TC,omitempty"`
	RD                 bool          `json:"RD,omitempty"`
	RA                 bool          `json:"RA,omitempty"`
	AD                 bool          `json:"AD,omitempty"`
	CD                 bool          `json:"CD,omitempty"`
	Question           []DNSQuestion `json:"Question,omitempty"`
	Answer             []DNSRR       `json:"Answer,omitempty"`
	Authority          []DNSRR       `json:"Authority,omitempty"`
	Additional         []DNSRR       `json:"Additional,omitempty"`
	Edns_client_subnet string        `json:"edns_client_subnet,omitempty"`
	Comment            string        `json:"Comment,omitempty"`
}

type DNSQuestion struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
}

type DNSRR struct {
	Name string `json:"name,omitempty"`
	Type int32  `json:"type,omitempty"`
	TTL  int32  `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

// Initialize a new RRGeneric from a DNSRR
func NewRR(a DNSRR) dns.RR {
	rrhdr := dns.RR_Header{
		Name:     a.Name,
		Rrtype:   uint16(a.Type),
		Class:    dns.ClassINET,
		Ttl:      uint32(a.TTL),
		Rdlength: uint16(len(a.Data)),
	}
	str := rrhdr.String() + a.Data
	rr, _ := dns.NewRR(str)
	return rr
}

func main() {
	flag.Parse()
	if *defaultServer == "" {
		log.Fatal("-default is required")
	}

	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	proxy(*defaultServer, w, req)
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	httpreq, err := http.NewRequest(http.MethodGet, *defaultServer, nil)
	if err != nil {
		log.Errorln("Error setting up request:", err)
		dns.HandleFailed(w, req)
		return
	}

	qry := httpreq.URL.Query()
	qry.Add("name", req.Question[0].Name)
	qry.Add("type", fmt.Sprintf("%v", req.Question[0].Qtype))
	if len(*subnet) > 0 {
		qry.Add("edns_client_subnet", *subnet)
	}
	httpreq.URL.RawQuery = qry.Encode()

	if *debug {
		log.Debugln(httpreq.URL.String())
	}

	httpresp, err := http.DefaultClient.Do(httpreq)
	if err != nil {
		log.Errorln("Error sending DNS response:", err)
		dns.HandleFailed(w, req)
		return
	}
	defer httpresp.Body.Close()

	// Parse the JSON response
	dnsResp := new(DNSResponseJson)
	decoder := json.NewDecoder(httpresp.Body)
	err = decoder.Decode(&dnsResp)
	if err != nil {
		log.Errorln("Malformed JSON DNS response:", err)
		dns.HandleFailed(w, req)
		return
	}

	// Parse the google Questions to DNS RRs
	questions := []dns.Question{}
	for idx, c := range dnsResp.Question {
		questions = append(questions, dns.Question{
			Name:   c.Name,
			Qtype:  uint16(c.Type),
			Qclass: req.Question[idx].Qclass,
		})
	}

	// Parse google RRs to DNS RRs
	answers := []dns.RR{}
	for _, a := range dnsResp.Answer {
		answers = append(answers, NewRR(a))
	}

	// Parse google RRs to DNS RRs
	authorities := []dns.RR{}
	for _, ns := range dnsResp.Authority {
		authorities = append(authorities, NewRR(ns))
	}

	// Parse google RRs to DNS RRs
	extras := []dns.RR{}
	for _, extra := range dnsResp.Additional {
		authorities = append(authorities, NewRR(extra))
	}

	resp := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 req.Id,
			Response:           (dnsResp.Status == 0),
			Opcode:             dns.OpcodeQuery,
			Authoritative:      false,
			Truncated:          dnsResp.TC,
			RecursionDesired:   dnsResp.RD,
			RecursionAvailable: dnsResp.RA,
			//Zero: false,
			AuthenticatedData: dnsResp.AD,
			CheckingDisabled:  dnsResp.CD,
			Rcode:             int(dnsResp.Status),
		},
		Compress: req.Compress,
		Question: questions,
		Answer:   answers,
		Ns:       authorities,
		Extra:    extras,
	}

	// Write the response
	err = w.WriteMsg(&resp)
	if err != nil {
		log.Errorln("Error writing DNS response:", err)
	}
}
