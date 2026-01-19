// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key"to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none"disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of raw bytes that can be encoded in a DNS
// query name, given the domain suffix and encoding constraints.
//
// maxQnameLen is the maximum total QNAME length in wire format (0 = 253 per RFC 1035).
// maxNumLabels is the maximum number of data labels (0 = unlimited).
// Labels are always chunked at 63 bytes (DNS maximum label size).
func dnsNameCapacity(domain dns.Name, maxQnameLen int, maxNumLabels int) int {
	const labelLen = 63 // DNS maximum label size

	// Default to RFC 1035 maximum if not specified
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}

	// Calculate domain wire length (each label: 1 length byte + content)
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Available wire bytes for data labels (excluding null terminator which is part of 255 limit)
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return 0
	}

	// Each label requires len+1 bytes to encode (1 length byte + content).
	// So for N labels of max length L, we use N*(L+1) wire bytes to carry N*L encoded chars.
	// The encoded chars capacity is: availableWireBytes * L / (L + 1)
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	// If maxNumLabels is limited, cap the encoded capacity
	if maxNumLabels > 0 {
		maxEncoded := maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	// Base32 expands every 5 bytes to 8 chars.
	rawCapacity := encodedCapacity * 5 / 8
	return rawCapacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Debugf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Infof("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func run(pubkey []byte, domains []dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, maxQnameLen int, maxNumLabels int) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	// Calculate MTU overhead:
	// - ClientID: 2 bytes
	// - Data length prefix: 1 byte (only present for data packets, not polls)
	// Use the longest domain for conservative MTU calculation
	var longestDomain dns.Name
	for _, domain := range domains {
		if len(domain.String()) > len(longestDomain.String()) {
			longestDomain = domain
		}
	}
	const clientIDSize = 2 // Reduced ClientID size
	const dataLenSize = 1  // Data length prefix
	mtu := dnsNameCapacity(longestDomain, maxQnameLen, maxNumLabels) - clientIDSize - dataLenSize
	// KCP requires MTU >= 50 (see kcp.go SetMtu)
	const kcpMinMTU = 50
	if mtu < kcpMinMTU {
		return fmt.Errorf("domain with max-qname-len %d and max-num-labels %d leaves only %d bytes for payload (KCP minimum %d)", maxQnameLen, maxNumLabels, mtu, kcpMinMTU)
	}
	if maxNumLabels > 0 || maxQnameLen > 0 {
		log.Infof("effective MTU %d (max-qname-len %d, max-num-labels %d)", mtu, maxQnameLen, maxNumLabels)
	} else {
		log.Infof("effective MTU %d", mtu)
	}

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Debugf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Infof("begin session %08x", conn.GetConv())
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		return fmt.Errorf("failed to set KCP MTU to %d (KCP internal error)", mtu)
	}

	// Put a Noise channel on top of the KCP conn.
	log.Debugf("starting Noise handshake...")
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		log.Debugf("Noise handshake failed: %v", err)
		return err
	}
	log.Debugf("Noise handshake completed successfully")

	// Start a smux session on the Noise channel.
	log.Debugf("creating smux session...")
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		log.Debugf("smux session creation failed: %v", err)
		return fmt.Errorf("opening smux session: %v", err)
	}
	log.Debugf("smux session created successfully")
	defer sess.Close()

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv())
			if err != nil {
				log.Errorf("handle: %v", err)
			}
		}()
	}
}

var dialerControl func(network, address string, c syscall.RawConn) error = nil

func main() {
	var dohURL string
	var dotAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string
	var rpsLimit float64

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, " %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, "%s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.Float64Var(&rpsLimit, "rps", 0, "limit outgoing DNS queries to this many requests per second (0 = unlimited)")
	var maxQnameLen int
	var maxNumLabels int
	var udpWorkers int
	var udpSharedSocket bool
	var logLevel string
	flag.IntVar(&maxQnameLen, "max-qname-len", 0, "maximum total QNAME length in wire format (0 = 253 per RFC 1035)")
	flag.IntVar(&maxNumLabels, "max-num-labels", 0, "maximum number of data labels (0 = unlimited)")
	flag.IntVar(&udpWorkers, "udp-workers", 100, "number of concurrent UDP worker goroutines")
	flag.BoolVar(&udpSharedSocket, "udp-shared-socket", false, "use a single shared UDP socket instead of per-query sockets (disables source port randomization)")
	flag.StringVar(&logLevel, "log-level", "warning", "log level (debug, info, warning, error)")
	flag.Parse()

	// Configure logrus
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("invalid log level: %v", err)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	// Parse comma-separated domains (e.g., "d.example.com,c.example.org")
	domainsArg := flag.Arg(0)
	domainStrs := strings.Split(domainsArg, ",")
	var domains []dns.Name
	for _, domainStr := range domainStrs {
		domainStr = strings.TrimSpace(domainStr)
		if domainStr == "" {
			continue
		}
		domain, err := dns.ParseName(domainStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", domainStr, err)
			os.Exit(1)
		}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		fmt.Fprintf(os.Stderr, "at least one domain is required\n")
		os.Exit(1)
	}
	for _, domain := range domains {
		log.Infof("using domain: %s", domain)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Infof("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{dohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			var pconn net.PacketConn
			if udpSharedSocket {
				// Old behavior: single shared UDP socket
				lc := net.ListenConfig{
					Control: dialerControl,
				}
				pconn, err = lc.ListenPacket(context.Background(), "udp", ":0")
			} else {
				// New behavior: multiple workers with per-query sockets
				pconn, err = NewUDPPacketConn(addr, dialerControl, udpWorkers)
			}
			return addr, pconn, err
		}},
	} {
		if opt.s == "" {
			continue
		}
		if pconn != nil {
			fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
			os.Exit(1)
		}
		var err error
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if pconn == nil {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}

	rateLimiter := NewRateLimiter(rpsLimit)
	if rateLimiter != nil {
		log.Infof("rate limiting DNS queries to %.2f requests per second", rpsLimit)
	}
	pconn = NewDNSPacketConn(pconn, remoteAddr, domains, rateLimiter, maxQnameLen, maxNumLabels)
	err = run(pubkey, domains, localAddr, remoteAddr, pconn, maxQnameLen, maxNumLabels)
	if err != nil {
		log.Fatal(err)
	}
}
