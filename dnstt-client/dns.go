package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer is initially set to initPollDelay. It increases by a
	// factor of pollDelayMultiplier every time the poll timer expires, up
	// to a maximum of maxPollDelay. The poll timer is reset to
	// initPollDelay whenever an a send occurs that is not the result of the
	// poll timer expiring.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data.
	pollLimit = 16
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// RateLimiter implements a token bucket rate limiter for controlling the rate
// of DNS queries.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// NewRateLimiter creates a new rate limiter that allows rps requests per second.
// If rps is 0, the limiter allows unlimited requests.
func NewRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{
		tokens:   rps,
		capacity: rps,
		rate:     rps,
		lastTime: time.Now(),
	}
}

// Wait blocks until a token is available, then consumes one token.
// If the limiter is nil (unlimited), it returns immediately.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now

	// Add tokens based on elapsed time
	rl.tokens = rl.tokens + elapsed*rl.rate
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}

	// If we have at least one token, consume it
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return
	}

	// Otherwise, wait until we have a token
	needed := 1.0 - rl.tokens
	waitTime := time.Duration(needed / rl.rate * float64(time.Second))
	rl.mu.Unlock()
	time.Sleep(waitTime)
	rl.mu.Lock()
	// Recalculate tokens after sleep, in case time passed
	now = time.Now()
	elapsed = now.Sub(rl.lastTime).Seconds()
	rl.tokens = elapsed * rl.rate
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}
	// Consume the token
	rl.tokens -= 1.0
	rl.lastTime = now
}

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as a TXT RR
// in downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domains  []dns.Name
	// domainIndex is an atomic counter for round-robin domain selection.
	domainIndex uint32
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// rateLimiter limits the rate of outgoing DNS queries.
	rateLimiter *RateLimiter
	// maxQnameLen is the maximum total QNAME length in wire format (0 = 253 per RFC).
	maxQnameLen int
	// maxNumLabels is the maximum number of data labels (0 = unlimited).
	maxNumLabels int
	// forgedCount tracks the number of forged DNS responses detected.
	forgedCount uint64
	// countSERVFAIL tracks RCODE 2 responses of forged DNS responses detected.
	countSERVFAIL uint64
	// countNXDOMAIN tracks RCODE 3 responses of forged DNS responses detected.
	countNXDOMAIN uint64
	// countSuccess tracks RCODE 0 responses.
	countSuccess uint64
	// countOtherError tracks other error responses.
	countOtherError uint64
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent. rateLimiter, if not
// nil, limits the rate of outgoing DNS queries.
// maxQnameLen is the max total QNAME length (0 = 253 per RFC 1035).
// maxNumLabels is the max number of data labels (0 = unlimited).
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domains []dns.Name, rateLimiter *RateLimiter, maxQnameLen int, maxNumLabels int) *DNSPacketConn {
	// Default to RFC 1035 maximum if not specified
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domains:         domains,
		pollChan:        make(chan struct{}, pollLimit),
		rateLimiter:     rateLimiter,
		maxQnameLen:     maxQnameLen,
		maxNumLabels:    maxNumLabels,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Errorf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		if err != nil {
			log.Errorf("sendLoop: %v", err)
		}
	}()
	return c
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// into the RDATA of a TXT RR. It returns (payload, false) on success,
// (nil, true) if the response has error flags (likely forged by firewall),
// or (nil, false) if the message doesn't pass other format checks.
func dnsResponsePayload(resp *dns.Message, domains []dns.Name) ([]byte, bool) {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil, false
	}
	rcode := resp.Flags & 0x000f
	if rcode != dns.RcodeNoError {
		// Non-NOERROR response - likely forged by firewall or actual error
		return nil, true
	}

	if len(resp.Answer) != 1 {
		return nil, false
	}
	answer := resp.Answer[0]

	// Check if the answer matches any of our domains
	var matchedDomain bool
	for _, domain := range domains {
		_, ok := answer.Name.TrimSuffix(domain)
		if ok {
			matchedDomain = true
			break
		}
	}
	if !matchedDomain {
		// Not the name we are expecting.
		return nil, false
	}

	if answer.Type != dns.RRTypeTXT {
		// We only support TYPE == TXT.
		return nil, false
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil, false
	}

	return payload, false
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	for {
		var n uint16
		err := binary.Read(r, binary.BigEndian, &n)
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		p := make([]byte, n)
		_, err = io.ReadFull(r, p)
		// Here we must change io.EOF to io.ErrUnexpectedEOF.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return p, err
	}
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
// KCP itself will also send an ACK packet for incoming data, which is
// effectively a second poll. Therefore, each time we receive data, we send up
// to 2 polling queries (or 1 + f polling queries, if KCP only ACKs an f
// fraction of incoming data). We say "up to" because sendLoop will discard an
// empty polling query if it has an organic non-empty packet to send (this goes
// also for KCP's organic ACK packets).
//
// The intuition behind polling immediately after receiving is that if server
// has just had something to send, it may have more to send, and in order for
// the server to send anything, we must give it a query to respond to. The
// intuition behind polling *2 times* (or 1 + f times) is similar to TCP slow
// start: we want to maintain some number of queries "in flight", and the faster
// the server is sending, the higher that number should be. If we polled only
// once for each received packet, we would tend to have only one query in flight
// at a time, ping-pong style. The first polling query replaces the in-flight
// query that has just finished its duty in returning data to us; the second
// grows the effective in-flight window proportional to the rate at which
// data-carrying responses are being received. Compare to Eq. (2) of
// https://tools.ietf.org/html/rfc5681#section-3.1. The differences are that we
// count messages, not bytes, and we don't maintain an explicit window. If a
// response comes back without data, or if a query or response is dropped by the
// network, then we don't poll again, which decreases the effective in-flight
// window.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Warnf("temp error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		log.Debugf("recvLoop: got %d bytes from %s", n, addr)
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Warnf("parse error: %v", err)
			continue
		}

		payload, isForged := dnsResponsePayload(&resp, c.domains)
		if isForged {
			// Forged response detected (has error flags) - likely from firewall
			rcode := resp.Rcode()
			var count uint64
			var errorType string

			// Increment appropriate counter
			switch rcode {
			case dns.RcodeServerFailure: // 2
				count = atomic.AddUint64(&c.countSERVFAIL, 1)
				errorType = "SERVFAIL"
			case dns.RcodeNameError: // 3
				count = atomic.AddUint64(&c.countNXDOMAIN, 1)
				errorType = "NXDOMAIN"
			default:
				count = atomic.AddUint64(&c.countOtherError, 1)
				errorType = fmt.Sprintf("RCODE_%d", rcode)
			}
			atomic.AddUint64(&c.forgedCount, 1) // Keep total count as well

			// Get current success count for context
			successCount := atomic.LoadUint64(&c.countSuccess)

			// Extract QNAME if possible
			qname := "<unknown>"
			if len(resp.Question) > 0 {
				qname = resp.Question[0].Name.String()
			}

			// Calculate packet loss ratio: (all errors) / (total packets)
			totalErrors := atomic.LoadUint64(&c.forgedCount)
			totalPackets := successCount + totalErrors
			lossRatio := 0.0
			if totalPackets > 0 {
				lossRatio = float64(totalErrors) / float64(totalPackets)
			}

			log.Warnf("DNS error: %s (RCODE=%d) | QNAME: %s | Count: %d | Successes: %d | Loss Ratio: %f",
				errorType, rcode, qname, count, successCount, lossRatio)
			continue
		}
		atomic.AddUint64(&c.countSuccess, 1)

		// DEBUG: Log successful response
		log.Debugf("recv: payload=%d bytes", len(payload))

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}

		// If the payload contained one or more packets, permit sendLoop
		// to poll immediately. ACKs on received data will effectively
		// serve as another stream of polls whose rate is proportional
		// to the rate of incoming packets.
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr). The length of p must be less than 224 bytes.
//
// Here is an example of how a packet is encoded into a DNS name, using
//
//	p = "supercalifragilisticexpialidocious"
//	c.clientID = "CLIENTID"
//	domain = "t.example.com"
//
// as the input.
//
//  0. Start with the raw packet contents.
//
//     supercalifragilisticexpialidocious
//
//  1. Length-prefix the packet and add random padding. A length prefix L < 0xe0
//     means a data packet of L bytes. A length prefix L ≥ 0xe0 means padding
//     of L − 0xe0 bytes (not counting the length of the length prefix itself).
//
//     \xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
//
//  2. Prefix the ClientID.
//
//     CLIENTID\xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
//
//  3. Base32-encode, without padding and in lower case.
//
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3djmrxwg2lpovzq
//
//  4. Break into labels of at most 63 octets.
//
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq
//
//  5. Append the domain.
//
//     ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq.t.example.com
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	const labelLen = 63 // DNS maximum label size

	// Round-robin domain selection - select domain first to calculate capacity
	domainIdx := atomic.AddUint32(&c.domainIndex, 1) % uint32(len(c.domains))
	domain := c.domains[domainIdx]

	// Calculate domain wire length (each label: 1 length byte + content)
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Calculate available wire bytes for data labels
	maxQnameLen := c.maxQnameLen
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return fmt.Errorf("domain %s is too long for max-qname-len %d", domain.String(), c.maxQnameLen)
	}

	// Calculate encoded capacity from wire bytes
	// Each label requires L+1 wire bytes to carry L encoded chars
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	// If maxNumLabels is limited, also cap the encoded capacity
	if c.maxNumLabels > 0 {
		maxEncoded := c.maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		// ClientID (2 bytes)
		buf.Write(c.clientID[:])
		// Protocol: [ClientID: 2][DataLen: 1][Data] for data, [ClientID: 2] for polls
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		// For polls (len(p) == 0), send only ClientID
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	// Chunk into labels using max 63 bytes per label
	labels := chunks(encoded, labelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(buf, addr)
	if err == nil {
		log.Debugf("send: decoded=%d encoded=%d dataLen=%d", len(decoded), len(encoded), len(p))
	}
	return err
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// A data-carrying packet displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		// Apply rate limiting before sending.
		c.rateLimiter.Wait()

		// Unlike in the server, in the client we assume that because
		// the data capacity of queries is so limited, it's not worth
		// trying to send more than one packet per query.
		err := c.send(transport, p, addr)
		if err != nil {
			log.Errorf("send: %v", err)
			continue
		}
	}
}
