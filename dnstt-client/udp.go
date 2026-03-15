package main

import (
	"context"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// UDPPacketConn is a UDP-based transport for DNS messages. Its WriteTo and
// ReadFrom methods exchange DNS messages over UDP, with each query using a
// new socket to randomize the source port.
//
// UDPPacketConn deals only with already formatted DNS messages. It does not
// handle encoding information into the messages. That is rather the
// responsibility of DNSPacketConn.
type UDPPacketConn struct {
	// remoteAddr is the address to which queries are sent.
	remoteAddr net.Addr

	// dialerControl is an optional function to control socket options when
	// creating new UDP sockets.
	dialerControl func(network, address string, c syscall.RawConn) error

	// responseTimeout is how long to wait for a UDP response per query.
	responseTimeout time.Duration

	// ignoreErrors controls whether to filter out non-NOERROR DNS responses.
	// When true (default), error responses (SERVFAIL, NXDOMAIN, etc.) are
	// skipped and the worker waits for a NOERROR response until timeout.
	// When false, all responses are passed through regardless of RCODE.
	ignoreErrors bool

	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// sendLoop workers remove messages from the outgoing queue that were
	// placed there by WriteTo, and insert messages into the incoming queue
	// to be returned from ReadFrom.
	*turbotunnel.QueuePacketConn
}

// NewUDPPacketConn creates a new UDPPacketConn configured to send queries to
// remoteAddr. It creates numWorkers concurrent worker goroutines, each of
// which creates a new UDP socket for each query to randomize the source port.
// responseTimeout controls how long each worker waits for a response.
// ignoreErrors controls whether to filter out non-NOERROR DNS responses.
func NewUDPPacketConn(remoteAddr net.Addr, dialerControl func(network, address string, c syscall.RawConn) error, numWorkers int, responseTimeout time.Duration, ignoreErrors bool) (*UDPPacketConn, error) {
	c := &UDPPacketConn{
		remoteAddr:      remoteAddr,
		dialerControl:   dialerControl,
		responseTimeout: responseTimeout,
		ignoreErrors:    ignoreErrors,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(remoteAddr, 0),
	}
	for i := 0; i < numWorkers; i++ {
		go c.sendLoop()
	}
	return c, nil
}

// sendLoop is a worker goroutine that processes packets from the outgoing
// queue. For each packet, it creates a new UDP socket, sends the query,
// waits for a response on that socket, and queues the response.
func (c *UDPPacketConn) sendLoop() {
	for p := range c.QueuePacketConn.OutgoingQueue(c.remoteAddr) {
		// Create a new UDP socket for this query. This will get a random
		// source port assigned by the OS.
		lc := net.ListenConfig{}
		if c.dialerControl != nil {
			lc.Control = c.dialerControl
		}
		conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			log.Warnf("sendLoop: ListenPacket: %v", err)
			continue
		}

		// Send the query.
		_, err = conn.WriteTo(p, c.remoteAddr)
		if err != nil {
			log.Warnf("sendLoop: WriteTo: %v", err)
			conn.Close()
			continue
		}

		// Read responses on this socket until we get a valid one or timeout.
		deadline := time.Now().Add(c.responseTimeout)
		conn.SetReadDeadline(deadline)
		var buf [4096]byte
		for {
			n, _, err := conn.ReadFrom(buf[:])
			if err != nil {
				// Timeout or other error.
				break
			}

			if c.ignoreErrors {
				// Filter mode: skip non-NOERROR responses (likely
				// forged by censorship) and wait for the real one.
				resp, parseErr := dns.MessageFromWireFormat(buf[:n])
				if parseErr == nil && resp.Flags&0x8000 != 0 {
					rcode := resp.Rcode()
					if rcode != dns.RcodeNoError {
						log.Debugf("UDP: skipping error response (RCODE=%d), waiting for real response", rcode)
						continue
					}
				}
			}

			// Pass through: queue the response.
			c.QueuePacketConn.QueueIncoming(buf[:n], c.remoteAddr)
			break
		}
		conn.Close()
	}
}
