package main

import (
	"context"
	"log"
	"net"
	"syscall"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// Timeout for waiting for a UDP response after sending a query.
	udpResponseTimeout = 10 * time.Second
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

	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// sendLoop workers remove messages from the outgoing queue that were
	// placed there by WriteTo, and insert messages into the incoming queue
	// to be returned from ReadFrom.
	*turbotunnel.QueuePacketConn
}

// NewUDPPacketConn creates a new UDPPacketConn configured to send queries to
// remoteAddr. It creates numWorkers concurrent worker goroutines, each of
// which creates a new UDP socket for each query to randomize the source port.
// dialerControl is an optional function to control socket options when
// creating new UDP sockets.
func NewUDPPacketConn(remoteAddr net.Addr, dialerControl func(network, address string, c syscall.RawConn) error, numWorkers int) (*UDPPacketConn, error) {
	c := &UDPPacketConn{
		remoteAddr:      remoteAddr,
		dialerControl:   dialerControl,
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
			log.Printf("sendLoop: ListenPacket: %v", err)
			continue
		}

		// Send the query.
		_, err = conn.WriteTo(p, c.remoteAddr)
		if err != nil {
			log.Printf("sendLoop: WriteTo: %v", err)
			conn.Close()
			continue
		}

		// Wait for a response on this socket, with a timeout.
		conn.SetReadDeadline(time.Now().Add(udpResponseTimeout))
		var buf [4096]byte
		n, _, err := conn.ReadFrom(buf[:])
		conn.Close()

		if err != nil {
			// Timeout or other error. This is expected for some queries
			// that don't receive responses, so we don't log it.
			continue
		}

		// Queue the response. Use c.remoteAddr since that's where we sent
		// the query to and where the response comes from.
		c.QueuePacketConn.QueueIncoming(buf[:n], c.remoteAddr)
	}
}
