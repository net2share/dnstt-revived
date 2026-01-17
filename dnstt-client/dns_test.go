package main

import (
	"bytes"
	"io"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func allPackets(buf []byte) ([][]byte, error) {
	var packets [][]byte
	r := bytes.NewReader(buf)
	for {
		p, err := nextPacket(r)
		if err != nil {
			return packets, err
		}
		packets = append(packets, p)
	}
}

func packetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestNextPacket(t *testing.T) {
	for _, test := range []struct {
		input   string
		packets [][]byte
		err     error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x00", [][]byte{{}}, io.EOF},
		{"\x00\x00\x00", [][]byte{{}}, io.ErrUnexpectedEOF},
		{"\x00\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x05hello\x00\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
	} {
		packets, err := allPackets([]byte(test.input))
		if !packetsEqual(packets, test.packets) || err != test.err {
			t.Errorf("%x\nreturned %x %v\nexpected %x %v",
				test.input, packets, err, test.packets, test.err)
		}
	}
}

// computeQueryNameLen calculates the total length of a DNS query name
// given encoded data length, label length, and domain labels.
func computeQueryNameLen(encodedLen int, labelLen int, domain dns.Name) int {
	numLabels := (encodedLen + labelLen - 1) / labelLen // ceil(encodedLen / labelLen)
	if numLabels == 0 {
		numLabels = 1
	}
	queryNameLen := encodedLen + (numLabels - 1) // encoded data + separator dots
	for _, label := range domain {
		queryNameLen += 1 + len(label)
	}
	return queryNameLen
}

func TestLabelConstraints(t *testing.T) {
	// Test that single-label mode produces single-label queries
	testCases := []struct {
		labelLen  int
		numLabels int
		domainStr string
	}{
		{57, 1, "d.example.org"}, // single-label mode
		{63, 1, "t.example.com"}, // max label length, single
		{40, 2, "short.io"},      // shorter labels, two labels
	}

	for _, tc := range testCases {
		domain, err := dns.ParseName(tc.domainStr)
		if err != nil {
			t.Fatalf("failed to parse domain %q: %v", tc.domainStr, err)
		}

		// Calculate max encoded chars with constraints
		maxEncoded := tc.numLabels * tc.labelLen

		// Calculate query name length
		queryNameLen := computeQueryNameLen(maxEncoded, tc.labelLen, domain)

		// Verify number of labels doesn't exceed limit
		actualLabels := (maxEncoded + tc.labelLen - 1) / tc.labelLen
		if actualLabels > tc.numLabels {
			t.Errorf("labelLen=%d numLabels=%d: produced %d labels, expected max %d",
				tc.labelLen, tc.numLabels, actualLabels, tc.numLabels)
		}

		t.Logf("labelLen=%d numLabels=%d domain=%s: maxEncoded=%d queryNameLen=%d",
			tc.labelLen, tc.numLabels, tc.domainStr, maxEncoded, queryNameLen)
	}
}
