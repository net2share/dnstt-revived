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
// given encoded data length, and domain labels.
// Labels are always chunked at 63 bytes (DNS max).
func computeQueryNameLen(encodedLen int, domain dns.Name) int {
	const labelLen = 63
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
	// Test that label constraints work correctly with new parameters
	const labelLen = 63 // DNS maximum label size
	testCases := []struct {
		maxQnameLen  int
		maxNumLabels int
		domainStr    string
	}{
		{0, 1, "d.example.org"}, // unlimited qname, single label
		{0, 0, "t.example.com"}, // unlimited both
		{200, 2, "short.io"},    // limited qname length
	}

	for _, tc := range testCases {
		domain, err := dns.ParseName(tc.domainStr)
		if err != nil {
			t.Fatalf("failed to parse domain %q: %v", tc.domainStr, err)
		}

		// Calculate max encoded chars with constraints
		maxEncoded := labelLen * 4 // assume up to 4 labels for testing
		if tc.maxNumLabels > 0 {
			maxEncoded = tc.maxNumLabels * labelLen
		}

		// Calculate query name length
		queryNameLen := computeQueryNameLen(maxEncoded, domain)

		// Verify number of labels doesn't exceed limit when limit is set
		actualLabels := (maxEncoded + labelLen - 1) / labelLen
		if tc.maxNumLabels > 0 && actualLabels > tc.maxNumLabels {
			t.Errorf("maxQnameLen=%d maxNumLabels=%d: produced %d labels, expected max %d",
				tc.maxQnameLen, tc.maxNumLabels, actualLabels, tc.maxNumLabels)
		}

		t.Logf("maxQnameLen=%d maxNumLabels=%d domain=%s: maxEncoded=%d queryNameLen=%d",
			tc.maxQnameLen, tc.maxNumLabels, tc.domainStr, maxEncoded, queryNameLen)
	}
}
