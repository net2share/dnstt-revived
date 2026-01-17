package main

import (
	"bytes"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestDNSNameCapacity(t *testing.T) {
	labelLen := 57 // default label length
	for domainLen := 0; domainLen < 255; domainLen++ {
		domain, err := dns.NewName(chunks(bytes.Repeat([]byte{'x'}, domainLen), 63))
		if err != nil {
			continue
		}
		capacity := dnsNameCapacity(domain, labelLen, 0) // 0 = unlimited labels
		if capacity <= 0 {
			continue
		}
		prefix := []byte(base32Encoding.EncodeToString(bytes.Repeat([]byte{'y'}, capacity)))
		labels := append(chunks(prefix, labelLen), domain...)
		_, err = dns.NewName(labels)
		if err != nil {
			t.Errorf("length %v  capacity %v  %v", domainLen, capacity, err)
		}
	}
}
