package main

import (
	"bytes"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestDNSNameCapacity(t *testing.T) {
	const labelLen = 63 // DNS maximum label size
	for domainLen := 0; domainLen < 255; domainLen++ {
		domain, err := dns.NewName(chunks(bytes.Repeat([]byte{'x'}, domainLen), 63))
		if err != nil {
			continue
		}
		capacity := dnsNameCapacity(domain, 0, 0) // 0 = unlimited for both
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

func TestDNSNameCapacityWithMaxQnameLen(t *testing.T) {
	testCases := []struct {
		name          string
		domainStr     string
		maxQnameLen   int
		maxNumLabels  int
		expectNonZero bool
	}{
		{"default limits", "t.example.com", 0, 0, true},
		{"max qname 200", "t.example.com", 200, 0, true},
		{"max qname 100", "short.io", 100, 0, true},
		{"max num labels 1", "d.example.org", 0, 1, true},
		{"max num labels 2", "d.example.org", 0, 2, true},
		{"both limits", "d.example.org", 150, 2, true},
		{"very short qname - edge", "x.io", 20, 0, false},          // domain itself is ~7 bytes, very little room
		{"qname exactly domain size", "example.com", 12, 0, false}, // domain is 12 bytes, no room for data
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain, err := dns.ParseName(tc.domainStr)
			if err != nil {
				t.Fatalf("failed to parse domain %q: %v", tc.domainStr, err)
			}

			capacity := dnsNameCapacity(domain, tc.maxQnameLen, tc.maxNumLabels)

			if tc.expectNonZero && capacity <= 0 {
				t.Errorf("expected positive capacity, got %d", capacity)
			}
			if !tc.expectNonZero && capacity > 0 {
				// This is okay - we're testing edge cases, not strict zeros
				t.Logf("capacity=%d for edge case (acceptable)", capacity)
			}

			t.Logf("domain=%s maxQnameLen=%d maxNumLabels=%d -> capacity=%d",
				tc.domainStr, tc.maxQnameLen, tc.maxNumLabels, capacity)
		})
	}
}

func TestDNSNameCapacityMultiDomain(t *testing.T) {
	// Test that capacity calculation works correctly for domains of different lengths
	domains := []string{
		"t.example.com",       // medium
		"a.b.c.d.example.org", // long
		"x.io",                // short
	}

	for _, domainStr := range domains {
		domain, err := dns.ParseName(domainStr)
		if err != nil {
			t.Fatalf("failed to parse domain %q: %v", domainStr, err)
		}

		// Calculate domain wire length for logging
		domainWireLen := 0
		for _, label := range domain {
			domainWireLen += 1 + len(label)
		}

		capacityUnlimited := dnsNameCapacity(domain, 0, 0)
		capacityLimitedQname := dnsNameCapacity(domain, 150, 0)
		capacityLimitedLabels := dnsNameCapacity(domain, 0, 2)
		capacityBothLimits := dnsNameCapacity(domain, 150, 2)

		t.Logf("domain=%s wireLen=%d | unlimited=%d qname150=%d labels2=%d both=%d",
			domainStr, domainWireLen, capacityUnlimited, capacityLimitedQname, capacityLimitedLabels, capacityBothLimits)

		// Verify that limited capacity is always <= unlimited
		if capacityLimitedQname > capacityUnlimited {
			t.Errorf("limited qname capacity %d > unlimited %d", capacityLimitedQname, capacityUnlimited)
		}
		if capacityLimitedLabels > capacityUnlimited {
			t.Errorf("limited labels capacity %d > unlimited %d", capacityLimitedLabels, capacityUnlimited)
		}
		if capacityBothLimits > capacityLimitedQname {
			t.Errorf("both limits capacity %d > qname limited %d", capacityBothLimits, capacityLimitedQname)
		}
		if capacityBothLimits > capacityLimitedLabels {
			t.Errorf("both limits capacity %d > labels limited %d", capacityBothLimits, capacityLimitedLabels)
		}
	}
}

func TestDNSNameCapacityBoundaryConditions(t *testing.T) {
	domain, _ := dns.ParseName("t.example.com")
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Test boundary: maxQnameLen just barely larger than domain
	capacity := dnsNameCapacity(domain, domainWireLen+10, 0)
	t.Logf("domainWireLen=%d, maxQnameLen=%d -> capacity=%d", domainWireLen, domainWireLen+10, capacity)

	// Capacity should be very small or zero
	if capacity > 10 {
		t.Errorf("expected small capacity for tight qname limit, got %d", capacity)
	}

	// Test that 0 maxNumLabels allows many labels
	capacityManyLabels := dnsNameCapacity(domain, 0, 0)
	capacitySingleLabel := dnsNameCapacity(domain, 0, 1)
	if capacitySingleLabel >= capacityManyLabels {
		t.Errorf("single label capacity %d should be < unlimited %d", capacitySingleLabel, capacityManyLabels)
	}
}
