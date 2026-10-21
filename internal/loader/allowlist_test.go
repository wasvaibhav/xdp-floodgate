// SPDX-License-Identifier: Apache-2.0

package loader

// Allowlist coverage: key encoding (no root) and the trusted class in the
// data plane (BPF_PROG_RUN, needs root).

import (
	"runtime"
	"testing"
)

func TestAllowKeyRoundTrip(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.5":            "192.0.2.5/32",
		"10.0.0.0/8":           "10.0.0.0/8",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"2001:db8::/32":        "2001:db8::/32",
		"2001:0db8:0000::/48":  "2001:db8::/48",
		"::1":                  "::1/128",
	} {
		k, err := allowKey(in)
		if err != nil {
			t.Errorf("allowKey(%q): %v", in, err)
			continue
		}
		if got := allowString(k); got != want {
			t.Errorf("allowKey(%q) round-trips to %q, want %q", in, got, want)
		}
	}
}

func TestAllowKeyRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "10.0.0.0/33", "fe80::1%eth0"} {
		if _, err := allowKey(in); err == nil {
			t.Errorf("allowKey(%q) accepted an invalid entry", in)
		}
	}
}

func TestAllowRejectsInvalid(t *testing.T) {
	if err := Allow("not-an-ip"); err == nil {
		t.Error("Allow accepted an invalid entry")
	}
}

func mustAllow(t *testing.T, objs *floodgateObjects, cidr string) {
	t.Helper()
	k, err := allowKey(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if err := objs.Allowlist.Put(&k, uint8(1)); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistTrustedIP(t *testing.T) {
	objs := loadTestObjects(t, Limits{
		IP:        Limit{Rate: 1, Burst: 1},
		TrustedIP: Limit{Rate: 1, Burst: 4},
	})
	mustAllow(t, objs, "192.0.2.0/24")
	if got := run(t, objs, tcpPacket([4]byte{192, 0, 2, 1}, ackFlag), 20); got != 4 {
		t.Errorf("trusted IPv4 passed %d, want 4", got)
	}
	if got := run(t, objs, tcpPacket([4]byte{192, 0, 3, 1}, ackFlag), 20); got != 1 {
		t.Errorf("untrusted IPv4 passed %d, want 1", got)
	}
}

func TestAllowlistTrustedIPv6(t *testing.T) {
	objs := loadTestObjects(t, Limits{
		IP:        Limit{Rate: 1, Burst: 1},
		TrustedIP: Limit{Rate: 1, Burst: 3},
	})
	mustAllow(t, objs, "2001:db8:1::/48")
	inside := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, ackFlag)
	if got := run(t, objs, inside, 10); got != 3 {
		t.Errorf("trusted IPv6 passed %d, want 3", got)
	}
	outside := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, ackFlag)
	if got := run(t, objs, outside, 10); got != 1 {
		t.Errorf("untrusted IPv6 passed %d, want 1", got)
	}
}

func TestAllowlistTrustedSYN(t *testing.T) {
	objs := loadTestObjects(t, Limits{
		SYN:        Limit{Rate: 1, Burst: 1},
		TrustedSYN: Limit{Rate: 1, Burst: 3},
	})
	mustAllow(t, objs, "198.51.100.0/24")
	trusted := tcpPacket([4]byte{198, 51, 100, 7}, synFlag)
	if got := run(t, objs, trusted, 10); got != 3 {
		t.Errorf("trusted SYN passed %d, want 3", got)
	}
	untrusted := tcpPacket([4]byte{198, 51, 101, 7}, synFlag)
	if got := run(t, objs, untrusted, 10); got != 1 {
		t.Errorf("untrusted SYN passed %d, want 1", got)
	}
}

func TestAllowlistStillCappedGlobally(t *testing.T) {
	// Trusted sources skip per-IP limits, not the node-wide backstop.
	objs := loadTestObjects(t, Limits{
		TrustedIP: Limit{Rate: 0, Burst: 0},
		Global:    Limit{Rate: 1, Burst: 1},
	})
	mustAllow(t, objs, "203.0.113.0/24")
	passed := 0
	for i := 0; i < 50; i++ {
		passed += run(t, objs, tcpPacket([4]byte{203, 0, 113, 1}, ackFlag), 1)
	}
	if passed < 1 || passed > runtime.NumCPU() {
		t.Errorf("trusted traffic passed %d packets, want 1..%d", passed, runtime.NumCPU())
	}
}
