// SPDX-License-Identifier: Apache-2.0

package loader

// Lifecycle tests for the pinned state: attach, read, update, detach.
// Needs root (CAP_NET_ADMIN + bpffs), like the BPF_PROG_RUN tests.

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestStartRejectsZeroMaxIPs(t *testing.T) {
	if err := Start("lo", 0, true, false, Limits{}); err == nil {
		t.Fatal("Start accepted max-ips 0")
	}
}

func TestLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach XDP and pin state")
	}
	if _, err := os.Stat(PinDir); err == nil {
		t.Skipf("%s already in use", PinDir)
	}
	lim := Limits{IP: Limit{Rate: 100, Burst: 10}, SYN: Limit{Rate: 10, Burst: 5}}
	if err := Start("lo", 1024, true, true, lim); err != nil {
		if strings.Contains(err.Error(), "bpffs") {
			t.Skipf("bpffs not mounted: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop() })

	if err := Start("lo", 1024, true, true, lim); err == nil || !strings.Contains(err.Error(), "already attached") {
		t.Errorf("second start error = %v, want already attached", err)
	}

	got, err := GetLimits()
	if err != nil {
		t.Fatal(err)
	}
	if got != lim {
		t.Errorf("limits = %+v, want %+v", got, lim)
	}
	if decap, err := Decap(); err != nil || !decap {
		t.Errorf("Decap() = %v, %v; want true", decap, err)
	}

	lim.IP.Rate = 7
	if err := SetLimits(lim); err != nil {
		t.Fatal(err)
	}
	if got, err = GetLimits(); err != nil {
		t.Fatal(err)
	}
	if got != lim {
		t.Errorf("after update limits = %+v, want %+v", got, lim)
	}

	stats, err := Stats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != len(StatNames) {
		t.Errorf("stats has %d counters, want %d", len(stats), len(StatNames))
	}

	// The allowlist lives in a pinned map and survives CLI invocations.
	for _, cidr := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		if err := Allow(cidr); err != nil {
			t.Fatalf("allow %s: %v", cidr, err)
		}
	}
	entries, err := Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "2001:db8::/32"}
	if len(entries) != len(want) || entries[0] != want[0] || entries[1] != want[1] {
		t.Errorf("allowlist = %v, want %v", entries, want)
	}
	if err := Disallow("192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if entries, err = Allowlist(); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != want[1] {
		t.Errorf("allowlist after remove = %v, want [%s]", entries, want[1])
	}

	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PinDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s still exists after stop: %v", PinDir, err)
	}
	if err := Stop(); err != nil {
		t.Errorf("second stop: %v", err)
	}
}
