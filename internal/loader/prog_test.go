// SPDX-License-Identifier: Apache-2.0

package loader

// These tests run the real XDP program in the kernel with BPF_PROG_RUN:
// we hand it a packet as bytes and get the verdict back, no NIC needed.
// Needs root (CAP_BPF + CAP_NET_ADMIN); `make docker-test` provides it.

import (
	"encoding/binary"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	xdpDrop = 1
	xdpPass = 2
)

func loadTestObjects(t *testing.T, lim Limits) *floodgateObjects {
	t.Helper()
	return loadTestObjectsDecap(t, lim, false)
}

func loadTestObjectsDecap(t *testing.T, lim Limits, decap bool) *floodgateObjects {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for BPF_PROG_RUN")
	}
	spec, err := loadFloodgate()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone // fresh, private maps per test
	}
	var objs floodgateObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load: %+v", err)
	}
	t.Cleanup(func() { objs.Close() })
	if err := objs.Config.Put(uint32(0), toConfig(lim)); err != nil {
		t.Fatal(err)
	}
	var decapValue uint32
	if decap {
		decapValue = 1
	}
	if err := objs.Settings.Put(uint32(0), decapValue); err != nil {
		t.Fatal(err)
	}
	return &objs
}

// tcpPacket builds Ethernet + IPv4 + TCP from src with the given TCP flags.
func tcpPacket(src [4]byte, flags byte) []byte {
	p := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(p[12:], 0x0800) // IPv4
	ip := p[14:]
	ip[0] = 0x45 // v4, 20-byte header
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:], src[:])
	copy(ip[16:], []byte{10, 0, 0, 100})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = flags
	return p
}

const (
	synFlag = 0x02
	ackFlag = 0x10
)

// run sends n packets and returns how many passed.
func run(t *testing.T, objs *floodgateObjects, pkt []byte, n int) int {
	t.Helper()
	passed := 0
	for i := 0; i < n; i++ {
		ret, err := objs.XdpFloodgate.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatal(err)
		}
		if ret == xdpPass {
			passed++
		} else if ret != xdpDrop {
			t.Fatalf("unexpected verdict %d", ret)
		}
	}
	return passed
}

func TestPerIPBurst(t *testing.T) {
	// 1 pps with burst 5: a fresh sender gets exactly 5 packets through.
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 5}})
	a := tcpPacket([4]byte{192, 0, 2, 1}, ackFlag)
	if got := run(t, objs, a, 20); got != 5 {
		t.Errorf("sender A passed %d, want 5", got)
	}
	// A different IP has its own bucket.
	b := tcpPacket([4]byte{192, 0, 2, 2}, ackFlag)
	if got := run(t, objs, b, 20); got != 5 {
		t.Errorf("sender B passed %d, want 5", got)
	}
	stats, err := readStats(objs.Stats)
	if err != nil {
		t.Fatal(err)
	}
	if stats[0].Packets != 10 || stats[1].Packets != 30 {
		t.Errorf("stats pass=%d drop_ip=%d, want 10/30", stats[0].Packets, stats[1].Packets)
	}
}

func TestSYNLimit(t *testing.T) {
	// SYNs are capped at burst 2 while other traffic from the same IP is not.
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 2}})
	src := [4]byte{198, 51, 100, 7}
	if got := run(t, objs, tcpPacket(src, synFlag), 10); got != 2 {
		t.Errorf("SYN passed %d, want 2", got)
	}
	if got := run(t, objs, tcpPacket(src, synFlag|ackFlag), 10); got != 10 {
		t.Errorf("SYN-ACK passed %d, want 10 (only bare SYNs are limited)", got)
	}
}

func TestLiveLimitUpdate(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}})
	pkt := tcpPacket([4]byte{203, 0, 113, 9}, ackFlag)
	if got := run(t, objs, pkt, 5); got != 1 {
		t.Fatalf("passed %d, want 1", got)
	}
	// Lifting the limit takes effect on the next packet, same program.
	if err := objs.Config.Put(uint32(0), toConfig(Limits{})); err != nil {
		t.Fatal(err)
	}
	if got := run(t, objs, pkt, 5); got != 5 {
		t.Errorf("after lifting limit passed %d, want 5", got)
	}
}

func TestNonIPPasses(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}, Global: Limit{Rate: 1, Burst: 1}})
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if got := run(t, objs, arp, 10); got != 10 {
		t.Errorf("ARP passed %d, want 10", got)
	}
}

func TestGlobalCap(t *testing.T) {
	// Global burst 1 is split per CPU, so at most one packet per CPU passes
	// no matter how many distinct sources send.
	objs := loadTestObjects(t, Limits{Global: Limit{Rate: 1, Burst: 1}})
	passed := 0
	for i := 0; i < 50; i++ {
		passed += run(t, objs, tcpPacket([4]byte{10, 1, byte(i), 1}, ackFlag), 1)
	}
	if passed < 1 || passed > runtime.NumCPU() {
		t.Errorf("passed %d, want 1..%d", passed, runtime.NumCPU())
	}
}
