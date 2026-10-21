// SPDX-License-Identifier: Apache-2.0

package loader

// More BPF_PROG_RUN coverage for the packet parser: IPv6, VLAN, IPv4
// options, fragments and truncated frames. Needs root, like prog_test.go.

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// tcpHeader fills the 20-byte TCP header at p with the given flags.
func tcpHeader(p []byte, src, dst uint16, flags byte) {
	binary.BigEndian.PutUint16(p[0:], src)
	binary.BigEndian.PutUint16(p[2:], dst)
	p[12] = 5 << 4 // data offset
	p[13] = flags
}

// ipv6Packet builds Ethernet + IPv6 + TCP from src.
func ipv6Packet(src [16]byte, flags byte) []byte {
	p := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(p[12:], 0x86dd)
	ip6 := p[14:]
	ip6[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip6[4:], 20)
	ip6[6] = 6 // TCP
	ip6[7] = 64
	copy(ip6[8:], src[:])
	copy(ip6[24:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	tcpHeader(ip6[40:], 40000, 80, flags)
	return p
}

// vlanPacket inserts an 802.1Q tag between the Ethernet header and p.
func vlanPacket(p []byte, vlanID uint16) []byte {
	out := make([]byte, 0, len(p)+4)
	out = append(out, p[:12]...)
	out = append(out, 0x81, 0x00)
	out = append(out, byte(vlanID>>8), byte(vlanID))
	out = append(out, p[12:]...)
	return out
}

// ipv4OptionsPacket builds Ethernet + IPv4 (24-byte header) + TCP.
func ipv4OptionsPacket(src [4]byte, flags byte) []byte {
	p := make([]byte, 14+24+20)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	ip := p[14:]
	ip[0] = 0x46 // v4, 24-byte header
	binary.BigEndian.PutUint16(ip[2:], 44)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], src[:])
	copy(ip[16:], []byte{10, 0, 0, 100})
	ip[20], ip[21], ip[22], ip[23] = 1, 1, 0, 0 // NOP, NOP, end of options
	tcpHeader(ip[24:], 40000, 80, flags)
	return p
}

// ipv4FragmentPacket builds Ethernet + IPv4 + bytes that look like TCP but
// belong to a non-first fragment (offset 1), so they must not be parsed as
// a TCP header.
func ipv4FragmentPacket(src [4]byte, flags byte) []byte {
	p := tcpPacket(src, flags)
	binary.BigEndian.PutUint16(p[14+6:], 1) // fragment offset, in 8-byte units
	return p
}

func TestPerIPv6Limit(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 3}})
	a := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, ackFlag)
	if got := run(t, objs, a, 10); got != 3 {
		t.Errorf("IPv6 sender A passed %d, want 3", got)
	}
	b := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, ackFlag)
	if got := run(t, objs, b, 10); got != 3 {
		t.Errorf("IPv6 sender B passed %d, want 3", got)
	}
}

func TestIPv6SYNLimit(t *testing.T) {
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 2}})
	pkt := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, synFlag)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("IPv6 SYN passed %d, want 2", got)
	}
}

func TestVLANLimit(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 2}})
	pkt := vlanPacket(tcpPacket([4]byte{192, 0, 2, 1}, ackFlag), 42)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("VLAN-tagged sender passed %d, want 2", got)
	}
}

func TestQinQIsNotIP(t *testing.T) {
	// QinQ is deliberately not parsed: it must pass untouched, not crash.
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}})
	outer := vlanPacket(vlanPacket(tcpPacket([4]byte{192, 0, 2, 1}, ackFlag), 1), 2)
	if got := run(t, objs, outer, 5); got != 5 {
		t.Errorf("QinQ passed %d, want 5", got)
	}
}

func TestIPv4OptionsSYN(t *testing.T) {
	// SYN detection must skip the IPv4 options, not read them as TCP.
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 2}})
	pkt := ipv4OptionsPacket([4]byte{198, 51, 100, 8}, synFlag)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("SYN with IPv4 options passed %d, want 2", got)
	}
}

func TestIPv4FragmentIsNotSYN(t *testing.T) {
	// Only the first fragment carries a TCP header; the SYN flag bits in a
	// later fragment are payload and must not consume the SYN budget.
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 1}})
	frag := ipv4FragmentPacket([4]byte{203, 0, 113, 10}, synFlag)
	if got := run(t, objs, frag, 5); got != 5 {
		t.Errorf("fragment passed %d, want 5", got)
	}
	bare := tcpPacket([4]byte{203, 0, 113, 10}, synFlag)
	if got := run(t, objs, bare, 5); got != 1 {
		t.Errorf("bare SYN passed %d, want 1", got)
	}
}

func TestTruncatedPacketsPass(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}, Global: Limit{Rate: 1, Burst: 1}})
	// BPF_PROG_RUN rejects frames shorter than an Ethernet header.
	for _, n := range []int{14, 20, 33} {
		if got := run(t, objs, make([]byte, n), 3); got != 3 {
			t.Errorf("%d-byte frame passed %d, want 3", n, got)
		}
	}
	stats, err := readStats(objs.Stats)
	if err != nil {
		t.Fatal(err)
	}
	if stats[4].Packets != 9 {
		t.Errorf("not_ip packets = %d, want 9", stats[4].Packets)
	}
}

func TestUDPIsLimited(t *testing.T) {
	// The per-IP limit covers every IP protocol, not just TCP.
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 2}})
	p := tcpPacket([4]byte{192, 0, 2, 20}, 0)
	p[14+9] = 17 // IPPROTO_UDP
	if got := run(t, objs, p, 10); got != 2 {
		t.Errorf("UDP passed %d, want 2", got)
	}
}

func TestStatsBytes(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}})
	pkt := tcpPacket([4]byte{192, 0, 2, 30}, ackFlag)
	if got := run(t, objs, pkt, 2); got != 1 {
		t.Fatalf("passed %d, want 1", got)
	}
	stats, err := readStats(objs.Stats)
	if err != nil {
		t.Fatal(err)
	}
	const frame = 14 + 20 + 20
	if stats[0].Bytes != frame || stats[1].Bytes != frame {
		t.Errorf("bytes pass=%d drop_ip=%d, want %d each", stats[0].Bytes, stats[1].Bytes, frame)
	}
}

// ip4in4Packet wraps an inner IPv4+TCP packet in an outer IPv4 IPIP
// header. Outer and inner sources differ so tests can tell which one the
// data plane used.
func ip4in4Packet(outer, inner [4]byte, flags byte) []byte {
	p := make([]byte, 14+20+20+20)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	o := p[14:]
	o[0] = 0x45
	binary.BigEndian.PutUint16(o[2:], 60)
	o[8] = 64
	o[9] = 4 // IPIP
	copy(o[12:], outer[:])
	copy(o[16:], []byte{10, 0, 0, 100})
	i := o[20:]
	i[0] = 0x45
	binary.BigEndian.PutUint16(i[2:], 40)
	i[8] = 64
	i[9] = 6
	copy(i[12:], inner[:])
	copy(i[16:], []byte{10, 0, 0, 200})
	tcp := i[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return p
}

// ip6in4Packet wraps an inner IPv6+TCP packet in an outer IPv4 header
// with protocol 41.
func ip6in4Packet(outer [4]byte, inner [16]byte, flags byte) []byte {
	p := make([]byte, 14+20+40+20)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	o := p[14:]
	o[0] = 0x45
	binary.BigEndian.PutUint16(o[2:], 80)
	o[8] = 64
	o[9] = 41 // IPv6
	copy(o[12:], outer[:])
	copy(o[16:], []byte{10, 0, 0, 100})
	i := o[20:]
	i[0] = 0x60
	binary.BigEndian.PutUint16(i[4:], 20)
	i[6] = 6
	i[7] = 64
	copy(i[8:24], inner[:])
	copy(i[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100})
	tcp := i[40:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return p
}

// ip4in6Packet wraps an inner IPv4+TCP packet in an outer IPv6 header.
func ip4in6Packet(outer [16]byte, inner [4]byte, flags byte) []byte {
	p := make([]byte, 14+40+20+20)
	binary.BigEndian.PutUint16(p[12:], 0x86dd)
	o := p[14:]
	o[0] = 0x60
	binary.BigEndian.PutUint16(o[4:], 40)
	o[6] = 4 // IPIP
	o[7] = 64
	copy(o[8:24], outer[:])
	copy(o[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100})
	i := o[40:]
	i[0] = 0x45
	binary.BigEndian.PutUint16(i[2:], 40)
	i[8] = 64
	i[9] = 6
	copy(i[12:], inner[:])
	copy(i[16:], []byte{10, 0, 0, 200})
	tcp := i[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return p
}

func runPackets(t *testing.T, objs *floodgateObjects, pkts [][]byte) int {
	t.Helper()
	passed := 0
	for _, pkt := range pkts {
		ret, err := objs.XdpFloodgate.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatal(err)
		}
		if ret == xdpPass {
			passed++
		}
	}
	return passed
}

func TestDecapIPv4Inner(t *testing.T) {
	// Same inner source, different outer sources: with decap the shared
	// inner bucket allows burst 2; without it every outer source is new.
	inner := [4]byte{192, 0, 2, 7}
	var pkts [][]byte
	for i := 0; i < 10; i++ {
		pkts = append(pkts, ip4in4Packet([4]byte{10, 9, 9, byte(i)}, inner, ackFlag))
	}
	on := loadTestObjectsDecap(t, Limits{IP: Limit{Rate: 1, Burst: 2}}, true)
	if got := runPackets(t, on, pkts); got != 2 {
		t.Errorf("decap on: %d passed, want 2", got)
	}
	off := loadTestObjectsDecap(t, Limits{IP: Limit{Rate: 1, Burst: 2}}, false)
	if got := runPackets(t, off, pkts); got != 10 {
		t.Errorf("decap off: %d passed, want 10", got)
	}
}

func TestDecapIPv6Inner(t *testing.T) {
	inner := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	var pkts [][]byte
	for i := 0; i < 10; i++ {
		pkts = append(pkts, ip6in4Packet([4]byte{10, 9, 9, byte(i)}, inner, ackFlag))
	}
	objs := loadTestObjectsDecap(t, Limits{IP: Limit{Rate: 1, Burst: 3}}, true)
	if got := runPackets(t, objs, pkts); got != 3 {
		t.Errorf("decap on: %d passed, want 3", got)
	}
}

func TestDecapIPv4InnerFromIPv6Outer(t *testing.T) {
	inner := [4]byte{192, 0, 2, 9}
	var pkts [][]byte
	for i := 0; i < 10; i++ {
		outer := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i)}
		pkts = append(pkts, ip4in6Packet(outer, inner, ackFlag))
	}
	objs := loadTestObjectsDecap(t, Limits{IP: Limit{Rate: 1, Burst: 2}}, true)
	if got := runPackets(t, objs, pkts); got != 2 {
		t.Errorf("decap on: %d passed, want 2", got)
	}
}

func TestDecapTrustedInner(t *testing.T) {
	// The inner source matches the allowlist, so the trusted class (burst
	// 5) applies instead of the default class (burst 1).
	objs := loadTestObjectsDecap(t, Limits{
		IP:        Limit{Rate: 1, Burst: 1},
		TrustedIP: Limit{Rate: 1, Burst: 5},
	}, true)
	k, err := allowKey("192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := objs.Allowlist.Put(&k, uint8(1)); err != nil {
		t.Fatal(err)
	}
	inner := [4]byte{192, 0, 2, 7}
	var pkts [][]byte
	for i := 0; i < 10; i++ {
		pkts = append(pkts, ip4in4Packet([4]byte{10, 9, 9, byte(i)}, inner, ackFlag))
	}
	if got := runPackets(t, objs, pkts); got != 5 {
		t.Errorf("trusted inner: %d passed, want 5", got)
	}
}
