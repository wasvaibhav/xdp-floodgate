// SPDX-License-Identifier: Apache-2.0

// Package loader loads the XDP program, attaches it to an interface and
// exposes its maps (limits, stats) to the CLI.
//
// Everything is pinned under PinDir on bpffs. A pin is a file that keeps a
// kernel BPF object alive after the creating process exits, so:
//   - `floodgate start` can attach and exit; the filter keeps running.
//   - status / set-limit are separate processes that open the pinned maps.
//   - a crashing control plane never removes protection.
package loader

//go:generate go tool bpf2go -cc clang -target bpfel -type fg_config -type fg_datarec -type fg_lpm_key floodgate ../../bpf/floodgate.c

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/wasvaibhav/xdp-floodgate/internal/limiter"
)

const PinDir = "/sys/fs/bpf/floodgate"

var linkPin = filepath.Join(PinDir, "xdp_link")

// Limit is one rate limit in human units. Rate 0 = unlimited.
type Limit struct {
	Rate  uint64 `json:"rate"`
	Burst uint64 `json:"burst"`
}

type Limits struct {
	IP         Limit `json:"ip"`          // all packets per source IP
	SYN        Limit `json:"syn"`         // TCP SYNs per source IP
	TrustedIP  Limit `json:"trusted_ip"`  // same, for allowlisted sources
	TrustedSYN Limit `json:"trusted_syn"` // same, for allowlisted sources
	Global     Limit `json:"global"`      // all packets for the whole node
}

// Decap reports whether the data plane was started with IP-in-IP
// decapsulation enabled.
func Decap() (bool, error) {
	m, err := openPinned("settings")
	if err != nil {
		return false, err
	}
	defer m.Close()
	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		return false, err
	}
	return v != 0, nil
}

// ValidateLimits checks that the derived GCRA fields fit in uint64, so a
// huge burst cannot silently wrap and disable a limit.
func ValidateLimits(l Limits) error {
	for _, c := range []struct {
		name   string
		lim    Limit
		shards int
	}{
		{"ip", l.IP, 1},
		{"syn", l.SYN, 1},
		{"trusted_ip", l.TrustedIP, 1},
		{"trusted_syn", l.TrustedSYN, 1},
		{"global", l.Global, runtime.NumCPU()},
	} {
		if c.lim.Rate == 0 {
			continue
		}
		n := uint64(c.shards)
		if n < 1 {
			n = 1
		}
		interval := uint64(1e9) * n / c.lim.Rate
		if interval == 0 {
			interval = 1
		}
		burst := c.lim.Burst / n
		if burst < 1 {
			burst = 1
		}
		if burst > math.MaxUint64/interval {
			return fmt.Errorf("%s: burst %d is too large for rate %d", c.name, c.lim.Burst, c.lim.Rate)
		}
	}
	return nil
}

// StatNames matches the order of enum fg_stat in bpf/floodgate.c.
var StatNames = []string{"pass", "drop_ip", "drop_syn", "drop_global", "not_ip"}

type Counter struct{ Packets, Bytes uint64 }

// Start loads the program, writes the initial limits, attaches to iface
// and pins everything. generic forces the slower skb-mode XDP, needed on
// NICs/veths without native XDP support.
func Start(iface string, maxIPs uint32, generic bool, decap bool, lim Limits) (err error) {
	if maxIPs == 0 {
		return errors.New("max-ips must be greater than 0")
	}
	if err := ValidateLimits(lim); err != nil {
		return err
	}
	if _, statErr := os.Stat(linkPin); statErr == nil {
		return errors.New("already attached (run `floodgate stop` first)")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	// No link pin means nothing is attached. Remove pins left behind by a
	// start that failed after creating its maps, so this attempt gets fresh
	// state and the requested max_entries.
	if err := os.RemoveAll(PinDir); err != nil {
		return err
	}
	if err := os.MkdirAll(PinDir, 0o700); err != nil {
		return fmt.Errorf("%w (is bpffs mounted at /sys/fs/bpf?)", err)
	}
	defer func() {
		if err != nil {
			// Best effort: never leave half-attached state behind.
			err = errors.Join(err, os.RemoveAll(PinDir))
		}
	}()

	spec, err := loadFloodgate()
	if err != nil {
		return err
	}
	spec.Maps["ip_state"].MaxEntries = maxIPs

	var objs floodgateObjects
	// PinPath: maps marked LIBBPF_PIN_BY_NAME are created and pinned there.
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: PinDir},
	})
	if err != nil {
		// Verifier errors are long; %+v prints the full verifier log.
		return fmt.Errorf("loading BPF objects: %+v", err)
	}
	// Closing our fds is fine: pins keep the maps (and the link, the prog).
	defer objs.Close()

	if err := objs.Config.Put(uint32(0), toConfig(lim)); err != nil {
		return err
	}
	var decapValue uint32
	if decap {
		decapValue = 1
	}
	if err := objs.Settings.Put(uint32(0), decapValue); err != nil {
		return err
	}
	if err := markApplied(); err != nil {
		return err
	}

	flags := link.XDPAttachFlags(0) // 0 = native if the driver supports it
	if generic {
		flags = link.XDPGenericMode
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFloodgate,
		Interface: ifc.Index,
		Flags:     flags,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", iface, err)
	}
	defer l.Close()
	return l.Pin(linkPin)
}

// Stop detaches the program and deletes all pinned state.
func Stop() error {
	l, err := link.LoadPinnedLink(linkPin, nil)
	if err == nil {
		// Keep the pin if detaching fails, so a retry can still find the link.
		if err := l.Unpin(); err != nil {
			_ = l.Close()
			return err
		}
		err = l.Close()
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	} else {
		// A corrupt pin cannot be detached; clear the directory anyway.
		return errors.Join(err, os.RemoveAll(PinDir))
	}
	return errors.Join(err, os.RemoveAll(PinDir))
}

// GetLimits reads the live limits.
func GetLimits() (Limits, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "config"), nil)
	if err != nil {
		return Limits{}, err
	}
	defer m.Close()
	var c floodgateFgConfig
	if err := m.Lookup(uint32(0), &c); err != nil {
		return Limits{}, err
	}
	return Limits{
		IP:         Limit{c.Ip.Rate, c.Ip.Burst},
		SYN:        Limit{c.Syn.Rate, c.Syn.Burst},
		TrustedIP:  Limit{c.TrustedIp.Rate, c.TrustedIp.Burst},
		TrustedSYN: Limit{c.TrustedSyn.Rate, c.TrustedSyn.Burst},
		Global:     Limit{c.Global.Rate, c.Global.Burst},
	}, nil
}

// SetLimits replaces the live limits. The XDP program sees the new values
// on its very next packet; no reload, no dropped connections.
func SetLimits(lim Limits) error {
	if err := ValidateLimits(lim); err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "config"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Put(uint32(0), toConfig(lim)); err != nil {
		return err
	}
	return markApplied()
}

// Applied reports when the policy was last changed. The data plane keeps
// enforcing it regardless of whether the control daemon is alive.
func Applied() (time.Time, error) {
	m, err := openPinned("applied")
	if err != nil {
		return time.Time{}, err
	}
	defer m.Close()
	var ns uint64
	if err := m.Lookup(uint32(0), &ns); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, int64(ns)), nil
}

func markApplied() error {
	m, err := openPinned("applied")
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Put(uint32(0), uint64(time.Now().UnixNano()))
}

// Allow adds an IP or CIDR to the trusted allowlist. Allowlisted sources
// use Limits.TrustedIP / Limits.TrustedSYN instead of the default class.
func Allow(cidr string) error {
	k, err := allowKey(cidr)
	if err != nil {
		return err
	}
	m, err := openPinned("allowlist")
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Put(&k, uint8(1)); err != nil {
		return err
	}
	return markApplied()
}

// Disallow removes an entry added by Allow.
func Disallow(cidr string) error {
	k, err := allowKey(cidr)
	if err != nil {
		return err
	}
	m, err := openPinned("allowlist")
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Delete(&k); err != nil {
		return err
	}
	return markApplied()
}

// Allowlist returns the trusted entries as canonical CIDRs, sorted.
func Allowlist() ([]string, error) {
	m, err := openPinned("allowlist")
	if err != nil {
		return nil, err
	}
	defer m.Close()

	out := []string{}
	var k floodgateFgLpmKey
	var v uint8
	it := m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, allowString(k))
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// ValidateCIDR reports whether s is an IP or CIDR the allowlist accepts,
// without touching the pinned map.
func ValidateCIDR(s string) error {
	_, err := CanonicalCIDR(s)
	return err
}

// CanonicalCIDR returns the form stored in the allowlist. IPv4 entries
// come back as IPv4-mapped prefixes, so callers can compare entries.
func CanonicalCIDR(s string) (string, error) {
	k, err := allowKey(s)
	if err != nil {
		return "", err
	}
	return allowString(k), nil
}

// allowKey builds the LPM key for an IP or CIDR. IPv4 prefixes are stored
// as IPv4-mapped IPv6 (::ffff:a.b.c.d), matching the packet-path key.
func allowKey(s string) (floodgateFgLpmKey, error) {
	var k floodgateFgLpmKey
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return k, fmt.Errorf("invalid IP or CIDR %q", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.IsValid() {
		return k, fmt.Errorf("invalid IP or CIDR %q", s)
	}
	p = p.Masked()
	addr, bits := p.Addr(), p.Bits()
	if addr.Zone() != "" {
		return k, fmt.Errorf("zones are not supported: %q", s)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Is4() {
		bits += 96
	}
	b := addr.As16()
	k.Prefixlen = uint32(bits)
	copy(k.Addr[:], b[:])
	return k, nil
}

func allowString(k floodgateFgLpmKey) string {
	addr, bits := netip.AddrFrom16(k.Addr), int(k.Prefixlen)
	if addr.Is4In6() && bits >= 96 {
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).String()
}

func openPinned(name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, name), nil)
	if err != nil {
		return nil, fmt.Errorf("%s (is floodgate started?): %w", name, err)
	}
	return m, nil
}

// Stats sums the per-CPU counters.
func Stats() ([]Counter, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "stats"), nil)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	return readStats(m)
}

func readStats(m *ebpf.Map) ([]Counter, error) {
	out := make([]Counter, len(StatNames))
	for i := range out {
		var perCPU []floodgateFgDatarec // per-CPU maps return one value per CPU
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			return nil, err
		}
		for _, r := range perCPU {
			out[i].Packets += r.Packets
			out[i].Bytes += r.Bytes
		}
	}
	return out, nil
}

// Stat is one verdict counter with its name.
type Stat struct {
	Verdict string `json:"verdict"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Snapshot is the live data-plane state served by status and the API.
type Snapshot struct {
	Limits    Limits    `json:"limits"`
	Stats     []Stat    `json:"stats"`
	Allowlist []string  `json:"allowlist"`
	Applied   time.Time `json:"applied_at"`
	Decap     bool      `json:"decap"`
}

// ReadSnapshot reads the limits, per-verdict counters and allowlist. It is
// a point-in-time view: the maps may change while it is being assembled.
func ReadSnapshot() (Snapshot, error) {
	lim, err := GetLimits()
	if err != nil {
		return Snapshot{}, err
	}
	counters, err := Stats()
	if err != nil {
		return Snapshot{}, err
	}
	allow, err := Allowlist()
	if err != nil {
		return Snapshot{}, err
	}
	applied, err := Applied()
	if err != nil {
		return Snapshot{}, err
	}
	decap, err := Decap()
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Limits: lim, Allowlist: allow, Applied: applied, Decap: decap}
	for i, c := range counters {
		out.Stats = append(out.Stats, Stat{StatNames[i], c.Packets, c.Bytes})
	}
	return out, nil
}

func toConfig(l Limits) floodgateFgConfig {
	var c floodgateFgConfig
	c.Ip.Rate, c.Ip.Burst = l.IP.Rate, l.IP.Burst
	c.Ip.IntervalNs, c.Ip.ToleranceNs = limiter.GCRA(l.IP.Rate, l.IP.Burst, 1)
	c.Syn.Rate, c.Syn.Burst = l.SYN.Rate, l.SYN.Burst
	c.Syn.IntervalNs, c.Syn.ToleranceNs = limiter.GCRA(l.SYN.Rate, l.SYN.Burst, 1)
	c.TrustedIp.Rate, c.TrustedIp.Burst = l.TrustedIP.Rate, l.TrustedIP.Burst
	c.TrustedIp.IntervalNs, c.TrustedIp.ToleranceNs = limiter.GCRA(l.TrustedIP.Rate, l.TrustedIP.Burst, 1)
	c.TrustedSyn.Rate, c.TrustedSyn.Burst = l.TrustedSYN.Rate, l.TrustedSYN.Burst
	c.TrustedSyn.IntervalNs, c.TrustedSyn.ToleranceNs = limiter.GCRA(l.TrustedSYN.Rate, l.TrustedSYN.Burst, 1)
	c.Global.Rate, c.Global.Burst = l.Global.Rate, l.Global.Burst
	// ponytail: splits evenly over all CPUs; if RSS steers traffic to only a
	// few RX queues, the effective cap is lower. Shard by RX-queue count then.
	c.Global.IntervalNs, c.Global.ToleranceNs = limiter.GCRA(l.Global.Rate, l.Global.Burst, runtime.NumCPU())
	return c
}
