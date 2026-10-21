// SPDX-License-Identifier: GPL-2.0
//
// Floodgate XDP data plane (phase 1).
//
// Runs on every received packet, in the NIC driver, before the kernel
// allocates an skb. Per packet it does:
//   1. parse Ethernet -> (VLAN) -> IPv4/IPv6 -> TCP (only to spot SYNs)
//   2. per-source-IP rate limit (all packets), stricter one for SYNs
//   3. per-node global PPS cap (backstop for spoofed-source floods)
// and returns XDP_DROP or XDP_PASS.
//
// Every limit lives in the `config` map, so userspace can change limits
// live without reloading this program.
//
// Rate limiting uses GCRA, which is a token bucket written in "time"
// instead of "tokens" -- see gcra_allow() below.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_8021Q_ 0x8100
#define ETH_P_8021AD_ 0x88A8

// One rate limit. Userspace writes rate/burst (for humans) plus the two
// derived fields this program actually uses, so the hot path never divides.
// interval  = nanoseconds "paid" per packet    (1e9 / rate)
// tolerance = how far ahead of now one may be (burst * interval)
// interval == 0 disables the limit.
struct fg_limit {
	__u64 rate;
	__u64 burst;
	__u64 interval_ns;
	__u64 tolerance_ns;
};

struct fg_config {
	struct fg_limit ip;          // all packets, per source IP
	struct fg_limit syn;         // TCP SYNs, per source IP
	struct fg_limit trusted_ip;  // same, for allowlisted sources
	struct fg_limit trusted_syn; // same, for allowlisted sources
	struct fg_limit global;      // whole node; interval is the per-CPU share
};

// Longest-prefix-match key for the allowlist. addr is raw network bytes;
// IPv4 sources are looked up as IPv4-mapped IPv6 (::ffff:a.b.c.d), so one
// trie holds both families. prefixlen is ignored on lookup.
struct fg_lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

// Source address. IPv4 is stored IPv4-mapped (::ffff:a.b.c.d) so one map
// serves both families.
struct fg_ip_key {
	__u32 addr[4];
};

// Per-source state: the "theoretical arrival time" of the next packet.
struct fg_ip_state {
	__u64 tat;
	__u64 syn_tat;
};

enum fg_stat {
	FG_STAT_PASS = 0,
	FG_STAT_DROP_IP,
	FG_STAT_DROP_SYN,
	FG_STAT_DROP_GLOBAL,
	FG_STAT_NOT_IP, // ARP, LLDP, malformed... passed untouched
	FG_STAT_MAX,
};

struct fg_datarec {
	__u64 packets;
	__u64 bytes;
};

// Force bpf2go to emit Go types for these (see internal/loader).
const struct fg_config *unused_cfg __attribute__((unused));
const struct fg_datarec *unused_rec __attribute__((unused));

// ---- maps -----------------------------------------------------------------

// Single-slot array: live limits written by userspace.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fg_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} config SEC(".maps");

// Last successful policy write, nanoseconds since the Unix epoch. The
// data plane never reads it; userspace exposes it so operators can alert
// on stale policy after a failed rollout.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} applied SEC(".maps");

// Start-time settings that are not rate limits. Written once by the
// loader; set-limit and the control API do not touch it.
//   decap: 1 = parse one level of IP-in-IP and limit the inner source.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} settings SEC(".maps");

// Per-source-IP state. LRU: when full, the least recently seen IP is
// evicted automatically, so memory is bounded no matter how many sources
// show up. max_entries is overridden by the loader (--max-ips).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2000000);
	__type(key, struct fg_ip_key);
	__type(value, struct fg_ip_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_state SEC(".maps");

// Sources that skip the default per-IP class and use the trusted limits
// instead. LPM trie so operators can allow whole IPv4/IPv6 prefixes.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__type(key, struct fg_lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allowlist SEC(".maps");

// Node-wide cap, split per CPU: each CPU has its own bucket with
// 1/Nth of the rate, so no two CPUs ever touch the same memory.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} global_tat SEC(".maps");

// Counters, one copy per CPU (no atomics, no cache-line bouncing);
// userspace sums the copies when it reads them.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FG_STAT_MAX);
	__type(key, __u32);
	__type(value, struct fg_datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

// ---- helpers --------------------------------------------------------------

// GCRA ("generic cell rate algorithm") == token bucket, bookkept as time.
//
// Think of `tat` as "the time this sender is paid up until". Each packet
// costs `interval` ns. If paying for this packet would put the sender more
// than `tolerance` (= burst packets' worth) into the future, drop it.
// Idle senders fall behind `now`, which is the same as the bucket refilling.
//
// Why not a classic tokens+last_refill bucket? That needs a division per
// packet and loses fractional tokens to integer rounding at low rates.
// GCRA is one compare and one add, exact, and stores a single u64.
//
// Returns 1 = allow (and advances *tat), 0 = drop.
static __always_inline int gcra_allow(__u64 *tat, __u64 now,
				      const struct fg_limit *l)
{
	__u64 t = *tat;

	if (t < now)
		t = now;
	if (t + l->interval_ns - now > l->tolerance_ns)
		return 0;
	// Plain store, not atomic: two CPUs racing on the same IP can both
	// admit a packet. Over-admission is bounded by the number of CPUs and
	// is far cheaper than a lock at millions of packets/sec.
	*tat = t + l->interval_ns;
	return 1;
}

static __always_inline void count(__u32 stat, __u64 bytes)
{
	struct fg_datarec *rec = bpf_map_lookup_elem(&stats, &stat);

	if (rec) {
		rec->packets++;
		rec->bytes += bytes;
	}
}

static __always_inline int verdict(__u32 stat, __u64 bytes)
{
	count(stat, bytes);
	return stat == FG_STAT_PASS || stat == FG_STAT_NOT_IP ? XDP_PASS : XDP_DROP;
}

// Parse an inner IPv4 or IPv6 header at l3 and fill key/tcp. Returns 0 if
// the inner header is malformed or of another family; the caller then
// keeps the outer source, so a truncated tunnel cannot bypass the limit.
static __always_inline int parse_inner(void *l3, __be16 proto, void *data_end,
				       struct fg_ip_key *key,
				       struct tcphdr **tcp)
{
	*tcp = NULL;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = l3;

		if ((void *)(iph + 1) > data_end || iph->ihl < 5)
			return 0;
		key->addr[2] = bpf_htonl(0xffff);
		key->addr[3] = iph->saddr;
		if (iph->protocol == IPPROTO_TCP &&
		    !(iph->frag_off & bpf_htons(0x1fff)))
			*tcp = (void *)iph + iph->ihl * 4;
		return 1;
	}
	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;

		if ((void *)(ip6 + 1) > data_end)
			return 0;
		__builtin_memcpy(key->addr, &ip6->saddr, sizeof(key->addr));
		if (ip6->nexthdr == IPPROTO_TCP)
			*tcp = (void *)(ip6 + 1);
		return 1;
	}
	return 0;
}

// ---- program --------------------------------------------------------------

SEC("xdp")
int xdp_floodgate(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 bytes = data_end - data;
	__u32 zero = 0;

	// Every pointer must be bounds-checked against data_end before use,
	// otherwise the verifier rejects the program at load time.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return verdict(FG_STAT_NOT_IP, bytes);

	__u16 proto = eth->h_proto;
	void *l3 = eth + 1;

	// One VLAN tag (common on bare metal). QinQ is left to the switch.
	if (proto == bpf_htons(ETH_P_8021Q_) || proto == bpf_htons(ETH_P_8021AD_)) {
		struct { __be16 tci; __be16 proto; } *vlan = l3;
		if ((void *)(vlan + 1) > data_end)
			return verdict(FG_STAT_NOT_IP, bytes);
		proto = vlan->proto;
		l3 = vlan + 1;
	}

	struct fg_ip_key key = {};
	struct tcphdr *tcp = NULL;
	void *inner = NULL;
	__be16 inner_proto = 0;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = l3;
		if ((void *)(iph + 1) > data_end || iph->ihl < 5)
			return verdict(FG_STAT_NOT_IP, bytes);
		key.addr[2] = bpf_htonl(0xffff);
		key.addr[3] = iph->saddr;
		// Only the first fragment carries the TCP header.
		if (iph->protocol == IPPROTO_TCP &&
		    !(iph->frag_off & bpf_htons(0x1fff)))
			tcp = (void *)iph + iph->ihl * 4;
		// One level of IP-in-IP; fragmented outer packets are not
		// decapsulated because the inner header may be incomplete.
		if ((iph->protocol == IPPROTO_IPIP ||
		     iph->protocol == IPPROTO_IPV6) &&
		    !(iph->frag_off & bpf_htons(0x3fff))) {
			inner = (void *)iph + iph->ihl * 4;
			inner_proto = iph->protocol == IPPROTO_IPIP
					      ? bpf_htons(ETH_P_IP)
					      : bpf_htons(ETH_P_IPV6);
		}
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > data_end)
			return verdict(FG_STAT_NOT_IP, bytes);
		__builtin_memcpy(key.addr, &ip6->saddr, sizeof(key.addr));
		// Extension headers are not walked: such packets are still rate
		// limited per IP, just not recognised as SYNs.
		if (ip6->nexthdr == IPPROTO_TCP)
			tcp = (void *)(ip6 + 1);
		if (ip6->nexthdr == IPPROTO_IPIP || ip6->nexthdr == IPPROTO_IPV6) {
			inner = (void *)(ip6 + 1);
			inner_proto = ip6->nexthdr == IPPROTO_IPIP
					      ? bpf_htons(ETH_P_IP)
					      : bpf_htons(ETH_P_IPV6);
		}
	} else {
		return verdict(FG_STAT_NOT_IP, bytes);
	}

	// Opt-in: trust the inner source only when the operator enabled
	// decapsulation. A malformed inner header leaves the outer source in
	// place instead of skipping the limit.
	if (inner) {
		__u32 *decap = bpf_map_lookup_elem(&settings, &zero);
		if (decap && *decap) {
			struct fg_ip_key inner_key = {};
			struct tcphdr *inner_tcp = NULL;
			if (parse_inner(inner, inner_proto, data_end,
					&inner_key, &inner_tcp)) {
				key = inner_key;
				tcp = inner_tcp;
			}
		}
	}

	int is_syn = 0;
	if (tcp && (void *)(tcp + 1) <= data_end)
		is_syn = tcp->syn && !tcp->ack;

	struct fg_config *cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg) // cannot happen for an array map, but the verifier insists
		return verdict(FG_STAT_PASS, bytes);

	__u64 now = bpf_ktime_get_ns();

	// Allowlisted sources use the trusted class. The lookup is only a
	// trie walk; the global cap below still applies to trusted traffic.
	const struct fg_limit *ip_limit = &cfg->ip;
	const struct fg_limit *syn_limit = &cfg->syn;
	struct fg_lpm_key lk = { .prefixlen = 128 };
	__builtin_memcpy(lk.addr, key.addr, sizeof(lk.addr));
	if (bpf_map_lookup_elem(&allowlist, &lk)) {
		ip_limit = &cfg->trusted_ip;
		syn_limit = &cfg->trusted_syn;
	}

	// 1. Per-source limits. Checked before the global cap so one noisy IP
	//    is dropped without eating the node-wide budget of everyone else.
	if (ip_limit->interval_ns || (is_syn && syn_limit->interval_ns)) {
		struct fg_ip_state *st = bpf_map_lookup_elem(&ip_state, &key);
		if (!st) {
			// First packet from this IP: start with a full bucket.
			struct fg_ip_state fresh = { .tat = now, .syn_tat = now };
			bpf_map_update_elem(&ip_state, &key, &fresh, BPF_ANY);
			st = bpf_map_lookup_elem(&ip_state, &key);
		}
		if (st) {
			if (is_syn && syn_limit->interval_ns &&
			    !gcra_allow(&st->syn_tat, now, syn_limit))
				return verdict(FG_STAT_DROP_SYN, bytes);
			if (ip_limit->interval_ns &&
			    !gcra_allow(&st->tat, now, ip_limit))
				return verdict(FG_STAT_DROP_IP, bytes);
		}
	}

	// 2. Node-wide cap. Catches floods from millions of spoofed sources,
	//    which per-IP limits cannot (every source looks "new").
	if (cfg->global.interval_ns) {
		__u64 *gt = bpf_map_lookup_elem(&global_tat, &zero);
		if (gt && !gcra_allow(gt, now, &cfg->global))
			return verdict(FG_STAT_DROP_GLOBAL, bytes);
	}

	return verdict(FG_STAT_PASS, bytes);
}

char LICENSE[] SEC("license") = "GPL";
