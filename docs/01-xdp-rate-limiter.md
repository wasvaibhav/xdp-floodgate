# Phase 1: XDP per-IP rate limiter

What got built, the eBPF ideas behind it, and the trade-offs. Written for
someone fluent in Python who is new to kernel networking.

## The eBPF concepts

**eBPF.** A small, sandboxed virtual machine inside the Linux kernel. You
write C, clang compiles it to eBPF bytecode, and the kernel runs it at a
*hook point*. Python analogy: a callback you register with the kernel,
except it runs in kernel space with no syscall overhead.

**The verifier.** Before the kernel accepts a program it proves it is safe:
no unbounded loops, no out-of-bounds memory reads, every map lookup
checked for NULL. That is why `floodgate.c` checks
`if ((void *)(eth + 1) > data_end)` before every header read. Leave one
out and the load fails with a verifier log instead of crashing the kernel.
The `prog_test.go` tests load the real program, so a verifier rejection
fails CI.

**XDP (eXpress Data Path).** The earliest hook: it runs inside the NIC
driver as each packet arrives, before the kernel builds its packet
structure (`skb`). Dropping here costs roughly 50–100 ns per packet and
10M+ packets/s per core. By comparison, iptables sits after skb allocation
and a userspace proxy sits after the whole TCP stack. The program returns
a verdict: `XDP_DROP`, `XDP_PASS` (continue into the normal stack),
`XDP_TX`, or `XDP_REDIRECT`.
- *Native mode* runs in the driver and is fast. Real NICs (mlx5, ixgbe,
  i40e, ena, virtio-net) support it.
- *Generic mode* (`-generic`) runs after skb allocation. It is slower but
  works on any interface, including Docker veths, so the demos use it.

**Maps.** Key/value stores shared between the BPF program and userspace.
They are how the two sides talk. Floodgate uses seven:

| map | type | why this type |
|---|---|---|
| `config` | ARRAY[1] | Live limits. Userspace writes, XDP reads each packet. |
| `ip_state` | LRU_HASH | Per-source state. When full, the kernel evicts the least-recently-seen IP, so memory stays bounded however many IPs appear. |
| `global_tat` | PERCPU_ARRAY | Node-wide cap. Each CPU gets its own copy, so CPUs never contend. |
| `stats` | PERCPU_ARRAY | Counters. Per-CPU means no atomics. Userspace sums the copies. |
| `allowlist` | LPM_TRIE | Trusted IPv4/IPv6 prefixes. Longest-prefix match, one lookup per packet. |
| `applied` | ARRAY[1] | Unix timestamp of the last successful policy write, for staleness alerts. |
| `settings` | ARRAY[1] | Start-time switches that are not rate limits (currently IP-in-IP decap). |

**Per-CPU maps.** At millions of packets/s, if every CPU increments one
shared counter, the cache line holding it moves between cores constantly
("cache-line bouncing"), which quickly costs more than the filtering.
Per-CPU maps give each core a private slot. Userspace reads a
`[]value` (one entry per CPU) and adds them up.

**Pinning.** A BPF object stays alive only while something references
it. Pinning creates a file for it in the special `bpffs` filesystem
(`/sys/fs/bpf/floodgate/*`). Because of that:
- `floodgate start` attaches and **exits**, and the filter keeps running.
- `status` and `set-limit` are separate processes that open the pinned
  maps.
- If the control plane crashes (phase 3+), the data plane keeps
  protecting the node. This fail-safe behaviour is deliberate.

**bpf_link.** The attachment itself is an object, and it is pinned too.
Unpinning the last reference (`floodgate stop`) detaches it cleanly.

**CO-RE (Compile Once, Run Everywhere).** CO-RE lets a program that reads
*kernel-internal structs* (such as `task_struct`) run on kernels where
those structs have a different layout. XDP only parses packet headers,
and those formats are fixed by RFCs, so we use stable UAPI headers
(`linux/ip.h`, …) instead of a 3 MB `vmlinux.h`. The object is still
built once and runs on any kernel ≥ 5.9 (needed for XDP bpf_link).

**bpf2go.** This is cilium/ebpf's code generator (`go generate`). It
compiles `floodgate.c` with clang, embeds the `.o` in the Go binary, and
generates Go structs that match the C structs (`floodgateFgConfig`), so
the Go and C layouts can't drift apart.

## The algorithm: GCRA (a token bucket written in time)

A classic token bucket stores `tokens` and `last_refill`, and on each
packet computes `tokens += elapsed * rate`. That needs a division per
packet, and it rounds away fractional tokens: at 100 pps with packets
every 5 ms, each refill is 0.5 → 0 tokens, and the sender starves.

GCRA stores a single timestamp, `tat` ("paid up until"):

```python
interval  = 1e9 / rate          # ns each packet costs
tolerance = burst * interval    # how far into the future you may run

def allow(now):
    t = max(tat, now)           # idle time = refill
    if t + interval - now > tolerance:
        return False            # more than `burst` packets ahead: drop
    tat = t + interval
    return True
```

It behaves exactly like a token bucket (same rate, same burst), with one
compare and one add, no rounding, and 8 bytes of state. Userspace
precomputes `interval` and `tolerance`
([internal/limiter/gcra.go](../internal/limiter/gcra.go)), so XDP never
divides.

## Packet path

```
packet -> parse eth / VLAN / (optional IPIP) / IPv4|IPv6 / TCP flags
       -> not IP?                      PASS  (ARP etc. must keep working)
       -> bare SYN over syn limit?     DROP  drop_syn
       -> over per-IP limit?           DROP  drop_ip
       -> over node-wide cap?          DROP  drop_global
       -> PASS
```

With `start -decap`, one level of IPv4/IPv6 IP-in-IP is parsed first, so
the inner client source drives the per-IP and allowlist lookups. It is
opt-in because the inner source is only as trustworthy as the tunnel
sender; see [05-deployment.md](05-deployment.md).

Per-IP is checked **before** the global cap. That way one noisy IP is
dropped without using up the node budget everyone else shares.

## Trade-offs made

| decision | cost | why it's fine / when to revisit |
|---|---|---|
| **Racy (non-atomic) update of `tat`** | Two CPUs handling the same IP at the same moment can both admit a packet. Over-admission is at most one packet per CPU per race. | A lock or compare-and-swap at 10M pps costs far more. Being briefly generous by a few packets is harmless for overload protection. |
| **Global cap split per CPU** (`rate / NumCPU`) | If RSS sends traffic to only a few RX queues, the effective cap is lower than configured. | Contention-free. Shard by RX-queue count if it matters (marked `ponytail:` in `loader.go`). |
| **LRU map, 2M entries** | ~100 B/entry kernel-side, so **~200 MB at 2M**. When >2M sources are active, the oldest are evicted and restart with a full bucket. | `-max-ips` controls it. 500k ≈ 50 MB is plenty for most nodes behind a Maglev LB, which spreads clients across the fleet. |
| **Spoofed-source floods** | Random source IPs each look "new", so the per-IP limit never triggers and the LRU churns. | The global PPS cap is the backstop for this case. The kernel's `net.ipv4.tcp_syncookies=1` handles SYN state exhaustion. XDP SYN-cookies are possible later. |
| **Generous default per-IP limit** (1000 pps) | A single attacking IP gets 1000 pps. | Carrier-grade NAT can put hundreds of real users behind one IP. The allowlist and trusted class (phase 2) let this be tightened safely. |
| **No IPv6 extension-header walk** | IPv6 SYNs behind extension headers aren't SYN-limited (they're still per-IP limited). | Rare in practice. Bounded-loop parsing if needed. |
| **IPIP is opt-in** (`-decap`) | Behind **Katran**, packets arrive IPIP-encapsulated; without `-decap` the per-IP limit applies to Katran's address. | One level of IPv4/IPv6 inner headers is parsed. Enable only when tunnels come from a trusted LB and filter IPIP at the edge; the inner source is spoofable. Fragmented outer packets and IPv6 extension headers fall back to the outer source. |

## Try it

```sh
make docker-test      # unit + in-kernel BPF_PROG_RUN tests (privileged container)
make docker-build     # floodgate:dev image

# on a Linux host (root):
floodgate start -iface eth0 -ip-rate 1000 -ip-burst 2000 -syn-rate 50 -global-pps 2000000
floodgate status
floodgate set-limit -ip-rate 200      # live; unspecified limits unchanged
floodgate stop
```
