# Phase 2: allowlist and the trusted class

Phase 1 ships generous per-IP defaults (1000 pps) because carrier-grade NAT
can put hundreds of real users behind one address. Phase 2 makes it safe to
tighten those defaults: known-good sources are added to an allowlist and
use a second set of limits instead.

## Data plane

The allowlist is an `LPM_TRIE` map: one trie holds IPv4 and IPv6 prefixes.
IPv4 sources are looked up as IPv4-mapped IPv6 (`::ffff:a.b.c.d`), the same
key layout `ip_state` already uses, so a packet needs no extra address
conversion. Lookup returns as soon as the longest matching prefix is found;
the key's `prefixlen` is ignored on lookup and only matters when userspace
inserts an entry.

Every packet takes one extra trie lookup. After a hit, the program uses
`trusted_ip` / `trusted_syn` from the config map instead of `ip` / `syn`:

```
packet -> parse -> allowlist lookup
                -> hit:  trusted per-IP / SYN limits
                -> miss: default per-IP / SYN limits
       -> global cap (always) -> PASS or DROP
```

The trusted class only replaces the per-source limits. The node-wide PPS
cap still applies, so an allowlisted source cannot starve the node by
itself. This is deliberate: allowlisting is about tolerating legitimate
bursts, not about removing the backstop.

An empty trusted limit (rate 0) means "no per-source limit" for
allowlisted traffic, which is the default: `floodgate allow` is enough to
exempt a health checker. Set `-trusted-ip-rate` and friends to cap it.

With `-decap`, both the allowlist and the per-IP state use the inner
source. Only enable it where IP-in-IP can arrive solely from a trusted
load balancer: anyone who can send a tunnel can claim an allowlisted
inner address. See [05-deployment.md](05-deployment.md).

## State sharing

Per-IP GCRA state is keyed by source address only, not by class. Adding or
removing an allowlist entry changes which limits apply to the next packet,
but the sender keeps its current `tat` (how far ahead it is paid up). That
avoids a second state map and makes allowlist changes instant; the
downside is that a source switched from trusted to default may be over its
new limit for one burst interval, which the next packets correct.

## CLI

```sh
floodgate allow 203.0.113.0/24       # IPv4 prefix
floodgate allow 2001:db8::/32        # IPv6 prefix
floodgate allow 198.51.100.7         # bare IP becomes /32 or /128
floodgate allowlist                  # canonical, sorted entries
floodgate deny 203.0.113.0/24        # remove

# Start with tighter defaults and a roomier trusted class:
floodgate start -iface eth0 \
  -ip-rate 100 -ip-burst 200 -syn-rate 10 -syn-burst 20 \
  -trusted-ip-rate 5000 -trusted-ip-burst 10000 \
  -trusted-syn-rate 500 -trusted-syn-burst 1000

floodgate set-limit -trusted-ip-rate 2000   # live, other limits unchanged
```

Entries live in the pinned map, so they survive CLI invocations and a
crashed control plane, and disappear with `floodgate stop` (or a reboot,
since bpffs is not persistent).

## Trade-offs

| decision | cost | why it is fine |
|---|---|---|
| **LPM trie on every packet** | A trie walk (~50 ns) even when the allowlist is empty. | The limit is opt-in and the node-wide cap is the primary overload defence; ops that never allowlist pay little. |
| **One trusted class, not N classes** | No per-service priority tiers. | The named phase 2 use case is "tighten defaults without breaking health checks". N classes need policy storage and a per-entry class validation surface; add them with the control plane if a real need appears. |
| **Global cap still applies** | An allowlisted source can be dropped during a node-wide flood. | Keeps the node alive; scale the cap or add a second node instead of punching a per-source hole. |
| **Per-IP state shared across classes** | A demoted source can overshoot for one burst interval. | State is one `tat` pair per IP; the alternative doubles memory and needs a flush on allowlist changes. |
| **65k prefixes** | Large allowlists fail at insert. | Enough for partner, monitoring and LB ranges; raise `max_entries` in the map definition if not. |
| **No allowlist persistence to disk** | Entries vanish on reboot. | Phase 5 policy bundles and phase 3 config are the persistence layer; bpffs is intentionally not persistent. |
