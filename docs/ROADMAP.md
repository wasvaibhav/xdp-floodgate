# Roadmap

Phase 1 is the XDP data plane: per-source-IP GCRA limits, a SYN-specific
limit, a node-wide PPS cap, per-CPU counters and a CLI. The phases below
build outward from it. The order matters: the data plane keeps enforcing
the last known policy when any userspace component dies.

All six phases are implemented. This file is kept as the design record.

## Phase 2 — trust

- Source allowlist stored in an LPM trie: IPv4 and IPv6 CIDRs.
- Allowlisted sources use a second, trusted set of per-IP and SYN limits
  instead of the default class, so operators can tighten the default
  without punishing health checkers, monitoring or partners.
- The node-wide cap still applies to trusted traffic.
- CLI: `allow`, `deny`, `allowlist`, plus `-trusted-*` limit flags.

## Phase 3 — local control plane

- `floodgate serve`: JSON over a root-owned Unix socket.
- Read status, replace limits, add/remove allowlist entries.
- The socket is optional at runtime; the pinned data plane keeps working
  while the daemon is down, restarted or upgraded.
- One writer at a time (file lock), so `set-limit` and the API cannot
  lose updates.

## Phase 4 — observability

- Prometheus text exposition on the same Unix socket.
- Metrics for every verdict, bytes, live limits, allowlist size and the
  timestamp of the last successful policy apply.
- `status -json` for scripts and tests.

## Phase 5 — fleet coordination

- Pull-based agent: `floodgate agent -source <url|file> -token <secret>`.
- A policy bundle carries limits and allowlist entries. The agent
  validates the whole bundle before touching any map, then applies a
  converging diff; on fetch, parse or validation errors it keeps the last
  known-good policy and reports the failure. No invalid bundle is ever
  partially applied.
- Token authenticated; TLS is handled by the URL (`https://`).
- No consensus, gossip or database: the source of truth is a file or an
  HTTP endpoint managed by existing orchestration (Ansible, Kubernetes,
  object storage).

## Phase 6 — encapsulated traffic and deployment

- Parse one level of IP-in-IP (IPv4 and IPv6), so clients behind Katran
  are limited by their real source address. This is opt-in (`-decap`):
  the inner source is trusted, so tunnels must be filtered at the edge.
- systemd unit, install target and a container healthcheck.
- Release artifacts built from the same commit as the image.
- See [05-deployment.md](05-deployment.md).
