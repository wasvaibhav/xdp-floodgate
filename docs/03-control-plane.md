# Local control plane and metrics

`floodgate serve` exposes the pinned maps over a root-owned Unix socket.
It is optional: the XDP program is attached and its maps are pinned, so
the last policy keeps being enforced while the daemon is down, being
restarted or upgraded.

```sh
floodgate serve                  # /run/floodgate.sock, mode 0600
floodgate serve -socket /tmp/fg.sock
```

The daemon refuses to start unless the data plane is already pinned
(`floodgate start` first). It exits cleanly on SIGINT/SIGTERM and removes
the socket. A stale socket is replaced; a live one is not.

## Why a Unix socket

- No TCP listener, no port to firewall, no remote unauthenticated API.
- File permissions are the authentication: only root can open the socket.
- HTTP/JSON needs no new dependency and is easy to drive from scripts,
  Prometheus or a sidecar.

For remote access, put an authenticating reverse proxy in front of a
relayed socket. Floodgate itself does not speak TLS.

## API

All bodies are JSON; unknown fields are rejected (400) so typos do not
silently disable a limit. Bodies are capped at 1 MiB.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | `200 ok` when the pinned maps are readable, `503` otherwise |
| GET | `/v1/status` | Limits, verdict counters, allowlist, `applied_at`, `decap` |
| PUT | `/v1/limits` | Replace all limits |
| GET | `/v1/allowlist` | `{"allowlist":["192.0.2.0/24", ...]}` |
| POST | `/v1/allowlist` | Add `{"cidr":"192.0.2.0/24"}` |
| DELETE | `/v1/allowlist?cidr=192.0.2.0%2F24` | Remove an entry |
| GET | `/v1/metrics` | Prometheus text exposition |

`PUT /v1/limits` replaces the whole limit set; a missing object means
zero (off):

```sh
curl --unix-socket /run/floodgate.sock -X PUT http://localhost/v1/limits \
  -H 'Content-Type: application/json' -d '{
    "ip":         {"rate": 500,  "burst": 1000},
    "syn":        {"rate": 25,   "burst": 50},
    "trusted_ip": {"rate": 5000, "burst": 10000},
    "trusted_syn":{"rate": 250,  "burst": 500},
    "global":     {"rate": 0,    "burst": 0}
  }'
```

Mutations return the new snapshot, so a client never needs a second
request to confirm the applied state.

## One writer at a time

`set-limit` reads the live limits, applies flags and writes them back.
The API can do the same concurrently. Both take an exclusive `flock` on
`/run/floodgate.lock` around the read-modify-write, so neither can
silently undo the other. Allowlist operations are single map writes and
do not need the lock.

## Metrics

`GET /v1/metrics` returns Prometheus text format:

```
floodgate_packets_total{verdict="pass"} 1234
floodgate_packets_total{verdict="drop_ip"} 17
floodgate_packets_total{verdict="drop_syn"} 2
floodgate_packets_total{verdict="drop_global"} 0
floodgate_packets_total{verdict="not_ip"} 40
floodgate_bytes_total{verdict="pass"} 98765
floodgate_limit_rate_per_second{limit="per_ip"} 1000
floodgate_limit_rate_per_second{limit="syn"} 50
floodgate_limit_rate_per_second{limit="trusted_ip"} 0
floodgate_limit_rate_per_second{limit="trusted_syn"} 0
floodgate_limit_rate_per_second{limit="global"} 0
floodgate_limit_burst{limit="per_ip"} 2000
floodgate_allowlist_entries 1
floodgate_policy_applied_timestamp_seconds 1700000000
```

- Verdict counters are monotonic except across a `stop`/`start`, which
  recreates the maps.
- `trusted_*` limits of `0` mean allowlisted sources are unlimited
  within their class; the global cap still applies.
- `floodgate_policy_applied_timestamp_seconds` changes on every successful
  limits or allowlist write. Alert if it stops advancing while your
  automation believes it is deploying policy.

## Scripting

`floodgate status -json` prints the same snapshot without the daemon:

```json
{
  "limits": {"ip": {"rate": 1000, "burst": 2000}, "...": {}},
  "stats": [{"verdict": "pass", "packets": 10, "bytes": 640}],
  "allowlist": ["192.0.2.0/24"],
  "applied_at": "2026-10-20T12:00:00Z",
  "decap": false
}
```

Use the socket when a long-running consumer should not race map changes;
the CLI is enough for one-shot checks.

## Limits of this design

- Single node. Fleet policy is phase 5.
- No authentication beyond socket permissions; no per-endpoint
  authorization.
- No metrics history; scrape the endpoint.
- Counters live in per-CPU maps and are summed on read, so a scrape can
  be momentarily inconsistent with a concurrent packet.
