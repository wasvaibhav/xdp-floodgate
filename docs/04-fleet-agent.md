# Fleet agent

`floodgate agent` pulls a policy bundle from a file or an HTTP(S) endpoint
and applies it to the pinned maps. It is a pull loop, not a control
channel: the source of truth stays in your existing orchestration (a Git
repo, object storage, Ansible, a ConfigMap exporter), and the agent only
reads it.

```sh
floodgate agent -source /etc/floodgate/bundle.json
floodgate agent -source https://policy.example/bundle.json -interval 15s
FLOODGATE_TOKEN=... floodgate agent -source https://policy.example/bundle.json
```

The daemon is not needed. `agent` talks to the pinned maps directly and
takes the same file lock as `set-limit` and the API, so it cannot lose a
concurrent operator change to an in-flight bundle.

## Bundle

```json
{
  "limits": {
    "ip":          {"rate": 1000, "burst": 2000},
    "syn":         {"rate": 50,   "burst": 100},
    "trusted_ip":  {"rate": 5000, "burst": 10000},
    "trusted_syn": {"rate": 250,  "burst": 500},
    "global":      {"rate": 0,    "burst": 0}
  },
  "allowlist": ["192.0.2.0/24", "2001:db8::/32"]
}
```

- `limits` is required. Use explicit zeroes to disable a limit; omitting
  the key is rejected so a truncated document cannot silently remove all
  protection.
- A missing sub-limit object means zero (off), matching `PUT /v1/limits`.
- An empty or missing `allowlist` clears it. Entries are canonicalised,
  deduplicated and sorted, so `192.0.2.7`, `192.0.2.7/32` and a different
  ordering are the same policy.
- Unknown fields are rejected.
- Maximum size is 1 MiB.

## Applying

1. Fetch the document (file read or HTTP GET).
2. Parse strictly and validate every limit (including GCRA overflow) and
   every CIDR.
3. Hash the canonical policy. If it equals the last applied hash, do
   nothing.
4. Under the file lock, diff the allowlist (remove, add) and write the
   limits.

The bundle is validated as a whole before any map changes, so an invalid
document is never partially applied. If a map write fails midway, the
agent logs the error and the next poll recomputes the diff; the policy
converges without operator intervention. This is a converging apply, not
a transaction across three BPF maps: a packet arriving between writes can
see the new allowlist with the old limits for a moment.

On fetch, parse or validation failure the agent keeps the current policy,
which is the last known-good bundle (or a manual CLI/API policy). Failures
are written to stderr, so systemd/journald captures them.

`floodgate status -json` shows `applied_at`; `GET /v1/metrics` exposes
`floodgate_policy_applied_timestamp_seconds`. Alert if that timestamp
stops advancing while your deployment system believes it is publishing.

## Authentication

- HTTP `Authorization: Bearer <token>` is sent when a token is set.
- Prefer the `FLOODGATE_TOKEN` environment variable over `-token`; command
  lines are visible in `ps`.
- Use `https://`. There is no insecure-skip-verify option.
- Do not put the token in the URL; it ends up in logs and proxies.
- File sources are protected by filesystem permissions. The agent runs as
  root because it opens BPF maps; keep the bundle readable only by root.

## Scheduling

Long-running mode polls every `-interval` (default 30s, minimum 1s) and
applies on first poll, then only on change. `-once` fetches once and exits
non-zero on failure, for a systemd timer or CI smoke test:

```sh
floodgate agent -source /etc/floodgate/bundle.json -once
```

SIGINT/SIGTERM stop the loop; the XDP program and its maps are untouched.
