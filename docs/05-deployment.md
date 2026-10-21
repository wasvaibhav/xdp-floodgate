# Deployment

## Encapsulated traffic (IP-in-IP)

Behind a load balancer such as Katran, packets arrive with the real
client address inside an outer IP header. By default Floodgate limits the
outer source (the load balancer). Start with `-decap` to parse one level
of IP-in-IP and use the inner source instead:

```sh
floodgate start -iface eth0 -decap -ip-rate 1000 -ip-burst 2000
```

- Outer IPv4 and IPv6 are both understood; inner IPv4 and IPv6 are both
  understood, including TCP SYN detection.
- Only one level is parsed. A second encapsulation is treated as payload.
- Fragment handling is deliberately conservative: a fragmented outer
  packet is not decapsulated, so the outer source is used. IPv6 extension
  headers are not walked, so an encapsulated packet behind an extension
  header is also limited by its outer source.
- If the inner header is malformed, the outer source is used rather than
  skipping the limit; the node-wide cap always applies.

**Trust boundary.** `-decap` trusts the inner source for allowlist and
per-IP decisions. Anyone who can send IP-in-IP to the protected interface
can claim an inner address. Only enable it on interfaces that receive
tunnels from a known load balancer, and filter IP-in-IP (IPv4 protocol 4
and 41, IPv6 next header 4 and 41) from everywhere else at the edge.

`floodgate status` and `GET /v1/status` show `decap: on|off`; the setting
is fixed at `start` and is not changed by `set-limit`, the API or a
bundle.

## systemd

Build and install the binary, unit and default file:

```sh
make
sudo make install
```

That writes:

- `/usr/local/bin/floodgate`
- `/etc/systemd/system/floodgate.service`
- `/etc/default/floodgate` (only created if absent; upgrades keep it)

Edit `/etc/default/floodgate`:

```sh
FLOODGATE_IFACE=eth0
FLOODGATE_ARGS="-generic -decap -ip-rate 1000 -ip-burst 2000"
```

Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now floodgate
systemctl status floodgate
sudo systemctl restart floodgate
```

The unit:

1. runs `floodgate stop` to clear pins from a previous instance,
2. attaches the program with `floodgate start`,
3. runs `floodgate serve` in the foreground,
4. detaches with `floodgate stop` on shutdown.

If `serve` crashes, systemd restarts the unit and the attach is redone,
so limits and counters are reset. If the machine reboots, the unit
attaches again from the same configuration. `bpffs` must be mounted at
`/sys/fs/bpf`.

`FLOODGATE_ARGS` is word-split by systemd, so flags with spaces in values
do not work; interface names and rate flags do.

The unit owns `/sys/fs/bpf/floodgate` and `/usr/local/bin/floodgate`. Do
not run a second instance against the same pins, and if you override
`PREFIX` or `SYSTEMD_DIR` in `make install`, update the paths in the unit
to match.

## Container

The image is `ghcr.io/wasvaibhav/xdp-floodgate`. It needs the host network
namespace, `--privileged` (or `CAP_BPF`, `CAP_NET_ADMIN` and a mounted
bpffs), and a long-running command so the healthcheck has something to
check:

```sh
docker run -d --name floodgate \
  --network host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --entrypoint sh \
  ghcr.io/wasvaibhav/xdp-floodgate:latest \
  -c 'floodgate stop; floodgate start -iface eth0 -generic -decap && exec floodgate serve'
```

The leading `stop` makes a container restart detach the old program
before reattaching; it also detaches any other instance using the same
pins, so run exactly one. The image healthcheck runs `floodgate status`;
it turns unhealthy when the pinned maps are gone. The control socket
lives in the container's `/run`. To use it from the host, bind-mount a
directory for the socket and pass `-socket`, or scrape through a sidecar
in the same namespace.

The XDP program is attached to the interface, not to the container's
process lifetime. A stopped container therefore leaves the data plane
running unless its command ran `floodgate stop`.

## Release artifacts

On every push to `main`, after the protected `production` environment is
approved, CI publishes:

- the image tagged `latest` and with the full commit SHA, and
- `floodgate-<sha>-linux-amd64.tar.gz` (binary, systemd unit, default
  file, README, docs) plus a SHA-256 checksum.

Both are built from the same commit. The artifact is attached to the
workflow run, not to a Git tag.

## Prometheus

If your Prometheus version supports Unix sockets in the HTTP client
configuration (for example a `unix_socket` setting), point the scrape job
at `/run/floodgate.sock`. Otherwise run a small proxy that exposes
`/v1/metrics` on a loopback port. Do not expose the control socket on a
TCP port without authentication.
