// SPDX-License-Identifier: Apache-2.0

// floodgate: attach, inspect and tune the XDP overload filter.
//
//	floodgate start -iface eth0 [limit flags]
//	floodgate status
//	floodgate set-limit -ip-rate 500
//	floodgate stop
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/wasvaibhav/xdp-floodgate/internal/agent"
	"github.com/wasvaibhav/xdp-floodgate/internal/control"
	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
	"github.com/wasvaibhav/xdp-floodgate/internal/lockfile"
)

const usage = `usage: floodgate <start|stop|status|serve|agent|set-limit|allow|deny|allowlist> [flags]
run "floodgate <command> -h" for flags`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "start":
		err = start(args)
	case "stop":
		err = loader.Stop()
	case "status":
		err = status(args)
	case "serve":
		err = serve(args)
	case "agent":
		err = agentCmd(args)
	case "set-limit":
		err = setLimit(args)
	case "allow":
		err = allow(args)
	case "deny":
		err = deny(args)
	case "allowlist":
		err = listAllowlist()
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "floodgate:", err)
		os.Exit(1)
	}
}

// limitFlags registers the limit flags on fs, defaulting to cur.
func limitFlags(fs *flag.FlagSet, cur *loader.Limits) {
	fs.Uint64Var(&cur.IP.Rate, "ip-rate", cur.IP.Rate, "packets/sec per source IP (0 = off)")
	fs.Uint64Var(&cur.IP.Burst, "ip-burst", cur.IP.Burst, "burst per source IP, packets")
	fs.Uint64Var(&cur.SYN.Rate, "syn-rate", cur.SYN.Rate, "TCP SYNs/sec per source IP (0 = off)")
	fs.Uint64Var(&cur.SYN.Burst, "syn-burst", cur.SYN.Burst, "SYN burst per source IP")
	fs.Uint64Var(&cur.TrustedIP.Rate, "trusted-ip-rate", cur.TrustedIP.Rate, "packets/sec per allowlisted source IP (0 = off)")
	fs.Uint64Var(&cur.TrustedIP.Burst, "trusted-ip-burst", cur.TrustedIP.Burst, "burst per allowlisted source IP")
	fs.Uint64Var(&cur.TrustedSYN.Rate, "trusted-syn-rate", cur.TrustedSYN.Rate, "TCP SYNs/sec per allowlisted source IP (0 = off)")
	fs.Uint64Var(&cur.TrustedSYN.Burst, "trusted-syn-burst", cur.TrustedSYN.Burst, "SYN burst per allowlisted source IP")
	fs.Uint64Var(&cur.Global.Rate, "global-pps", cur.Global.Rate, "packets/sec for the whole node (0 = off)")
	fs.Uint64Var(&cur.Global.Burst, "global-burst", cur.Global.Burst, "node-wide burst, packets")
}

func start(args []string) error {
	// Defaults are deliberately generous: behind carrier-grade NAT hundreds
	// of real users can share one IP. Tune down per service.
	lim := loader.Limits{
		IP:  loader.Limit{Rate: 1000, Burst: 2000},
		SYN: loader.Limit{Rate: 50, Burst: 100},
	}
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	iface := fs.String("iface", "", "interface to protect (required)")
	maxIPs := fs.Uint64("max-ips", 2_000_000, "source IPs tracked; least recently seen evicted beyond this (~100 B each)")
	generic := fs.Bool("generic", false, "force generic (skb) XDP mode, for NICs/veths without native XDP")
	decap := fs.Bool("decap", false, "trust one level of IP-in-IP and limit the inner source")
	limitFlags(fs, &lim)
	fs.Parse(args)
	if *iface == "" {
		return fmt.Errorf("-iface is required")
	}
	if *maxIPs == 0 || *maxIPs > math.MaxUint32 {
		return fmt.Errorf("-max-ips must be between 1 and %d", uint64(math.MaxUint32))
	}
	if err := loader.Start(*iface, uint32(*maxIPs), *generic, *decap, lim); err != nil {
		return err
	}
	fmt.Printf("attached to %s, state pinned in %s\n", *iface, loader.PinDir)
	return nil
}

func setLimit(args []string) error {
	// Start from the live values so unspecified flags stay unchanged. The
	// lock makes that read-modify-write atomic against the control daemon.
	return lockfile.Do(control.DefaultLock, func() error {
		lim, err := loader.GetLimits()
		if err != nil {
			return fmt.Errorf("reading limits (is floodgate started?): %w", err)
		}
		fs := flag.NewFlagSet("set-limit", flag.ExitOnError)
		limitFlags(fs, &lim)
		fs.Parse(args)
		return loader.SetLimits(lim)
	})
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", control.DefaultSocket, "Unix socket path")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "floodgate: serving on %s\n", *socket)
	return control.Serve(ctx, *socket)
}

func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	source := fs.String("source", "", "bundle URL (http/https) or file path (required)")
	token := fs.String("token", os.Getenv("FLOODGATE_TOKEN"), "bearer token for HTTP sources (default $FLOODGATE_TOKEN)")
	interval := fs.Duration("interval", 30*time.Second, "poll interval")
	once := fs.Bool("once", false, "apply one bundle and exit")
	fs.Parse(args)
	if *source == "" {
		return fmt.Errorf("-source is required")
	}
	if _, err := loader.ReadSnapshot(); err != nil {
		return fmt.Errorf("not running? %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := agent.New(*source, *token, *interval)
	if *once {
		return a.Once(ctx)
	}
	return a.Run(ctx)
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full snapshot as JSON")
	fs.Parse(args)

	snap, err := loader.ReadSnapshot()
	if err != nil {
		return fmt.Errorf("not running? %w", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LIMIT\tRATE/s\tBURST")
	for _, l := range []struct {
		name string
		loader.Limit
	}{
		{"per-ip", snap.Limits.IP},
		{"syn", snap.Limits.SYN},
		{"trusted-ip", snap.Limits.TrustedIP},
		{"trusted-syn", snap.Limits.TrustedSYN},
		{"global", snap.Limits.Global},
	} {
		fmt.Fprintf(w, "%s\t%s\t%d\n", l.name, rate(l.Rate), l.Burst)
	}
	fmt.Fprintln(w, "\nVERDICT\tPACKETS\tBYTES")
	for _, st := range snap.Stats {
		fmt.Fprintf(w, "%s\t%d\t%d\n", st.Verdict, st.Packets, st.Bytes)
	}
	fmt.Fprintf(w, "\nallowlist: %d entries\n", len(snap.Allowlist))
	fmt.Fprintf(w, "decap: %s\n", onOff(snap.Decap))
	return w.Flush()
}

func rate(r uint64) string {
	if r == 0 {
		return "off"
	}
	return fmt.Sprint(r)
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func allow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: floodgate allow <ip|cidr>")
	}
	if err := loader.Allow(args[0]); err != nil {
		return err
	}
	fmt.Printf("allowlisted %s\n", args[0])
	return nil
}

func deny(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: floodgate deny <ip|cidr>")
	}
	return loader.Disallow(args[0])
}

func listAllowlist() error {
	entries, err := loader.Allowlist()
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Println(e)
	}
	return nil
}
