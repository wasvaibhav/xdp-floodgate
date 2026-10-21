// SPDX-License-Identifier: Apache-2.0

// Package control exposes the pinned data plane over a root-owned Unix
// socket: status, live limits, allowlist edits and Prometheus metrics.
//
// The daemon is optional. Maps and the XDP link are pinned, so the data
// plane keeps enforcing the last policy while this process is down.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
	"github.com/wasvaibhav/xdp-floodgate/internal/lockfile"
)

const (
	// DefaultSocket is the local control socket.
	DefaultSocket = "/run/floodgate.sock"
	// DefaultLock serializes limit changes across processes.
	DefaultLock = "/run/floodgate.lock"
)

// Backend is the subset of the loader the API needs.
type Backend interface {
	Snapshot() (loader.Snapshot, error)
	SetLimits(loader.Limits) error
	Allow(string) error
	Disallow(string) error
}

type loaderBackend struct{}

func (loaderBackend) Snapshot() (loader.Snapshot, error) { return loader.ReadSnapshot() }
func (loaderBackend) SetLimits(l loader.Limits) error    { return loader.SetLimits(l) }
func (loaderBackend) Allow(c string) error               { return loader.Allow(c) }
func (loaderBackend) Disallow(c string) error            { return loader.Disallow(c) }

// Server serves the local API. An empty LockPath disables cross-process
// locking, which tests use.
type Server struct {
	Backend
	LockPath string
}

// New returns a control server for b.
func New(b Backend, lockPath string) *Server {
	return &Server{Backend: b, LockPath: lockPath}
}

// Serve runs the local API on socket until ctx is cancelled. It refuses
// to start unless the data plane is already pinned.
func Serve(ctx context.Context, socket string) error {
	if _, err := loader.ReadSnapshot(); err != nil {
		return fmt.Errorf("reading data plane: %w", err)
	}
	return New(loaderBackend{}, DefaultLock).Listen(ctx, socket)
}

// Listen serves the API on a Unix socket. The socket is mode 0600 and is
// removed on return.
func (s *Server) Listen(ctx context.Context, socket string) error {
	ln, err := listen(socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socket)

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdown)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func listen(socket string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(socket); err == nil {
		// A live socket means another daemon; a stale one is safe to remove.
		c, derr := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if derr == nil {
			c.Close()
			return nil, fmt.Errorf("%s is already in use", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Handler returns the HTTP routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("PUT /v1/limits", s.putLimits)
	mux.HandleFunc("GET /v1/allowlist", s.getAllowlist)
	mux.HandleFunc("POST /v1/allowlist", s.addAllow)
	mux.HandleFunc("DELETE /v1/allowlist", s.removeAllow)
	mux.HandleFunc("GET /v1/metrics", s.metrics)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	if _, err := s.Snapshot(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	fmt.Fprintln(w, "ok")
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) putLimits(w http.ResponseWriter, r *http.Request) {
	var lim loader.Limits
	if err := decodeBody(r, &lim); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := loader.ValidateLimits(lim); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := lockfile.Do(s.LockPath, func() error { return s.SetLimits(lim) }); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.status(w, r)
}

func (s *Server) getAllowlist(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"allowlist": snap.Allowlist})
}

func (s *Server) addAllow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := loader.ValidateCIDR(req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Allow(req.CIDR); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.status(w, r)
}

func (s *Server) removeAllow(w http.ResponseWriter, r *http.Request) {
	cidr := r.URL.Query().Get("cidr")
	if err := loader.ValidateCIDR(cidr); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Disallow(cidr); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.status(w, r)
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, snap)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON: trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeMetrics(w io.Writer, s loader.Snapshot) {
	fmt.Fprintln(w, "# HELP floodgate_packets_total Packets by XDP verdict.")
	fmt.Fprintln(w, "# TYPE floodgate_packets_total counter")
	for _, st := range s.Stats {
		fmt.Fprintf(w, "floodgate_packets_total{verdict=%q} %d\n", st.Verdict, st.Packets)
	}
	fmt.Fprintln(w, "# HELP floodgate_bytes_total Bytes by XDP verdict.")
	fmt.Fprintln(w, "# TYPE floodgate_bytes_total counter")
	for _, st := range s.Stats {
		fmt.Fprintf(w, "floodgate_bytes_total{verdict=%q} %d\n", st.Verdict, st.Bytes)
	}
	fmt.Fprintln(w, "# HELP floodgate_limit_rate_per_second Configured rate per second (0 = off).")
	fmt.Fprintln(w, "# TYPE floodgate_limit_rate_per_second gauge")
	for _, e := range limitEntries(s.Limits) {
		fmt.Fprintf(w, "floodgate_limit_rate_per_second{limit=%q} %d\n", e.name, e.limit.Rate)
	}
	fmt.Fprintln(w, "# HELP floodgate_limit_burst Configured burst in packets.")
	fmt.Fprintln(w, "# TYPE floodgate_limit_burst gauge")
	for _, e := range limitEntries(s.Limits) {
		fmt.Fprintf(w, "floodgate_limit_burst{limit=%q} %d\n", e.name, e.limit.Burst)
	}
	fmt.Fprintln(w, "# HELP floodgate_allowlist_entries Trusted allowlist prefixes.")
	fmt.Fprintln(w, "# TYPE floodgate_allowlist_entries gauge")
	fmt.Fprintf(w, "floodgate_allowlist_entries %d\n", len(s.Allowlist))
	applied := int64(0)
	if !s.Applied.IsZero() {
		applied = s.Applied.Unix()
	}
	fmt.Fprintln(w, "# HELP floodgate_policy_applied_timestamp_seconds Unix time of the last successful policy write.")
	fmt.Fprintln(w, "# TYPE floodgate_policy_applied_timestamp_seconds gauge")
	fmt.Fprintf(w, "floodgate_policy_applied_timestamp_seconds %d\n", applied)
}

func limitEntries(l loader.Limits) []struct {
	name  string
	limit loader.Limit
} {
	return []struct {
		name  string
		limit loader.Limit
	}{
		{"per_ip", l.IP},
		{"syn", l.SYN},
		{"trusted_ip", l.TrustedIP},
		{"trusted_syn", l.TrustedSYN},
		{"global", l.Global},
	}
}
