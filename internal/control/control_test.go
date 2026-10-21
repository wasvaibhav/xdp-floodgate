// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
)

type fakeBackend struct {
	mu    sync.Mutex
	lim   loader.Limits
	allow []string
	stats []loader.Stat
}

func (f *fakeBackend) Snapshot() (loader.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return loader.Snapshot{
		Limits:    f.lim,
		Allowlist: append([]string(nil), f.allow...),
		Stats:     append([]loader.Stat(nil), f.stats...),
		Applied:   time.Unix(1_700_000_000, 0),
	}, nil
}

func (f *fakeBackend) SetLimits(l loader.Limits) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lim = l
	return nil
}

func (f *fakeBackend) Allow(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow = append(f.allow, c)
	return nil
}

func (f *fakeBackend) Disallow(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.allow {
		if a == c {
			f.allow = append(f.allow[:i], f.allow[i+1:]...)
			return nil
		}
	}
	return nil
}

func newFake() *fakeBackend {
	return &fakeBackend{
		lim:   loader.Limits{IP: loader.Limit{Rate: 1000, Burst: 2000}},
		allow: []string{"192.0.2.0/24"},
		stats: []loader.Stat{{Verdict: "pass", Packets: 10, Bytes: 640}},
	}
}

func newServer(t *testing.T, f *fakeBackend) http.Handler {
	t.Helper()
	return New(f, filepath.Join(t.TempDir(), "lock")).Handler()
}

func get(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStatus(t *testing.T) {
	h := newServer(t, newFake())
	rec := get(t, h, "GET", "/v1/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var snap loader.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Limits.IP.Rate != 1000 || len(snap.Allowlist) != 1 || snap.Stats[0].Verdict != "pass" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}

func TestPutLimits(t *testing.T) {
	f := newFake()
	h := newServer(t, f)
	body := `{"ip":{"rate":500,"burst":750},"syn":{"rate":0,"burst":0},
		"trusted_ip":{"rate":0,"burst":0},"trusted_syn":{"rate":0,"burst":0},
		"global":{"rate":0,"burst":0}}`
	rec := get(t, h, "PUT", "/v1/limits", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	got, _ := f.Snapshot()
	if got.Limits.IP.Rate != 500 || got.Limits.IP.Burst != 750 {
		t.Fatalf("limits not applied: %+v", got.Limits)
	}
}

func TestPutLimitsRejectsOverflow(t *testing.T) {
	f := newFake()
	h := newServer(t, f)
	rec := get(t, h, "PUT", "/v1/limits",
		`{"ip":{"rate":1,"burst":18446744073709551615}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got, _ := f.Snapshot(); got.Limits.IP.Rate != 1000 {
		t.Fatalf("limits changed: %+v", got.Limits)
	}
}

func TestPutLimitsRejectsUnknownField(t *testing.T) {
	f := newFake()
	h := newServer(t, f)
	rec := get(t, h, "PUT", "/v1/limits", `{"ip_rate":500}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAllowlistAddRemove(t *testing.T) {
	f := newFake()
	h := newServer(t, f)

	rec := get(t, h, "POST", "/v1/allowlist", `{"cidr":"198.51.100.7"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add status = %d, body %s", rec.Code, rec.Body)
	}
	if got, _ := f.Snapshot(); len(got.Allowlist) != 2 {
		t.Fatalf("allowlist = %v", got.Allowlist)
	}

	rec = get(t, h, "POST", "/v1/allowlist", `{"cidr":"not-a-cidr"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid add status = %d, want 400", rec.Code)
	}

	rec = get(t, h, "DELETE", "/v1/allowlist?cidr=192.0.2.0%2F24", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body %s", rec.Code, rec.Body)
	}
	if got, _ := f.Snapshot(); len(got.Allowlist) != 1 {
		t.Fatalf("allowlist after delete = %v", got.Allowlist)
	}

	rec = get(t, h, "DELETE", "/v1/allowlist", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing cidr status = %d, want 400", rec.Code)
	}
}

func TestMetrics(t *testing.T) {
	h := newServer(t, newFake())
	rec := get(t, h, "GET", "/v1/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, want := range []string{
		`floodgate_packets_total{verdict="pass"} 10`,
		`floodgate_limit_rate_per_second{limit="per_ip"} 1000`,
		`floodgate_allowlist_entries 1`,
		`floodgate_policy_applied_timestamp_seconds 1700000000`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, rec.Body)
		}
	}
}

func TestHealth(t *testing.T) {
	h := newServer(t, newFake())
	if rec := get(t, h, "GET", "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newServer(t, newFake())
	if rec := get(t, h, "GET", "/v1/limits", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestListenUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "control.sock")
	s := New(newFake(), "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, sock) }()

	waitForSocket(t, sock)
	client := unixClient(sock)
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Get("http://floodgate/v1/status")
	if err != nil {
		t.Fatalf("GET over unix socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("socket mode = %o, want 600", mode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not stop")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still exists: %v", err)
	}
}

func waitForSocket(t *testing.T, sock string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		c, err := net.Dial("unix", sock)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", sock)
}

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}
