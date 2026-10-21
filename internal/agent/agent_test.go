// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
)

type fakeStore struct {
	mu        sync.Mutex
	allow     []string
	lim       loader.Limits
	allowN    int
	disallowN int
	setN      int
}

func (f *fakeStore) Allowlist() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.allow...), nil
}

func (f *fakeStore) Allow(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow = append(f.allow, c)
	f.allowN++
	return nil
}

func (f *fakeStore) Disallow(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.allow {
		if a == c {
			f.allow = append(f.allow[:i], f.allow[i+1:]...)
			break
		}
	}
	f.disallowN++
	return nil
}

func (f *fakeStore) SetLimits(l loader.Limits) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lim = l
	f.setN++
	return nil
}

func (f *fakeStore) state() (allow []string, lim loader.Limits, allowN, disallowN, setN int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.allow...), f.lim, f.allowN, f.disallowN, f.setN
}

const testBundle = `{
  "limits": {"ip": {"rate": 25, "burst": 50}},
  "allowlist": ["198.51.100.7", "198.51.100.7/32", "2001:db8::/32"]
}`

func newTestAgent(source string, store Store) *Agent {
	a := New(source, "s3cret", 30*time.Second)
	a.Store = store
	a.LockPath = filepath.Join(os.TempDir(), "floodgate-agent-test.lock")
	a.Logf = tLogf
	return a
}

func tLogf(string, ...any) {}

func TestOnceHTTP(t *testing.T) {
	var gotAuth, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		io.WriteString(w, testBundle)
	}))
	defer srv.Close()

	store := &fakeStore{allow: []string{"192.0.2.0/24"}}
	a := newTestAgent(srv.URL, store)
	if err := a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer s3cret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	allow, lim, allowN, disallowN, setN := store.state()
	want := []string{"198.51.100.7/32", "2001:db8::/32"}
	if !reflect.DeepEqual(allow, want) {
		t.Errorf("allowlist = %v, want %v", allow, want)
	}
	if lim.IP.Rate != 25 || lim.IP.Burst != 50 {
		t.Errorf("limits = %+v", lim)
	}
	if allowN != 2 || disallowN != 1 || setN != 1 {
		t.Errorf("calls: allow=%d disallow=%d set=%d", allowN, disallowN, setN)
	}

	// Same bundle: skip the writes.
	if err := a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, allowN, disallowN, setN := store.state(); allowN != 2 || disallowN != 1 || setN != 1 {
		t.Errorf("unchanged bundle reapplied: allow=%d disallow=%d set=%d", allowN, disallowN, setN)
	}
}

func TestOnceFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(testBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	a := newTestAgent(path, store)
	if err := a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, lim, _, _, _ := store.state(); lim.IP.Rate != 25 {
		t.Fatalf("limits = %+v", lim)
	}
}

func TestRejectsBadBundles(t *testing.T) {
	for name, body := range map[string]string{
		"missing limits": `{"allowlist":["192.0.2.0/24"]}`,
		"unknown field":  `{"limits":{"ip":{"rate":1,"burst":1}},"allow_list":[]}`,
		"bad cidr":       `{"limits":{"ip":{"rate":1,"burst":1}},"allowlist":["nope"]}`,
		"overflow":       `{"limits":{"ip":{"rate":1,"burst":18446744073709551615}}}`,
		"trailing data":  `{"limits":{"ip":{"rate":1,"burst":1}}} {}`,
		"not json":       `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, body)
			}))
			defer srv.Close()
			store := &fakeStore{allow: []string{"192.0.2.0/24"}}
			a := newTestAgent(srv.URL, store)
			if err := a.Once(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
			allow, lim, allowN, disallowN, setN := store.state()
			if len(allow) != 1 || allow[0] != "192.0.2.0/24" || lim != (loader.Limits{}) || allowN+disallowN+setN != 0 {
				t.Errorf("state changed on invalid bundle: %v %+v calls=%d/%d/%d",
					allow, lim, allowN, disallowN, setN)
			}
		})
	}
}

func TestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	a := newTestAgent(srv.URL, &fakeStore{})
	err := a.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestSourceValidation(t *testing.T) {
	for _, source := range []string{"", "ftp://example.com/bundle", "http://"} {
		a := newTestAgent(source, &fakeStore{})
		if err := a.Once(context.Background()); err == nil {
			t.Errorf("source %q accepted", source)
		}
	}
}

func TestRunAppliesAndStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testBundle)
	}))
	defer srv.Close()
	store := &fakeStore{}
	a := newTestAgent(srv.URL, store)
	a.Interval = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, lim, _, _, _ := store.state(); lim.IP.Rate == 25 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not apply the bundle")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}
