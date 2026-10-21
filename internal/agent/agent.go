// SPDX-License-Identifier: Apache-2.0

// Package agent pulls a policy bundle from a file or HTTP endpoint and
// applies it to the pinned maps.
//
// A bundle is validated as a whole before any map is touched. Applying is
// a converging diff: deletes, adds, then limits. If a write fails, the
// next poll recomputes the diff and finishes; no invalid bundle is ever
// partially applied. On fetch, parse or validation failure the agent
// leaves the current (last known-good) policy alone.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wasvaibhav/xdp-floodgate/internal/control"
	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
	"github.com/wasvaibhav/xdp-floodgate/internal/lockfile"
)

const maxBundle = 1 << 20

// Bundle is the policy document. Limits is required (use explicit zeroes
// to disable a limit); an empty allowlist clears it.
type Bundle struct {
	Limits    *loader.Limits `json:"limits"`
	Allowlist []string       `json:"allowlist"`
}

// Store is the map surface the agent needs. Tests replace it.
type Store interface {
	Allowlist() ([]string, error)
	Allow(string) error
	Disallow(string) error
	SetLimits(loader.Limits) error
}

type loaderStore struct{}

func (loaderStore) Allowlist() ([]string, error)    { return loader.Allowlist() }
func (loaderStore) Allow(c string) error            { return loader.Allow(c) }
func (loaderStore) Disallow(c string) error         { return loader.Disallow(c) }
func (loaderStore) SetLimits(l loader.Limits) error { return loader.SetLimits(l) }

// Agent polls one source. The zero value is not usable; call New.
type Agent struct {
	Source   string
	Token    string
	Interval time.Duration
	Store    Store
	LockPath string
	Client   *http.Client
	Logf     func(format string, args ...any)

	lastHash string
}

// New returns an agent for source. token is sent as a bearer token to
// HTTP sources and ignored for files.
func New(source, token string, interval time.Duration) *Agent {
	return &Agent{
		Source:   source,
		Token:    token,
		Interval: interval,
		Store:    loaderStore{},
		LockPath: control.DefaultLock,
		Client:   &http.Client{Timeout: 15 * time.Second},
		Logf:     log.Printf,
	}
}

// Run polls until ctx is cancelled. Fetch and validation failures are
// logged and retried; the current policy keeps being enforced.
func (a *Agent) Run(ctx context.Context) error {
	if _, err := a.validateSource(); err != nil {
		return err
	}
	if a.Interval < time.Second {
		return errors.New("interval must be at least 1s")
	}
	if err := a.poll(ctx); err != nil && ctx.Err() == nil {
		a.logf("agent: %v; keeping current policy", err)
	}
	t := time.NewTicker(a.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := a.poll(ctx); err != nil && ctx.Err() == nil {
				a.logf("agent: %v; keeping current policy", err)
			}
		}
	}
}

// Once fetches and applies one bundle. It is meant for cron, CI checks
// and tests.
func (a *Agent) Once(ctx context.Context) error {
	if _, err := a.validateSource(); err != nil {
		return err
	}
	return a.poll(ctx)
}

func (a *Agent) poll(ctx context.Context) error {
	body, err := a.fetch(ctx)
	if err != nil {
		return err
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("invalid bundle: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid bundle: trailing data")
	}
	if b.Limits == nil {
		return errors.New("invalid bundle: limits is required")
	}
	if err := loader.ValidateLimits(*b.Limits); err != nil {
		return fmt.Errorf("invalid bundle: %w", err)
	}
	want, err := canonicalAllowlist(b.Allowlist)
	if err != nil {
		return fmt.Errorf("invalid bundle: %w", err)
	}

	hash, err := bundleHash(*b.Limits, want)
	if err != nil {
		return err
	}
	if hash == a.lastHash {
		return nil
	}
	if err := a.apply(*b.Limits, want); err != nil {
		return fmt.Errorf("applying bundle: %w", err)
	}
	a.lastHash = hash
	a.logf("agent: applied policy (%d allowlist entries)", len(want))
	return nil
}

func (a *Agent) apply(lim loader.Limits, want []string) error {
	return lockfile.Do(a.LockPath, func() error {
		have, err := a.Store.Allowlist()
		if err != nil {
			return err
		}
		wantSet := make(map[string]struct{}, len(want))
		for _, c := range want {
			wantSet[c] = struct{}{}
		}
		haveSet := make(map[string]struct{}, len(have))
		for _, c := range have {
			haveSet[c] = struct{}{}
			if _, keep := wantSet[c]; !keep {
				if err := a.Store.Disallow(c); err != nil {
					return fmt.Errorf("removing %s: %w", c, err)
				}
			}
		}
		for _, c := range want {
			if _, exists := haveSet[c]; !exists {
				if err := a.Store.Allow(c); err != nil {
					return fmt.Errorf("adding %s: %w", c, err)
				}
			}
		}
		if err := a.Store.SetLimits(lim); err != nil {
			return fmt.Errorf("setting limits: %w", err)
		}
		return nil
	})
}

func (a *Agent) fetch(ctx context.Context) ([]byte, error) {
	remote, err := a.validateSource()
	if err != nil {
		return nil, err
	}
	if !remote {
		data, err := os.ReadFile(a.Source)
		if err != nil {
			return nil, err
		}
		if len(data) > maxBundle {
			return nil, fmt.Errorf("bundle is larger than %d bytes", maxBundle)
		}
		return data, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("fetch %s: %s: %s", req.URL.Redacted(), resp.Status,
			strings.TrimSpace(string(snippet)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBundle {
		return nil, fmt.Errorf("bundle is larger than %d bytes", maxBundle)
	}
	return data, nil
}

// validateSource reports whether the source is remote (HTTP) or a file.
func (a *Agent) validateSource() (remote bool, err error) {
	if a.Source == "" {
		return false, errors.New("-source is required")
	}
	u, err := url.Parse(a.Source)
	if err != nil {
		return false, fmt.Errorf("invalid source: %w", err)
	}
	if u.Scheme == "" {
		return false, nil
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false, fmt.Errorf("unsupported source scheme %q (use http, https or a file path)", u.Scheme)
	}
	if u.Host == "" {
		return false, errors.New("source URL has no host")
	}
	return true, nil
}

func canonicalAllowlist(in []string) ([]string, error) {
	set := make(map[string]struct{}, len(in))
	for _, c := range in {
		canon, err := loader.CanonicalCIDR(c)
		if err != nil {
			return nil, err
		}
		set[canon] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

func bundleHash(lim loader.Limits, allow []string) (string, error) {
	doc, err := json.Marshal(struct {
		Limits    loader.Limits `json:"limits"`
		Allowlist []string      `json:"allowlist"`
	}{lim, allow})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:]), nil
}

func (a *Agent) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}
