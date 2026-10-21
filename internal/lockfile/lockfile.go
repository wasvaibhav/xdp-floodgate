// SPDX-License-Identifier: Apache-2.0

// Package lockfile serializes writers across processes with flock(2).
// Floodgate's CLI and control daemon both read-modify-write the live
// limits; without a lock, two concurrent updates can lose one.
package lockfile

import (
	"os"
	"syscall"
)

// Do runs fn while holding an exclusive lock on path, creating the file
// if needed. An empty path means no locking.
func Do(path string, fn func() error) error {
	if path == "" {
		return fn()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
