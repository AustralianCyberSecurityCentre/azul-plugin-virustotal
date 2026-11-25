package vthuntfeed

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type State struct {
	path string
	last uint64
}

// NewState loads the last successfully committed timestamp. Corrupt state is an
// error, not a reason to silently replay an arbitrary history window.
func NewState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{path: path}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("reading checkpoint %s: %w", path, err)
	}
	last, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return State{}, fmt.Errorf("invalid checkpoint %s: %w", path, err)
	}
	return State{path: path, last: last}, nil
}

// After reports whether the checkpoint is newer than ts.
func (s State) After(ts uint64) bool { return s.last > ts }

// Last returns the committed checkpoint timestamp.
func (s State) Last() uint64 { return s.last }

// Update atomically persists and updates the in-memory checkpoint. It refuses
// to move backwards; callers must use an explicit recovery procedure to rewind.
func (s *State) Update(ts uint64) error {
	if ts < s.last {
		return fmt.Errorf("checkpoint rewind refused: %d < %d", ts, s.last)
	}
	if err := AtomicWriteFile(s.path, []byte(strconv.FormatUint(ts, 10)+"\n"), 0644); err != nil {
		return err
	}
	s.last = ts
	return nil
}

// AtomicWriteFile writes a durable replacement using a same-directory temporary
// file and fsyncs both data and the directory after rename.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
