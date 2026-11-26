package vthuntfeed

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointDurabilityAndMonotonicity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.txt")
	state, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Update(120); err != nil {
		t.Fatal(err)
	}
	if state.Last() != 120 {
		t.Fatalf("in-memory checkpoint was not updated: %d", state.Last())
	}
	if err := state.Update(119); err == nil {
		t.Fatal("checkpoint unexpectedly moved backwards")
	}
	again, err := NewState(path)
	if err != nil || again.Last() != 120 {
		t.Fatalf("reload got %#v, %v", again, err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewState(path); err == nil {
		t.Fatal("corrupt state must be rejected")
	}
}
