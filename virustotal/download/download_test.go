package download

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackage(t *testing.T) {
	dirname, err := os.MkdirTemp(os.TempDir(), "teststate")
	if err != nil {
		t.Errorf("Failed to create tempdir: %s", err)
		return
	}
	defer os.RemoveAll(dirname)

	state, _ := NewState(filepath.Join(dirname, "package"), time.Hour*999999)
	then := time.Date(2008, 11, 12, 13, 14, 15, 1234, time.UTC)
	err = (&state).Update(then)
	if err != nil {
		t.Errorf("Unable to update state")
	}
	// time hasn't gone past lag period
	s := NextMetadataPackage(then, time.Hour, &state)
	if (s != time.Time{}) {
		t.Errorf("Unexpected next package string: %s", s)
	}
	// fast forward time
	then = then.Add(time.Hour * 2)
	s = NextMetadataPackage(then, time.Hour, &state)
	if s != time.Date(2008, 11, 12, 13, 15, 0, 0, time.UTC) {
		t.Errorf("Unexpected next package string: %s", s)
	}
}
