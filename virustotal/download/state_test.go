package download

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestState(t *testing.T) {
	dirname, err := os.MkdirTemp(os.TempDir(), "teststate")
	if err != nil {
		t.Errorf("Failed to create tempdir: %s", err)
		return
	}
	defer os.RemoveAll(dirname)

	// relative to now
	age := time.Hour * 5
	s, err := NewState(filepath.Join(dirname, "relative"), age)
	if err != nil {
		t.Errorf("Unable to create statefile in %s", dirname)
	}
	n := s.Next(time.Minute)
	if n.Second() > 0 {
		t.Errorf("Time not truncated to minute boundary %s", n)
	}
	if n.Before(time.Now().Add(age * -1)) {
		t.Errorf("New time not limited to max age %s", n)
	}
	if time.Now().UTC().Before(n) {
		t.Errorf("New time in future %s", n)
	}

	err = s.Update(n)
	if err != nil {
		t.Errorf("Unable to update statefile")
	}
	// reload and see if persisted as expected
	s2, err := NewState(filepath.Join(dirname, "relative"), age)
	if err != nil {
		t.Errorf("Unable to load reload state")
	}
	n2 := s2.Next(time.Minute)
	if !n.Add(time.Minute).Equal(n2) {
		t.Errorf("Reloaded time did not resume from previous got: %s", n)
	}

	// Try and set state to empty
	err = os.WriteFile(s.path, []byte{}, 0644)
	if err != nil {
		t.Errorf("Unable to zero out statefile.")
	}
	_, err = NewState(filepath.Join(dirname, "relative"), age)
	if err != nil {
		t.Errorf("Unable to load reload state %v", err)
	}

}
