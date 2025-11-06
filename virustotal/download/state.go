package download

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// State is for persisting where a feed is up to in time.
type State struct {
	path   string
	last   int64
	maxAge time.Duration
}

// NewState creates a new state saving object at the given file path.
// maxAge controls how far back in time state will return before jumping.
func NewState(path string, maxAge time.Duration) (State, error) {
	if _, err := os.Stat(path); err == nil {
		dat, _ := os.ReadFile(path)
		last, err := strconv.ParseInt(string(dat), 10, 64)
		if err != nil {
			fmt.Printf("warning - could not load last virustotal download timestamp reverting to start, error was: %v", err)
			return State{path: path, maxAge: maxAge}, nil
		}
		return State{path: path, last: last, maxAge: maxAge}, err
	} else if os.IsNotExist(err) {
		return State{path: path, maxAge: maxAge}, nil
	} else {
		return State{}, err
	}

}

// Next returns the Time for the next feed package.
// d is the time granularity of packages.
func (s *State) Next(d time.Duration) time.Time {
	t := s.Last()
	oldest := time.Now().UTC().Add(s.maxAge * -1)
	if t.Before(oldest) {
		// need to jump forward
		t = oldest
	}
	// need to truncate to correct boundary
	next := t.Truncate(d).Add(d)
	return next
}

// Update sets and persists the supplied Time.
func (s *State) Update(t time.Time) error {
	s.last = t.Unix()
	return s.Save()
}

// Save persists the current State time.
func (s *State) Save() error {
	ts := strconv.FormatInt(s.last, 10)
	err := os.WriteFile(s.path, []byte(ts), 0644)
	return err
}

// Last returns the last saved State time.
func (s *State) Last() time.Time {
	return time.Unix(s.last, 0).UTC()
}
