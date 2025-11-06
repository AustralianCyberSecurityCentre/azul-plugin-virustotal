package vthuntfeed

import (
	"fmt"
	"os"
	"strconv"
)

type State struct {
	path string
	last uint64
}

// NewState creates a new state saving object at the given file path.
func NewState(path string) (State, error) {
	if _, err := os.Stat(path); err == nil {
		dat, _ := os.ReadFile(path)
		last, err := strconv.ParseUint(string(dat), 10, 64)
		if err != nil {
			fmt.Printf("warning - could not load last vthuntfeed timestamp reverting to start, error was: %v", err)
			return State{path: path}, nil
		}
		return State{path: path, last: last}, err
	} else if os.IsNotExist(err) {
		return State{path: path}, nil
	} else {
		return State{}, err
	}

}

// After returns whether the specified timestamp is greater than current stored value.
func (s State) After(ts uint64) bool {
	return s.last > ts
}

// Update sets and persists the timestamp state.
func (s State) Update(ts uint64) error {
	t := strconv.FormatUint(ts, 10)
	err := os.WriteFile(s.path, []byte(t), 0644)
	return err
}
