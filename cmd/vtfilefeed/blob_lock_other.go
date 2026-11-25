//go:build !linux

package vtfilefeed

import "fmt"

func lockStateFile(path string) (func(), error) {
	return nil, fmt.Errorf("blob ingestion requires advisory lock support on this OS: %s", path)
}
