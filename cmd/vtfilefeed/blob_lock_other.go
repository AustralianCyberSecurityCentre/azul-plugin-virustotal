//go:build !linux

package vtfilefeed

import "fmt"

// lockStateFile fails closed on unsupported systems to avoid unsafe overlap.
func lockStateFile(path string) (func(), error) {
	return nil, fmt.Errorf("blob ingestion requires advisory lock support on this OS: %s", path)
}
