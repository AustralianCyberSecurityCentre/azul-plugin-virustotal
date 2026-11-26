package vtfilefeed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vthuntfeed"
)

// DeferredBlob describes an hour that was passed by the primary watermark but
// still requires a later retry. It is intentionally persisted across runs.
type DeferredBlob struct {
	Hour      int64     `json:"hour"`
	Reason    string    `json:"reason"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error"`
	UpdatedAt time.Time `json:"updated_at"`
}

// deferredBlobLedger tracks hours skipped by the main checkpoint so late
// arrivals can be retried without rewinding that checkpoint.
type deferredBlobLedger struct {
	path    string
	entries map[int64]DeferredBlob
}

// loadDeferredBlobLedger validates persisted entries rather than discarding
// corrupt recovery state and losing pending hours.
func loadDeferredBlobLedger(path string) (*deferredBlobLedger, error) {
	l := &deferredBlobLedger{path: path, entries: make(map[int64]DeferredBlob)}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read deferred blob ledger: %w", err)
	}
	if err := json.Unmarshal(b, &l.entries); err != nil {
		return nil, fmt.Errorf("invalid deferred blob ledger %s: %w", path, err)
	}
	if l.entries == nil {
		return nil, fmt.Errorf("invalid deferred blob ledger %s: null is not a ledger", path)
	}
	for hour, entry := range l.entries {
		if hour != entry.Hour || hour < 0 || time.Unix(hour, 0).UTC().Truncate(time.Hour).Unix() != hour {
			return nil, fmt.Errorf("invalid deferred blob ledger entry for hour %d", hour)
		}
	}
	return l, nil
}

func (l *deferredBlobLedger) save() error {
	b, err := json.MarshalIndent(l.entries, "", "  ")
	if err != nil {
		return err
	}
	return vthuntfeed.AtomicWriteFile(l.path, append(b, '\n'), 0644)
}

// deferHour persists an unresolved hour and its latest retry information.
func (l *deferredBlobLedger) deferHour(hour time.Time, reason string, failure error, now time.Time) error {
	key := hour.Unix()
	old := l.entries[key]
	detail := ""
	if failure != nil {
		detail = failure.Error()
	}
	l.entries[key] = DeferredBlob{Hour: key, Reason: reason, Attempts: old.Attempts + 1, LastError: detail, UpdatedAt: now}
	return l.save()
}

// resolve removes a recovered hour only after the updated ledger is saved.
func (l *deferredBlobLedger) resolve(hour time.Time) error {
	key := hour.Unix()
	prior, ok := l.entries[key]
	if !ok {
		return nil
	}
	delete(l.entries, key)
	if err := l.save(); err != nil {
		l.entries[key] = prior
		return err
	}
	return nil
}

// eligible returns pending hours within the recovery window, oldest first.
func (l *deferredBlobLedger) eligible(now time.Time, recovery time.Duration) []time.Time {
	var hours []time.Time
	for h := range l.entries {
		hour := time.Unix(h, 0).UTC()
		if !hour.After(now) && now.Sub(hour) <= recovery {
			hours = append(hours, hour)
		}
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i].Before(hours[j]) })
	return hours
}

// unresolvedOutsideWindow exposes hours too old for automatic recovery.
func (l *deferredBlobLedger) unresolvedOutsideWindow(now time.Time, recovery time.Duration) []DeferredBlob {
	var skipped []DeferredBlob
	for _, entry := range l.entries {
		if now.Sub(time.Unix(entry.Hour, 0)) > recovery {
			skipped = append(skipped, entry)
		}
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Hour < skipped[j].Hour })
	return skipped
}

// lockBlobState guards checkpoint and ledger writes against overlapping runs.
func lockBlobState(dir string) (func(), error) {
	// Use the same advisory lock for the full run, including any publishing.
	return lockStateFile(filepath.Join(dir, ".ingestion.lock"))
}
