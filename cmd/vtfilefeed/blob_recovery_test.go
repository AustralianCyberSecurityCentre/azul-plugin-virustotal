package vtfilefeed

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vthuntfeed"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/stretchr/testify/require"
)

// TestDeferredBlobLedgerRoundtrip verifies pending hours survive restarts
// and disappear after successful recovery.
func TestDeferredBlobLedgerRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deferred_hours.json")
	ledger, err := loadDeferredBlobLedger(path)
	require.NoError(t, err)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	hour := now.Add(-5 * time.Hour)
	require.NoError(t, ledger.deferHour(hour, "missing", nil, now))
	restored, err := loadDeferredBlobLedger(path)
	require.NoError(t, err)
	require.Len(t, restored.eligible(now, 48*time.Hour), 1)
	require.Empty(t, restored.unresolvedOutsideWindow(now, 48*time.Hour))
	require.NoError(t, restored.deferHour(hour, "test", errors.New("later error"), now))
	require.Equal(t, 2, restored.entries[hour.Unix()].Attempts)
	require.NoError(t, restored.resolve(hour))
	restored, err = loadDeferredBlobLedger(path)
	require.NoError(t, err)
	require.Empty(t, restored.entries)
}

// TestBlobDoesNotCheckpointBeforePublisherAcknowledges guards against
// losing a failed hour when Dispatcher does not accept its events.
func TestBlobDoesNotCheckpointBeforePublisherAcknowledges(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previous := hour.Add(-time.Hour)
	seedBlobState(t, stateDir, previous)
	body := testTarBZ2(t)
	etag := `"stable"`
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != blobRequestPath(hour) {
			t.Errorf("unexpected blob %s", r.URL.Path)
		}
		if r.Method == http.MethodHead {
			writeBlobProperties(w, now.Add(-time.Hour), etag, len(body))
			return
		}
		writeBlobDownload(w, body, now.Add(-time.Hour), etag)
	}))
	err := runBlobDownloadWithPublisher(client, now, func(body io.ReadCloser, name string) (int, error) {
		defer body.Close()
		_, _ = io.Copy(io.Discard, body)
		return 2, fmtDispatcherFailure()
	})
	require.ErrorIs(t, err, errDispatcherIngest)
	require.Equal(t, uint64(previous.Unix()), readBlobState(t, stateDir))
	require.Empty(t, readDeferredLedger(t, stateDir).entries)
}

func fmtDispatcherFailure() error {
	return errors.Join(errDispatcherIngest, errors.New("publish failed"))
}

func readDeferredLedger(t *testing.T, dir string) *deferredBlobLedger {
	t.Helper()
	ledger, err := loadDeferredBlobLedger(filepath.Join(dir, "blob_files", "deferred_hours.json"))
	require.NoError(t, err)
	return ledger
}

// TestFutureCheckpointIsRejectedWithoutAzureRequest prevents silently
// rewinding invalid state or contacting Azure with an invalid checkpoint.
func TestFutureCheckpointIsRejectedWithoutAzureRequest(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	future := now.Truncate(time.Hour).Add(5 * time.Hour)
	path := filepath.Join(stateDir, "blob_files", "state.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	state, err := vthuntfeed.NewState(path)
	require.NoError(t, err)
	require.NoError(t, state.Update(uint64(future.Unix())))
	requests := 0
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(500) }))
	err = runBlobDownloadWithPublisher(client, now, func(io.ReadCloser, string) (int, error) { return 1, nil })
	require.ErrorContains(t, err, "exceeds latest eligible")
	require.Zero(t, requests)
}

// TestDeferredMissingHourRecoveredNextRun verifies a late upload can
// be recovered after the main checkpoint moves past its hour.
func TestDeferredMissingHourRecoveredNextRun(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	missing := now.Truncate(time.Hour).Add(-3 * time.Hour)
	available := missing.Add(time.Hour)
	seedBlobState(t, stateDir, missing.Add(-time.Hour))
	body := testTarBZ2(t)
	etag := `"stable"`
	missingAvailable := false
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == blobRequestPath(missing) && !missingAvailable {
			writeAzureError(w, http.StatusNotFound, "BlobNotFound")
			return
		}
		if r.Method == http.MethodHead {
			writeBlobProperties(w, now.Add(-time.Hour), etag, len(body))
			return
		}
		writeBlobDownload(w, body, now.Add(-time.Hour), etag)
	}))
	publish := func(body io.ReadCloser, name string) (int, error) {
		defer body.Close()
		_, err := io.Copy(io.Discard, body)
		return 2, err
	}
	require.NoError(t, runBlobDownloadWithPublisher(client, now, publish))
	require.Equal(t, uint64(available.Unix()), readBlobState(t, stateDir))
	require.Contains(t, readDeferredLedger(t, stateDir).entries, missing.Unix())
	missingAvailable = true
	// Stay within the same eligibility window: this run should recover the
	// deferred blob without ingesting an additional newly eligible hour.
	require.NoError(t, runBlobDownloadWithPublisher(client, now.Add(10*time.Minute), publish))
	require.NotContains(t, readDeferredLedger(t, stateDir).entries, missing.Unix())
	require.Equal(t, uint64(available.Unix()), readBlobState(t, stateDir))
}

// TestBlobStateLockIsExclusive prevents overlapping ingestion runs.
func TestBlobStateLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	release, err := lockBlobState(dir)
	require.NoError(t, err)
	defer release()
	_, err = lockBlobState(dir)
	require.Error(t, err)
}

// TestInvalidDeferredLedgerDoesNotReset ensures corrupt recovery state
// stops processing instead of silently losing deferred work.
func TestInvalidDeferredLedgerDoesNotReset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deferred_hours.json")
	require.NoError(t, os.WriteFile(path, []byte("bad"), 0600))
	_, err := loadDeferredBlobLedger(path)
	require.Error(t, err)
}

// TestBlobStartTimeHardLimitedTo72Hours covers fresh, stale and recent
// checkpoints against the fixed ingestion age limit.
func TestBlobStartTimeHardLimitedTo72Hours(t *testing.T) {
	dir := configureBlobTest(t)
	now := time.Date(2026, 11, 26, 12, 35, 0, 0, time.UTC)
	oldestAllowed := now.Truncate(time.Hour).Add(-72 * time.Hour)
	statePath := filepath.Join(dir, "blob_files", "state.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(statePath), 0755))
	state, err := vthuntfeed.NewState(statePath)
	require.NoError(t, err)
	require.Equal(t, oldestAllowed, getBlobStartTime(state, now), "no checkpoint must start at 72-hour cutoff")

	require.NoError(t, state.Update(uint64(now.Add(-30*24*time.Hour).Unix())))
	require.Equal(t, oldestAllowed, getBlobStartTime(state, now), "stale checkpoint must not cause historical replay")

	require.NoError(t, state.Update(uint64(oldestAllowed.Add(4*time.Hour).Unix())))
	require.Equal(t, oldestAllowed.Add(5*time.Hour), getBlobStartTime(state, now), "recent checkpoint must resume normally")
}

// TestStaleCheckpointAndDeferredHourNeverDownloaded verifies that neither
// stale state nor deferred work bypasses the hard 72-hour limit.
func TestStaleCheckpointAndDeferredHourNeverDownloaded(t *testing.T) {
	dir := configureBlobTest(t)
	now := time.Date(2026, 11, 26, 12, 30, 0, 0, time.UTC)
	oldestAllowed := now.Truncate(time.Hour).Add(-72 * time.Hour)
	staleHour := oldestAllowed.Add(-time.Hour)
	seedBlobState(t, dir, now.Add(-30*24*time.Hour).Truncate(time.Hour))

	ledger, err := loadDeferredBlobLedger(filepath.Join(dir, "blob_files", "deferred_hours.json"))
	require.NoError(t, err)
	require.NoError(t, ledger.deferHour(staleHour, "missing", nil, now))

	// Even a 7-day configured recovery window must obey the 72-hour hard cap.
	oldRecovery, oldGrace := st.BlobRecoveryHours, st.BlobHourGracePeriod
	st.BlobRecoveryHours, st.BlobHourGracePeriod = 168, 71
	t.Cleanup(func() { st.BlobRecoveryHours, st.BlobHourGracePeriod = oldRecovery, oldGrace })

	var checked []string
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checked = append(checked, r.URL.Path)
		writeAzureError(w, http.StatusNotFound, "BlobNotFound")
	}))
	require.NoError(t, runBlobDownloadWithPublisher(client, now, func(io.ReadCloser, string) (int, error) {
		t.Fatal("missing blob should not be published")
		return 0, nil
	}))
	require.NotEmpty(t, checked)
	for _, request := range checked {
		require.NotContains(t, request, blobRequestPath(staleHour), "hour outside 72-hour window must never be requested")
	}
	require.Equal(t, uint64(oldestAllowed.Add(time.Hour).Unix()), readBlobState(t, dir))
	require.Contains(t, readDeferredLedger(t, dir).entries, staleHour.Unix(), "expired ledger entry is preserved for manual inspection")
}
