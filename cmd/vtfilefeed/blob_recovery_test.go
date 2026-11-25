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
	"github.com/stretchr/testify/require"
)

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

func TestBlobStateLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	release, err := lockBlobState(dir)
	require.NoError(t, err)
	defer release()
	_, err = lockBlobState(dir)
	require.Error(t, err)
}

func TestInvalidDeferredLedgerDoesNotReset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deferred_hours.json")
	require.NoError(t, os.WriteFile(path, []byte("bad"), 0600))
	_, err := loadDeferredBlobLedger(path)
	require.Error(t, err)
}
