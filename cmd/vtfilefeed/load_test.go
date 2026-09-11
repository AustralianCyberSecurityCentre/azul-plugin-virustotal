package vtfilefeed

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vthuntfeed"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/stretchr/testify/require"
)

func TestAuthorGetsFeatures(t *testing.T) {
	require.Greater(t, len(author.Features), 30)
}

func TestProcess1V3(t *testing.T) {
	st.MaxAgeHours = -1
	chFromVT := make(chan []byte, 10)
	chToDP := make(chan *events.BinaryEvent, 10)
	done := make(chan *processOutput)
	go func() {
		done <- process(nil, chFromVT, chToDP)
		close(done)
		close(chToDP)
	}()
	chFromVT <- []byte("{}")
	close(chFromVT)
	res := <-done

	require.Equal(t, res, &processOutput{
		recordsIn:       1,
		recordBytesIn:   2,
		binaryEventsOut: 0,
		filtered:        1,
		failed:          0,
	})
}

func TestProcess2V3(t *testing.T) {
	st.MaxAgeHours = -1
	st.SetNowToISO("2024-01-01T01:00:00Z")
	chFromVT := make(chan []byte, 10)
	chToDP := make(chan *events.BinaryEvent, 10)

	done := make(chan *processOutput)
	go func() {
		done <- process(nil, chFromVT, chToDP)
		close(done)
		close(chToDP)
	}()
	for _, line := range strings.Split(string(testdata.GetFileBytes("data/load/v3_feed_example.json")), "\n") {
		if len(line) > 0 {
			chFromVT <- []byte(line)
		}
	}
	close(chFromVT)
	res := <-done

	require.Equal(t, &processOutput{
		recordsIn:       10,
		recordBytesIn:   217528,
		binaryEventsOut: 10,
		filtered:        0,
		failed:          0,
	}, res)
}

// TestBlobDownloadSkipsMissingHourAndProcessesNext covers the original gap
// failure mode: state is at hour 01, hour 02 never exists, but hour 03 does.
// Once 02 is outside the grace window it must be marked skipped, then 03 must
// still be downloaded and processed.
func TestBlobDownloadSkipsMissingHourAndProcessesNext(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	missingHour := now.Truncate(time.Hour).Add(-3 * time.Hour)   // 02:00
	availableHour := now.Truncate(time.Hour).Add(-2 * time.Hour) // 03:00
	seedBlobState(t, stateDir, missingHour.Add(-time.Hour))      // state = 01:00

	body := testTarBZ2(t)
	etag := `"stable-etag"`
	lastModified := now.Add(-time.Hour)
	missingPath := blobRequestPath(missingHour)
	availablePath := blobRequestPath(availableHour)

	var mu sync.Mutex
	var requests []string
	var downloadIfMatch string

	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case missingPath:
			if r.Method != http.MethodHead {
				t.Errorf("missing blob received %s, expected HEAD", r.Method)
			}
			writeAzureError(w, http.StatusNotFound, "BlobNotFound")

		case availablePath:
			switch r.Method {
			case http.MethodHead:
				writeBlobProperties(w, lastModified, etag, len(body))
			case http.MethodGet:
				mu.Lock()
				downloadIfMatch = r.Header.Get("If-Match")
				mu.Unlock()
				writeBlobDownload(w, body, lastModified, etag)
			default:
				t.Errorf("available blob received unexpected method %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}

		default:
			t.Errorf("unexpected Azure request: %s %s", r.Method, r.URL.Path)
			writeAzureError(w, http.StatusNotFound, "BlobNotFound")
		}
	}))

	chFromVT := make(chan []byte, 10)
	runBlobDownloadAt(chFromVT, client, now)

	var got []string
	for line := range chFromVT {
		got = append(got, string(line))
	}

	require.Equal(t, []string{`{"hello":"world"}`, `{"second":2}`}, got)
	require.Equal(t, uint64(availableHour.Unix()), readBlobState(t, stateDir))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{
		http.MethodHead + " " + missingPath,
		http.MethodHead + " " + availablePath,
		http.MethodGet + " " + availablePath,
	}, requests)
	require.Equal(t, etag, downloadIfMatch, "download must be pinned to the ETag checked by GetProperties")
}

// TestBlobDownloadDoesNotTouchHoursInsideGraceWindow ensures the downloader is
// deliberately behind Azure. If the next state hour is newer than the latest
// eligible hour, Azure must not be contacted at all.
func TestBlobDownloadDoesNotTouchHoursInsideGraceWindow(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	currentHour := now.Truncate(time.Hour)
	seedHour := currentHour.Add(-2 * time.Hour) // state = 03:00, next = 04:00
	seedBlobState(t, stateDir, seedHour)

	var mu sync.Mutex
	requestCount := 0
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		t.Errorf("Azure should not have been contacted inside the grace window: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))

	chFromVT := make(chan []byte, 1)
	runBlobDownloadAt(chFromVT, client, now)
	for range chFromVT {
		t.Fatal("did not expect any records")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Zero(t, requestCount)
	require.Equal(t, uint64(seedHour.Unix()), readBlobState(t, stateDir))
}

// TestBlobDownloadWaitsForRecentlyModifiedBlob protects against a late or still
// settling upload at an otherwise old hourly path. It may be old enough by name,
// but Last-Modified must also be outside the stability period before GET occurs.
func TestBlobDownloadWaitsForRecentlyModifiedBlob(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	eligibleHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previousHour := eligibleHour.Add(-time.Hour)
	seedBlobState(t, stateDir, previousHour)

	path := blobRequestPath(eligibleHour)
	etag := `"still-changing"`
	lastModified := now.Add(-5 * time.Minute)

	var mu sync.Mutex
	var methods []string
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()

		if r.URL.Path != path {
			t.Errorf("unexpected path %s, expected %s", r.URL.Path, path)
		}
		if r.Method != http.MethodHead {
			t.Errorf("recently modified blob should only receive HEAD, got %s", r.Method)
		}
		writeBlobProperties(w, lastModified, etag, 100)
	}))

	chFromVT := make(chan []byte, 1)
	runBlobDownloadAt(chFromVT, client, now)
	for range chFromVT {
		t.Fatal("did not expect any records from an unstable blob")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{http.MethodHead}, methods)
	require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir), "state must not advance while the blob is still settling")
}

// TestBlobDownloadPropertyErrorDoesNotAdvanceState verifies that a real Azure
// error is not mistaken for a skipped hour. The downloader must stop and leave
// the state unchanged so the same hour is retried next run.
func TestBlobDownloadPropertyErrorDoesNotAdvanceState(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	eligibleHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previousHour := eligibleHour.Add(-time.Hour)
	seedBlobState(t, stateDir, previousHour)

	path := blobRequestPath(eligibleHour)
	var mu sync.Mutex
	var methods []string
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()

		if r.URL.Path != path {
			t.Errorf("unexpected path %s, expected %s", r.URL.Path, path)
		}
		writeAzureError(w, http.StatusForbidden, "AuthorizationFailure")
	}))

	chFromVT := make(chan []byte, 1)
	runBlobDownloadAt(chFromVT, client, now)
	for range chFromVT {
		t.Fatal("did not expect records after Azure property error")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{http.MethodHead}, methods)
	require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir), "state must not advance on non-BlobNotFound Azure errors")
	retryState := readBlobRetryState(t, stateDir)
	require.Zero(t, retryState.attempts, "service-wide Azure errors must not consume the per-blob retry budget")
}

// TestBlobDownloadETagChangeDoesNotAdvanceState simulates the blob changing
// after GetProperties but before DownloadStream. Azure rejects the conditional
// GET and the same hour must remain pending for the next run.
func TestBlobDownloadETagChangeDoesNotAdvanceState(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	eligibleHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previousHour := eligibleHour.Add(-time.Hour)
	seedBlobState(t, stateDir, previousHour)

	path := blobRequestPath(eligibleHour)
	etag := `"etag-seen-by-head"`
	lastModified := now.Add(-time.Hour)

	var mu sync.Mutex
	var methods []string
	var gotIfMatch string
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()

		if r.URL.Path != path {
			t.Errorf("unexpected path %s, expected %s", r.URL.Path, path)
		}

		switch r.Method {
		case http.MethodHead:
			writeBlobProperties(w, lastModified, etag, 100)
		case http.MethodGet:
			mu.Lock()
			gotIfMatch = r.Header.Get("If-Match")
			mu.Unlock()
			writeAzureError(w, http.StatusPreconditionFailed, "ConditionNotMet")
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	chFromVT := make(chan []byte, 1)
	runBlobDownloadAt(chFromVT, client, now)
	for range chFromVT {
		t.Fatal("did not expect records after failed ETag condition")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{http.MethodHead, http.MethodGet}, methods)
	require.Equal(t, etag, gotIfMatch)
	require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir), "state must remain on the previous hour after a failed conditional download")
	retryState := readBlobRetryState(t, stateDir)
	require.Equal(t, eligibleHour.Unix(), retryState.hour)
	require.Equal(t, 1, retryState.attempts)
}

// TestBlobDownloadProcessingFailureDoesNotAdvanceState covers the first failure
// of a corrupt or incomplete response body. It must remain pending and persist
// retry attempt 1 so a process restart does not lose the retry count.
func TestBlobDownloadProcessingFailureDoesNotAdvanceState(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	eligibleHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previousHour := eligibleHour.Add(-time.Hour)
	seedBlobState(t, stateDir, previousHour)

	path := blobRequestPath(eligibleHour)
	etag := `"stable-but-bad-content"`
	lastModified := now.Add(-time.Hour)
	badBody := []byte("this is not a bzip2 tar archive")

	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("unexpected path %s, expected %s", r.URL.Path, path)
		}
		switch r.Method {
		case http.MethodHead:
			writeBlobProperties(w, lastModified, etag, len(badBody))
		case http.MethodGet:
			writeBlobDownload(w, badBody, lastModified, etag)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	chFromVT := make(chan []byte, 10)
	runBlobDownloadAt(chFromVT, client, now)
	for range chFromVT {
		t.Fatal("did not expect records from corrupt blob content")
	}

	require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir), "state must not advance after the first processBlob failure")
	retryState := readBlobRetryState(t, stateDir)
	require.Equal(t, eligibleHour.Unix(), retryState.hour)
	require.Equal(t, 1, retryState.attempts)
}

// TestBlobDownloadRetrySucceedsBeforeLimit verifies that a blob-specific failure
// is retried on the next run and that a later successful attempt clears the
// retry state and advances the normal watermark.
func TestBlobDownloadRetrySucceedsBeforeLimit(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 5, 30, 0, 0, time.UTC)
	eligibleHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	previousHour := eligibleHour.Add(-time.Hour)
	seedBlobState(t, stateDir, previousHour)

	path := blobRequestPath(eligibleHour)
	etag := `"retry-then-good"`
	lastModified := now.Add(-time.Hour)
	badBody := []byte("not a bzip2 tar archive")
	goodBody := testTarBZ2(t)

	var mu sync.Mutex
	getCount := 0
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("unexpected path %s, expected %s", r.URL.Path, path)
		}
		switch r.Method {
		case http.MethodHead:
			writeBlobProperties(w, lastModified, etag, len(goodBody))
		case http.MethodGet:
			mu.Lock()
			getCount++
			curGet := getCount
			mu.Unlock()
			if curGet == 1 {
				writeBlobDownload(w, badBody, lastModified, etag)
				return
			}
			writeBlobDownload(w, goodBody, lastModified, etag)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	first := make(chan []byte, 10)
	runBlobDownloadAt(first, client, now)
	for range first {
		t.Fatal("did not expect records from the first corrupt attempt")
	}
	require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir))
	require.Equal(t, 1, readBlobRetryState(t, stateDir).attempts)

	second := make(chan []byte, 10)
	runBlobDownloadAt(second, client, now)
	var got []string
	for line := range second {
		got = append(got, string(line))
	}

	require.Equal(t, []string{`{"hello":"world"}`, `{"second":2}`}, got)
	require.Equal(t, uint64(eligibleHour.Unix()), readBlobState(t, stateDir))
	require.Zero(t, readBlobRetryState(t, stateDir).attempts, "successful retry must clear persisted retry state")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 2, getCount)
}

// TestBlobDownloadRetryLimitSkipsBadHourAndCatchesUp is the key liveness test.
// A permanently corrupt 03 is allowed blobMaxRetryAttempts failures across runs.
// On the final failed attempt it is explicitly skipped and the same run continues
// to a healthy 04, ending at the latest eligible hour instead of remaining stuck.
func TestBlobDownloadRetryLimitSkipsBadHourAndCatchesUp(t *testing.T) {
	stateDir := configureBlobTest(t)
	now := time.Date(2026, 9, 9, 6, 30, 0, 0, time.UTC)
	badHour := now.Truncate(time.Hour).Add(-3 * time.Hour)  // 03:00
	goodHour := now.Truncate(time.Hour).Add(-2 * time.Hour) // 04:00, latest eligible
	previousHour := badHour.Add(-time.Hour)                 // state = 02:00
	seedBlobState(t, stateDir, previousHour)

	badPath := blobRequestPath(badHour)
	goodPath := blobRequestPath(goodHour)
	badETag := `"permanently-bad"`
	goodETag := `"healthy-next-hour"`
	lastModified := now.Add(-time.Hour)
	badBody := []byte("permanently corrupt archive")
	goodBody := testTarBZ2(t)

	var mu sync.Mutex
	badGets := 0
	goodGets := 0
	client := newTestAzureClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case badPath:
			switch r.Method {
			case http.MethodHead:
				writeBlobProperties(w, lastModified, badETag, len(badBody))
			case http.MethodGet:
				mu.Lock()
				badGets++
				mu.Unlock()
				writeBlobDownload(w, badBody, lastModified, badETag)
			default:
				t.Errorf("bad blob received unexpected method %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case goodPath:
			switch r.Method {
			case http.MethodHead:
				writeBlobProperties(w, lastModified, goodETag, len(goodBody))
			case http.MethodGet:
				mu.Lock()
				goodGets++
				mu.Unlock()
				writeBlobDownload(w, goodBody, lastModified, goodETag)
			default:
				t.Errorf("good blob received unexpected method %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		default:
			t.Errorf("unexpected Azure request: %s %s", r.Method, r.URL.Path)
			writeAzureError(w, http.StatusNotFound, "BlobNotFound")
		}
	}))

	for attempt := 1; attempt <= st.BlobMaxRetryAttempts; attempt++ {
		ch := make(chan []byte, 10)
		runBlobDownloadAt(ch, client, now)

		var got []string
		for line := range ch {
			got = append(got, string(line))
		}

		if attempt < st.BlobMaxRetryAttempts {
			require.Empty(t, got)
			require.Equal(t, uint64(previousHour.Unix()), readBlobState(t, stateDir))
			retryState := readBlobRetryState(t, stateDir)
			require.Equal(t, badHour.Unix(), retryState.hour)
			require.Equal(t, attempt, retryState.attempts)
			continue
		}

		require.Equal(t, []string{`{"hello":"world"}`, `{"second":2}`}, got)
		require.Equal(t, uint64(goodHour.Unix()), readBlobState(t, stateDir), "after exhausting retries for 03, downloader must catch up through healthy 04")
		require.Zero(t, readBlobRetryState(t, stateDir).attempts, "retry state must be cleared after skip/catch-up")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, st.BlobMaxRetryAttempts, badGets)
	require.Equal(t, 1, goodGets, "later healthy hour should be downloaded immediately after bad hour is skipped")
}

func configureBlobTest(t *testing.T) string {
	t.Helper()

	oldStateDir := st.StateDir
	oldContainer := st.BlobContainer
	oldFullPathFormat := st.BlobFullPathFormat
	oldFileNameFormat := st.BlobFileNameFormat

	oldGracePeriod := st.BlobHourGracePeriod
	oldStabilityPeriod := st.BlobStabilityPeriod
	oldMaxRetryAttempts := st.BlobMaxRetryAttempts

	stateDir := t.TempDir()
	st.StateDir = stateDir
	st.BlobContainer = "test-container"
	st.BlobFullPathFormat = "%s/%s/%s"
	st.BlobFileNameFormat = "2006010215"

	// Explicit test values so tests do not depend on production defaults.
	st.BlobHourGracePeriod = 2
	st.BlobStabilityPeriod = 10
	st.BlobMaxRetryAttempts = 3

	t.Cleanup(func() {
		st.StateDir = oldStateDir
		st.BlobContainer = oldContainer
		st.BlobFullPathFormat = oldFullPathFormat
		st.BlobFileNameFormat = oldFileNameFormat

		st.BlobHourGracePeriod = oldGracePeriod
		st.BlobStabilityPeriod = oldStabilityPeriod
		st.BlobMaxRetryAttempts = oldMaxRetryAttempts
	})

	return stateDir
}

func seedBlobState(t *testing.T, stateDir string, hour time.Time) {
	t.Helper()

	statePath := filepath.Join(stateDir, "blob_files", "state.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(statePath), 0755))
	state, err := vthuntfeed.NewState(statePath)
	require.NoError(t, err)
	require.NoError(t, state.Update(uint64(hour.Unix())))
}

func readBlobState(t *testing.T, stateDir string) uint64 {
	t.Helper()

	state, err := vthuntfeed.NewState(filepath.Join(stateDir, "blob_files", "state.txt"))
	require.NoError(t, err)
	return state.Last()
}

func readBlobRetryState(t *testing.T, stateDir string) blobRetryState {
	t.Helper()

	state, err := loadBlobRetryState(filepath.Join(stateDir, "blob_files", "retry_state.txt"))
	require.NoError(t, err)
	return state
}

func blobRequestPath(hour time.Time) string {
	blobName := fmt.Sprintf(
		st.BlobFullPathFormat,
		strconv.Itoa(hour.Year()),
		strconv.Itoa(int(hour.Month())),
		hour.Format(st.BlobFileNameFormat),
	)
	return "/" + strings.Trim(st.BlobContainer, "/") + "/" + strings.TrimLeft(blobName, "/")
}

func newTestAzureClient(t *testing.T, handler http.Handler) azblob.Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := azblob.NewClientWithNoCredential(server.URL+"/", nil)
	require.NoError(t, err)
	return *client
}

func writeBlobProperties(w http.ResponseWriter, lastModified time.Time, etag string, size int) {
	w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("x-ms-blob-type", "BlockBlob")
	w.Header().Set("x-ms-request-id", "test-request-id")
	w.Header().Set("x-ms-version", "2025-11-05")
	w.WriteHeader(http.StatusOK)
}

func writeBlobDownload(w http.ResponseWriter, body []byte, lastModified time.Time, etag string) {
	w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("x-ms-blob-type", "BlockBlob")
	w.Header().Set("x-ms-request-id", "test-request-id")
	w.Header().Set("x-ms-version", "2025-11-05")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeAzureError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-ms-error-code", code)
	w.Header().Set("x-ms-request-id", "test-request-id")
	w.Header().Set("x-ms-version", "2025-11-05")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>test error</Message></Error>`, code)
}

func testTarBZ2(t *testing.T) []byte {
	t.Helper()

	// tar.bz2 containing feed.json with two newline-delimited records:
	// {"hello":"world"}
	// {"second":2}
	const encoded = "QlpoOTFBWSZTWY8FmTIAAHfbgMqQUAFfkACAb1WeiggIIAB0IImCABpkNDBBKTUGgBoAAGj7aYVBAbCgghRxVIOnlagIMGMHi86PMVHNBSQCDjCBkX6lw7FWi2gcJQdE0i+i9kOkreBMjSSGToqllZ1O0REA/F3JFOFCQjwWZMg="

	data, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return data
}
