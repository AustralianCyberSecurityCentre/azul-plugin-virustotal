// Test / Example event publisher to submit Binaries from the command-line
package vtfilefeed

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/events"
	bedset "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/batch"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/cmd/vthuntfeed"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/download"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/receiver"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtselect"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/push"
)

type blobRetryState struct {
	hour     int64
	attempts int
}

var newestVTTimestamp float64
var virustotalTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "virustotal_plugin_last_ingested_timestamp",
	Help: "The current timestamp being used to scrape data from virustotal.",
})

var start = time.Now()

var dpclient *bedclient.Client

var author = events.PluginEntity{
	Name:        "VirustotalFileFeed",
	Version:     "2.2.0",
	Contact:     "azul@asd.gov.au",
	Category:    "plugin",
	Description: "Load vt metadata into kafka.",
	Features:    vtmap.TotalFeatureDescriptions(),
}

var authorSummary = author.Summary()

type processOutput struct {
	recordsIn         int
	recordBytesIn     int
	downloadEventsOut int
	binaryEventsOut   int
	filtered          int
	failed            int
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// printState displays processing stats of vt records
func printState(po *processOutput) {
	duration := time.Since(start)
	log.Printf(
		"%d vt-records (%0.02f/s %0.02fMB/s) -> %d binary-events & %d download-events & %d filtered",
		po.recordsIn,
		float64(po.recordsIn)/float64(duration)*float64(time.Second),
		float64(po.recordBytesIn)/float64(duration)*float64(time.Second)/1000/1000,
		po.binaryEventsOut,
		po.downloadEventsOut,
		po.filtered,
	)
}

// process transforms vt records to various azul events
func process(dpclient *bedclient.Client, chFromVT chan []byte, chToDP chan *events.BinaryEvent) *processOutput {
	var ret = processOutput{}
	for s := range chFromVT {
		// print state every 1k records
		if ret.recordsIn > 0 && ret.recordsIn%1000 == 0 {
			printState(&ret)
		}
		ret.recordsIn += 1
		ret.recordBytesIn += len(s)
		bulk_binary, err := vtmap.TransformFileFeedSingleV3(s, &authorSummary)
		if err != nil {
			ret.failed += 1
			reduced := s[:min(len(s), 1000)]
			log.Printf("failed to convert message (%v):\n%v", err, string(reduced))
			continue
		}
		if bulk_binary == nil {
			ret.filtered += 1
			continue
		}

		for _, ev := range bulk_binary {
			chToDP <- ev
			// Update metrics
			if len(ev.Source.Path) > 0 {
				vtLatestTimestamp := float64(ev.Source.Path[0].Timestamp.UTC().UnixMilli())
				if vtLatestTimestamp > newestVTTimestamp {
					newestVTTimestamp = vtLatestTimestamp
					virustotalTimestamp.Set(vtLatestTimestamp)
				}
			}
			ret.binaryEventsOut += 1
		}

		// decide if the binary file should be downloaded
		bulk_download, err := vtselect.SelectForDownloadV3(s, &authorSummary)
		if err != nil {
			ret.failed += 1
			reduced := s[:min(len(s), 1000)]
			log.Printf("failed to evaluate for download message: %v\n%v", err, string(reduced))
			continue
		}

		// FUTURE this could be configured as a separate channel but that's a premature optimisation
		if len(bulk_download) > 0 && dpclient != nil {
			bulk := events.BulkDownloadEvent{Events: bulk_download}
			_, err := dpclient.PostEvents(&bulk, &bedclient.PublishBytesOptions{Sync: false})
			if err != nil {
				log.Printf("failed to post download messages: %v", err)
				continue
			}
			ret.downloadEventsOut += len(bulk_download)
		}
	}
	return &ret
}

// processToDispatcher sends vt records to kafka after transformation
func processToDispatcher(chFromVT chan []byte) *processOutput {
	chToDP := make(chan *events.BinaryEvent, 10)
	dpclient = bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, st.DeploymentKey)
	err := dpclient.PublishPlugin()
	if err != nil {
		log.Fatal(err)
	}
	batcher := batch.NewBatcher(dpclient)
	// buffer responses as we only read them after workers are finished
	sendErrors := make(chan int, batcher.SendWorkerCount)
	wg := batcher.SendBulkBinaryEvents(chToDP, sendErrors)
	ret := process(dpclient, chFromVT, chToDP)

	close(chToDP)
	wg.Wait()
	// multiple senders so can't close in a sender
	close(sendErrors)
	for curErr := range sendErrors {
		ret.failed += curErr
	}
	return ret
}

func startPrometheusPusher(ctx context.Context, pushgateway string, wg *sync.WaitGroup) {
	defer wg.Done()
	pusher := push.New(pushgateway, "plugin-virustotal-load").Collector(virustotalTimestamp)
	minutely := time.NewTicker(1 * time.Minute)
	var err error
	for {
		select {
		case <-minutely.C:
			err = pusher.Push()
			if err != nil {
				log.Printf("Failed to push metrics with error: %v\n", err)
			}
		case <-ctx.Done():
			err = pusher.Push()
			if err != nil {
				log.Printf("Failed to push metrics with error: %v\n", err)
			}
			return
		}
	}
}

func Entrypoint(downloadFromBlob bool) {
	_, err := vtselect.LoadRules()
	if err != nil {
		panic(err)
	}

	chFromVT := make(chan []byte, 10)
	ctx, cancelFunc := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	if len(st.PushGateway) > 0 {
		bedset.Logger.Info().Str("Gateway", st.PushGateway).Msg("Setting up worker to push to Prometheus push gateway")
		wg.Add(1)
		go startPrometheusPusher(ctx, st.PushGateway, &wg)
	}

	if downloadFromBlob {
		startBlobDownload(chFromVT)
	} else {
		startVTDownload(chFromVT)
	}

	details := processToDispatcher(chFromVT)

	printState(details)
	cancelFunc()
	wg.Wait()

	if details.filtered > 0 {
		log.Printf("%v invalid vt-records", details.filtered)
	}

	if details.failed > 0 {
		log.Printf("%v failed vt-records", details.failed)
		os.Exit(1)
	}
}

func StartServer() {
	_, err := vtselect.LoadRules()
	if err != nil {
		panic(err)
	}

	chFromVT := make(chan []byte, 10)

	go processToDispatcher(chFromVT)

	log.Println("Running server to allow VT file uploads via POST request.")
	receiver.RunServer(chFromVT)
}

func startVTDownload(chFromVT chan []byte) {
	if st.VirustotalApiKey == "" {
		log.Fatal("VirustotalApiKey is required")
	}

	bedset.Logger.Info().Msg("Downloading from VirusTotal")

	d, err := download.NewDownloader(
		filepath.Join(st.StateDir, "v3_files"),
		st.VirustotalApiServer,
		st.VirustotalApiKey,
	)
	if err != nil {
		panic(err)
	}

	bedset.Logger.Info().Msg("Fetching with downloader")

	go d.Fetch(chFromVT, st.PkgLimit)
}

func startBlobDownload(chFromVT chan []byte) {
	bedset.Logger.Info().Msg("Downloading from Blob Storage")

	if st.AzureConnectionString == "" {
		bedset.Logger.Fatal().Msg("AzureConnectionString is required")
	}

	client, err := azblob.NewClientFromConnectionString(
		st.AzureConnectionString,
		nil,
	)
	if err != nil {
		bedset.Logger.Fatal().Err(err)
	}

	go runBlobDownload(chFromVT, *client)
}

func runBlobDownload(chFromVT chan []byte, client azblob.Client) {
	runBlobDownloadAt(chFromVT, client, time.Now().UTC())
}

// runBlobDownloadAt contains the blob catch-up logic using an explicit current
// time. Production passes time.Now(), while tests can supply a fixed time so
// grace-period and stability behaviour is deterministic.
func runBlobDownloadAt(chFromVT chan []byte, client azblob.Client, now time.Time) {
	defer close(chFromVT)

	now = now.UTC()

	var blobHourGracePeriod = time.Duration(st.BlobHourGracePeriod) * time.Hour
	var blobStabilityPeriod = time.Duration(st.BlobStabilityPeriod) * time.Minute
	var blobMaxRetryAttempts = st.BlobMaxRetryAttempts

	stateDir := filepath.Join(st.StateDir, "blob_files")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		bedset.Logger.Fatal().Err(err)
	}

	statePath := filepath.Join(stateDir, "state.txt")

	state, err := vthuntfeed.NewState(statePath)
	if err != nil {
		bedset.Logger.Fatal().Err(err)
	}

	retryPath := filepath.Join(stateDir, "retry_state.txt")
	retryState, err := loadBlobRetryState(retryPath)
	if err != nil {
		bedset.Logger.Fatal().Err(err)
	}

	// Deliberately stay behind the current UTC hour. For example, with a two-hour
	// grace period, a run during hour 05 will only consider hours up to and
	// including 03. Hours 04 and 05 are never touched by this run.
	currentHour := now.Truncate(time.Hour)
	latestEligibleHour := currentHour.Add(-blobHourGracePeriod)

	startTime := getBlobStartTime(state, currentHour)

	if startTime.After(latestEligibleHour) {
		bedset.Logger.Info().
			Str("start_time", startTime.Format(time.RFC3339)).
			Str("latest_eligible_hour", latestEligibleHour.Format(time.RFC3339)).
			Dur("grace_period", blobHourGracePeriod).
			Msg("No blob hours are old enough to process yet")
		bedset.Logger.Info().Msg("Blob download run complete")
		return
	}

	containerClient := client.ServiceClient().
		NewContainerClient(st.BlobContainer)

	for cur := startTime; !cur.After(latestEligibleHour); cur = cur.Add(time.Hour) {
		blobName := fmt.Sprintf(
			st.BlobFullPathFormat,
			strconv.Itoa(cur.Year()),
			strconv.Itoa(int(cur.Month())),
			cur.Format(st.BlobFileNameFormat),
		)

		bedset.Logger.Info().
			Str("blob", blobName).
			Str("hour", cur.Format(time.RFC3339)).
			Msg("Checking eligible blob")

		// Blob-specific failures are retried across runs. After the configured
		// number of failures, explicitly skip the hour and continue catch-up so
		// one permanently bad blob cannot block every later eligible hour.
		handleRetryableFailure := func(failure error, reason string) bool {
			attempts, retryErr := recordBlobRetryFailure(retryPath, &retryState, cur)
			if retryErr != nil {
				bedset.Logger.Error().
					Err(retryErr).
					Str("blob", blobName).
					Msg("Failed updating blob retry state. Stopping catch-up without advancing state.")
				return false
			}

			if attempts < blobMaxRetryAttempts {
				bedset.Logger.Error().
					Err(failure).
					Str("blob", blobName).
					Str("hour", cur.Format(time.RFC3339)).
					Int("attempt", attempts).
					Int("max_attempts", blobMaxRetryAttempts).
					Msg(reason + ". Stopping catch-up so this hour is retried on the next run.")
				return false
			}

			bedset.Logger.Error().
				Err(failure).
				Str("blob", blobName).
				Str("hour", cur.Format(time.RFC3339)).
				Int("attempts", attempts).
				Int("max_attempts", blobMaxRetryAttempts).
				Msg(reason + ". Retry limit reached; marking hour as skipped and continuing catch-up.")

			if updateErr := state.Update(uint64(cur.Unix())); updateErr != nil {
				bedset.Logger.Error().
					Err(updateErr).
					Str("blob", blobName).
					Msg("Failed advancing state after retry limit was reached")
				return false
			}

			if clearErr := clearBlobRetryState(retryPath, &retryState); clearErr != nil {
				// The primary state has already advanced. A stale retry file cannot
				// cause reprocessing because retry entries are tied to a specific hour.
				bedset.Logger.Warn().Err(clearErr).Msg("Failed clearing blob retry state after skipped hour")
			}

			return true
		}

		// Check the blob metadata before opening the download stream. This lets us
		// avoid consuming a blob that has only just appeared or was modified very
		// recently, even if its hourly filename is old.
		blobClient := containerClient.NewBlobClient(blobName)

		props, err := blobClient.GetProperties(context.Background(), nil)
		if err != nil {
			if bloberror.HasCode(err, bloberror.BlobNotFound) {
				// Every hour reaching this loop is already older than the grace window.
				// If it still does not exist, treat that hour as intentionally skipped
				// and advance the contiguous state watermark.
				bedset.Logger.Warn().
					Str("blob", blobName).
					Str("hour", cur.Format(time.RFC3339)).
					Dur("grace_period", blobHourGracePeriod).
					Msg("Eligible blob is still missing after the grace period. Marking hour as skipped and continuing catch-up.")

				if err := state.Update(uint64(cur.Unix())); err != nil {
					bedset.Logger.Error().Err(err).Msg("Failed updating state for skipped blob")
					break
				}
				if err := clearBlobRetryState(retryPath, &retryState); err != nil {
					bedset.Logger.Warn().Err(err).Msg("Failed clearing blob retry state after missing hour was skipped")
				}

				continue
			}

			// Authentication, network, throttling, or other Azure errors are never
			// interpreted as a missing hour. Leave state unchanged and retry this
			// exact hour on the next run.
			bedset.Logger.Error().
				Err(err).
				Str("blob", blobName).
				Msg("Failed checking blob properties. Stopping catch-up without advancing state.")
			break
		}

		if props.LastModified == nil {
			failure := fmt.Errorf("blob properties did not include LastModified")
			if handleRetryableFailure(failure, "Blob is missing required LastModified metadata") {
				continue
			}
			break
		}

		modifiedAge := now.Sub(props.LastModified.UTC())
		if modifiedAge < blobStabilityPeriod {
			bedset.Logger.Info().
				Str("blob", blobName).
				Time("last_modified", props.LastModified.UTC()).
				Dur("modified_age", modifiedAge).
				Dur("stability_period", blobStabilityPeriod).
				Msg("Blob was modified too recently. Stopping catch-up so it can settle before processing.")
			break
		}

		if props.ETag == nil {
			failure := fmt.Errorf("blob properties did not include an ETag")
			if handleRetryableFailure(failure, "Blob is missing required ETag metadata") {
				continue
			}
			break
		}

		bedset.Logger.Info().
			Str("blob", blobName).
			Time("last_modified", props.LastModified.UTC()).
			Dur("modified_age", modifiedAge).
			Msg("Blob is outside the hour grace window and has been stable long enough. Starting download.")

		// Pin the GET to the exact ETag observed above. If the producer modifies or
		// replaces the blob after our stability check but before the GET starts,
		// Azure rejects this request instead of allowing us to process a different
		// version than the one we judged stable.
		resp, err := client.DownloadStream(
			context.Background(),
			st.BlobContainer,
			blobName,
			&azblob.DownloadStreamOptions{
				AccessConditions: &blob.AccessConditions{
					ModifiedAccessConditions: &blob.ModifiedAccessConditions{
						IfMatch: props.ETag,
					},
				},
			},
		)
		if err != nil {
			// A failed ETag condition is specific to this blob/version, so it uses
			// the bounded retry budget. Other download failures may be service-wide
			// (network, auth, throttling, Azure outage), so they never consume retries
			// and never cause an hour to be skipped.
			if bloberror.HasCode(err, bloberror.ConditionNotMet) {
				if handleRetryableFailure(err, "Blob changed after the stability check") {
					continue
				}
				break
			}

			bedset.Logger.Error().
				Err(err).
				Str("blob", blobName).
				Msg("Failed downloading stable blob due to an Azure/service error. Stopping catch-up without consuming the blob retry budget.")
			break
		}

		recordCount, err := processBlob(
			resp.Body,
			blobName,
			chFromVT,
		)

		if err != nil {
			log.Printf(
				"Finished blob %s, records=%d success=false",
				blobName,
				recordCount,
			)
			if handleRetryableFailure(err, "Failed processing blob") {
				continue
			}
			break
		}

		log.Printf(
			"Finished blob %s, records=%d success=true",
			blobName,
			recordCount,
		)

		if err := state.Update(uint64(cur.Unix())); err != nil {
			bedset.Logger.Error().Err(err).Msg("Failed updating state")
			break
		}
		if err := clearBlobRetryState(retryPath, &retryState); err != nil {
			bedset.Logger.Warn().Err(err).Msg("Failed clearing blob retry state after successful blob")
		}
	}

	bedset.Logger.Info().Msg("Blob download run complete")
}

func loadBlobRetryState(path string) (blobRetryState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return blobRetryState{}, nil
	}
	if err != nil {
		return blobRetryState{}, fmt.Errorf("failed reading blob retry state: %w", err)
	}

	var state blobRetryState
	if _, err := fmt.Sscanf(string(data), "%d %d", &state.hour, &state.attempts); err != nil {
		return blobRetryState{}, fmt.Errorf("failed parsing blob retry state: %w", err)
	}
	if state.attempts < 0 {
		return blobRetryState{}, fmt.Errorf("invalid negative blob retry attempt count: %d", state.attempts)
	}

	return state, nil
}

func recordBlobRetryFailure(path string, state *blobRetryState, hour time.Time) (int, error) {
	hourUnix := hour.UTC().Truncate(time.Hour).Unix()
	if state.hour != hourUnix {
		state.hour = hourUnix
		state.attempts = 0
	}

	state.attempts++
	if err := saveBlobRetryState(path, *state); err != nil {
		return 0, err
	}

	return state.attempts, nil
}

func saveBlobRetryState(path string, state blobRetryState) error {
	tmpPath := path + ".tmp"
	data := fmt.Appendf(nil, "%d %d\n", state.hour, state.attempts)
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed writing temporary blob retry state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed replacing blob retry state: %w", err)
	}
	return nil
}

func clearBlobRetryState(path string, state *blobRetryState) error {
	*state = blobRetryState{}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed removing blob retry state: %w", err)
	}
	return nil
}

func getBlobStartTime(
	state vthuntfeed.State,
	now time.Time,
) time.Time {
	if state.Last() == 0 {
		startTime := now.
			Add(-time.Duration(st.MaxAgeHours) * time.Hour).
			Truncate(time.Hour)

		bedset.Logger.Info().
			Int("max_age_hours", st.MaxAgeHours).
			Str("start_time", startTime.Format(time.RFC3339)).
			Msg("No state file found")

		return startTime
	}

	startTime := time.Unix(
		int64(state.Last()),
		0,
	).UTC().Add(time.Hour)

	bedset.Logger.Info().
		Str("start_time", startTime.Format(time.RFC3339)).
		Msg("Resuming from previous state")

	return startTime
}

func processBlob(
	body io.ReadCloser,
	blobName string,
	chFromVT chan<- []byte,
) (int, error) {
	defer body.Close()

	recordCount := 0

	bz2Reader := bzip2.NewReader(body)
	tarReader := tar.NewReader(bz2Reader)

	for {
		hdr, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return recordCount, fmt.Errorf(
				"failed reading tar in %s: %w",
				blobName,
				err,
			)
		}

		bedset.Logger.Info().
			Str("entry", hdr.Name).
			Str("blob", blobName).
			Msg("Reading tar entry")

		scanner := bufio.NewScanner(tarReader)
		scanner.Buffer(nil, 10*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()

			lineBuf := make([]byte, len(line))
			copy(lineBuf, line)

			chFromVT <- lineBuf
			recordCount++
		}

		if err := scanner.Err(); err != nil {
			return recordCount, fmt.Errorf(
				"failed reading content from %s: %w",
				blobName,
				err,
			)
		}
	}

	return recordCount, nil
}
