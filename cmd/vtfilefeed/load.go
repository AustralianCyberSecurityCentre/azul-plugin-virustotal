// Test / Example event publisher to submit Binaries from the command-line
package vtfilefeed

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"context"
	"errors"
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
func process(dpclient *bedclient.Client, chFromVT chan []byte, chToDP chan *events.BinaryEvent, synchronousDownload ...bool) *processOutput {
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
			requireAck := len(synchronousDownload) > 0 && synchronousDownload[0]
			_, err := dpclient.PostEvents(&bulk, &bedclient.PublishBytesOptions{Sync: requireAck})
			if err != nil {
				ret.failed += len(bulk_download)
				log.Printf("failed to post download messages: %v", err)
				continue
			}
			ret.downloadEventsOut += len(bulk_download)
		}
	}
	return &ret
}

// processWithClient does not return until every queued binary event has been
// synchronously acknowledged by Dispatcher (or counted as a failure).
func processWithClient(client *bedclient.Client, chFromVT chan []byte, requireAck bool) *processOutput {
	chToDP := make(chan *events.BinaryEvent, 10)
	batcher := batch.NewBatcher(client)
	sendErrors := make(chan int, batcher.SendWorkerCount)
	wg := batcher.SendBulkBinaryEvents(chToDP, sendErrors)
	ret := process(client, chFromVT, chToDP, requireAck)
	close(chToDP)
	wg.Wait()
	close(sendErrors)
	for curErr := range sendErrors {
		ret.failed += curErr
	}
	return ret
}

// processToDispatcher sends vt records to Kafka after transformation.
func processToDispatcher(chFromVT chan []byte) *processOutput {
	client := bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, st.DeploymentKey)
	if err := client.PublishPlugin(); err != nil {
		log.Fatal(err)
	}
	return processWithClient(client, chFromVT, false)
}

// blobPublishFn processes one entire blob and only returns nil after all
// downstream Dispatcher publishes have been acknowledged.
type blobPublishFn func(io.ReadCloser, string) (int, error)

var errBlobUnstable = errors.New("blob has not reached stability period")
var errDispatcherIngest = errors.New("dispatcher ingest failed")
var errBlobInfrastructure = errors.New("azure blob storage operation failed")

func newBlobPublisher() (blobPublishFn, error) {
	client := bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, st.DeploymentKey)
	if err := client.PublishPlugin(); err != nil {
		return nil, fmt.Errorf("register VirusTotal plugin: %w", err)
	}
	return func(body io.ReadCloser, blobName string) (int, error) {
		records := make(chan []byte, 10)
		type blobReadResult struct {
			count int
			err   error
		}
		readDone := make(chan blobReadResult, 1)
		go func() {
			count, err := processBlob(body, blobName, records)
			close(records)
			readDone <- blobReadResult{count, err}
		}()
		result := processWithClient(client, records, true)
		read := <-readDone
		if read.err != nil {
			return read.count, read.err
		}
		if read.count == 0 {
			return 0, errors.New("blob archive contains no records")
		}
		if result.failed != 0 {
			return read.count, fmt.Errorf("%w: %d failed records/events", errDispatcherIngest, result.failed)
		}
		return read.count, nil
	}, nil
}

func ingestBlobRun(now time.Time) error {
	if st.AzureConnectionString == "" {
		return errors.New("AzureConnectionString is required")
	}
	client, err := azblob.NewClientFromConnectionString(st.AzureConnectionString, nil)
	if err != nil {
		return err
	}
	publisher, err := newBlobPublisher()
	if err != nil {
		return err
	}
	return runBlobDownloadWithPublisher(*client, now, publisher)
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
		ingestErr := ingestBlobRun(time.Now().UTC())
		cancelFunc()
		wg.Wait()
		if ingestErr != nil {
			log.Printf("VirusTotal blob ingestion failed: %v", ingestErr)
			os.Exit(1)
		}
		return
	}
	startVTDownload(chFromVT)

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

// runBlobDownloadWithPublisher serially commits only fully published hours.
// Missing/bad hours enter a durable deferred ledger before the high-watermark
// moves on; a bounded look-back retries these hours on subsequent runs.
func runBlobDownloadWithPublisher(client azblob.Client, now time.Time, publish blobPublishFn) error {
	now = now.UTC()
	if st.BlobHourGracePeriod < 0 || st.BlobStabilityPeriod < 0 || st.BlobMaxRetryAttempts < 1 || st.BlobRecoveryHours < 1 || st.BlobOperationTimeoutMinutes < 1 {
		return errors.New("invalid blob grace/stability/retry/recovery/timeout settings")
	}
	stateDir := filepath.Join(st.StateDir, "blob_files")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return err
	}
	unlock, err := lockBlobState(stateDir)
	if err != nil {
		return fmt.Errorf("another blob ingestion instance may be running: %w", err)
	}
	defer unlock()
	state, err := vthuntfeed.NewState(filepath.Join(stateDir, "state.txt"))
	if err != nil {
		return err
	}
	currentHour := now.Truncate(time.Hour)
	latestEligible := currentHour.Add(-time.Duration(st.BlobHourGracePeriod) * time.Hour)
	if state.Last() != 0 && time.Unix(int64(state.Last()), 0).UTC().After(latestEligible) {
		return fmt.Errorf("blob checkpoint %s exceeds latest eligible hour %s; inspect persisted state (will not silently rewind)", time.Unix(int64(state.Last()), 0).UTC().Format(time.RFC3339), latestEligible.Format(time.RFC3339))
	}
	ledger, err := loadDeferredBlobLedger(filepath.Join(stateDir, "deferred_hours.json"))
	if err != nil {
		return err
	}
	retryPath := filepath.Join(stateDir, "retry_state.txt")
	retryState, err := loadBlobRetryState(retryPath)
	if err != nil {
		return err
	}
	containerClient := client.ServiceClient().NewContainerClient(st.BlobContainer)
	operationTimeout := time.Duration(st.BlobOperationTimeoutMinutes) * time.Minute

	// processHour returns (done, missing, error). Transient failures stop
	// ordinary catch-up, but a recovery attempt won't block newer hours.
	processHour := func(cur time.Time) (bool, bool, error) {
		name := fmt.Sprintf(st.BlobFullPathFormat, strconv.Itoa(cur.Year()), strconv.Itoa(int(cur.Month())), cur.Format(st.BlobFileNameFormat))
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		bc := containerClient.NewBlobClient(name)
		props, err := bc.GetProperties(ctx, nil)
		if err != nil {
			if bloberror.HasCode(err, bloberror.BlobNotFound) {
				return false, true, nil
			}
			return false, false, fmt.Errorf("%w: checking properties for %s: %w", errBlobInfrastructure, name, err)
		}
		if props.LastModified == nil || props.ETag == nil {
			return false, false, fmt.Errorf("blob %s lacks LastModified or ETag", name)
		}
		if now.Sub(props.LastModified.UTC()) < time.Duration(st.BlobStabilityPeriod)*time.Minute {
			return false, false, fmt.Errorf("%w: %s", errBlobUnstable, name)
		}
		response, err := client.DownloadStream(ctx, st.BlobContainer, name, &azblob.DownloadStreamOptions{
			AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: props.ETag}},
		})
		if err != nil {
			if bloberror.HasCode(err, bloberror.ConditionNotMet) {
				return false, false, fmt.Errorf("blob %s changed after stability check: %w", name, err)
			}
			return false, false, fmt.Errorf("%w: downloading %s: %w", errBlobInfrastructure, name, err)
		}
		count, err := publish(response.Body, name)
		if err != nil {
			if ctx.Err() != nil {
				return false, false, fmt.Errorf("%w: stream timed out for %s: %w", errBlobInfrastructure, name, ctx.Err())
			}
			return false, false, fmt.Errorf("processing %s (%d records): %w", name, count, err)
		}
		if count == 0 {
			return false, false, fmt.Errorf("empty archive %s", name)
		}
		log.Printf("Finished and published blob %s, records=%d success=true", name, count)
		return true, false, nil
	}

	recoveryWindow := time.Duration(st.BlobRecoveryHours) * time.Hour
	for _, entry := range ledger.unresolvedOutsideWindow(now, recoveryWindow) {
		log.Printf("ALERT: unresolved blob hour %s outside recovery window (reason=%s attempts=%d); manual replay required", time.Unix(entry.Hour, 0).UTC().Format(time.RFC3339), entry.Reason, entry.Attempts)
	}
	for _, hour := range ledger.eligible(latestEligible, recoveryWindow) {
		done, missing, failure := processHour(hour)
		if done {
			if err := ledger.resolve(hour); err != nil {
				return err
			}
			log.Printf("Recovered previously deferred blob hour %s", hour.Format(time.RFC3339))
		} else {
			reason := "recovery_failure"
			if missing {
				reason = "still_missing"
			}
			if err := ledger.deferHour(hour, reason, failure, now); err != nil {
				return err
			}
			log.Printf("Deferred blob %s still unavailable: %v", hour.Format(time.RFC3339), failure)
		}
	}

	startTime := getBlobStartTime(state, currentHour)
	if startTime.After(latestEligible) {
		log.Printf("No new eligible blob hours; checkpoint %s", startTime.Format(time.RFC3339))
		return nil
	}
	for hour := startTime; !hour.After(latestEligible); hour = hour.Add(time.Hour) {
		done, missing, failure := processHour(hour)
		if done {
			if err := state.Update(uint64(hour.Unix())); err != nil {
				return err
			}
			if err := clearBlobRetryState(retryPath, &retryState); err != nil {
				return err
			}
			continue
		}
		if missing {
			// Persist the missing hour *before* advancing, so late arrivals
			// remain discoverable even after the normal checkpoint moves on.
			if err := ledger.deferHour(hour, "missing", nil, now); err != nil {
				return err
			}
			if err := state.Update(uint64(hour.Unix())); err != nil {
				return err
			}
			if err := clearBlobRetryState(retryPath, &retryState); err != nil {
				return err
			}
			log.Printf("Missing eligible blob %s; recorded for later recovery", hour.Format(time.RFC3339))
			continue
		}
		// Network/auth/throttle problems should stop rather than skip. For a
		// demonstrably bad blob, retry up to N runs, then move it to the ledger.
		if errors.Is(failure, errDispatcherIngest) {
			// Do not skip an hour when Dispatcher is unavailable or rejects
			// events. Retry the whole hour on the next invocation.
			return failure
		}
		if errors.Is(failure, errBlobUnstable) {
			// A file being actively written is not a bad file; it must not
			// consume retries or be deferred after three routine polls.
			log.Printf("Blob %s not yet stable; retry on next scheduled run", hour.Format(time.RFC3339))
			return nil
		}
		if errors.Is(failure, errBlobInfrastructure) {
			// These are infrastructure/permission failures rather than proof
			// that a particular blob is corrupt.
			return failure
		}
		attempts, err := recordBlobRetryFailure(retryPath, &retryState, hour)
		if err != nil {
			return err
		}
		if attempts < st.BlobMaxRetryAttempts {
			return fmt.Errorf("blob hour %s failed attempt %d/%d: %w", hour.Format(time.RFC3339), attempts, st.BlobMaxRetryAttempts, failure)
		}
		if err := ledger.deferHour(hour, "retry_exhausted", failure, now); err != nil {
			return err
		}
		if err := state.Update(uint64(hour.Unix())); err != nil {
			return err
		}
		if err := clearBlobRetryState(retryPath, &retryState); err != nil {
			return err
		}
		log.Printf("Blob %s hit retry limit; deferred for automatic recovery: %v", hour.Format(time.RFC3339), failure)
	}
	log.Printf("Blob download run complete, checkpoint %s", time.Unix(int64(state.Last()), 0).UTC().Format(time.RFC3339))
	return nil
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
	data := fmt.Appendf(nil, "%d %d\n", state.hour, state.attempts)
	return vthuntfeed.AtomicWriteFile(path, data, 0644)
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
	scannerBuffer := make([]byte, 0, 64*1024)

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
		scanner.Buffer(scannerBuffer, 10*1024*1024)

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
