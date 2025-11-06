// Test / Example event publisher to submit Binaries from the command-line
package vtfilefeed

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/batch"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/download"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/receiver"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtselect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/push"
)

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

func Entrypoint() {
	_, err := vtselect.LoadRules()
	if err != nil {
		panic(err)
	}
	chFromVT := make(chan []byte, 10)
	ctx, cancelFunc := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	// read from VT vs read from stdin
	if st.VirustotalApiKey != "" {
		log.Printf("Downloading from VirusTotal")
		d, err := download.NewDownloader(
			filepath.Join(st.StateDir, "v3_files"),
			st.VirustotalApiServer,
			st.VirustotalApiKey,
		)
		if err != nil {
			panic(err)
		}
		log.Println("Fetching with downloader")
		if len(st.PushGateway) > 0 {
			log.Printf("Setting up worker to push to Prometheus push gateway %s", st.PushGateway)
			wg.Add(1)
			go startPrometheusPusher(ctx, st.PushGateway, &wg)
		}
		go d.Fetch(chFromVT, st.PkgLimit)
	} else {
		log.Println("Running server to allow VT file uploads via POST request.")
		go receiver.RunServer(chFromVT)
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
