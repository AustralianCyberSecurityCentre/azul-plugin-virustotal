package vtdownload

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
)

var client = &http.Client{}
var author = events.PluginEntity{
	Name:        "VirustotalDownload",
	Version:     "2.2.0",
	Contact:     "azul@asd.gov.au",
	Category:    "plugin",
	Description: "Handles requests for downloading binaries from VirusTotal.",
	Features: []events.PluginEntityFeature{
		{Name: "file_format_legacy", Type: "string", Description: "System normalised file type format"},
		{Name: "magic", Type: "string", Description: "File magic description string"},
		{Name: "mime", Type: "string", Description: "File magic mime-type label"},
	},
}

var dpclient *bedclient.Client
var batchSize = 1

// download publishes the vt binary to azul
func download(source, url string, fetchPCAP bool) (*events.BinaryEntity, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", st.VirustotalApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to download from url: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errorMessage, _ := io.ReadAll(resp.Body)
		fmt.Println(string(errorMessage))
		err = fmt.Errorf("VirusTotal HTTP Status Code: %d", resp.StatusCode)
		log.Println(err)
		return nil, err
	}

	log.Println("Streaming sample download to dispatcher store")
	bin, err := dpclient.PostStreamContent(source, resp.Body)
	if err != nil {
		panic(err)
	}
	log.Printf("Successfully download sample: %s (%s) and uploaded to store", bin.Sha256, bin.FileFormatLegacy)
	// best effort to download corresponding pcap
	if fetchPCAP {
		p, err := downloadPcapV2(source, bin.Sha256)
		if err == nil {
			log.Printf("Successfully downloaded PCAP for Sample: %s", bin.Sha256)
			bin.Datastreams = append(bin.Datastreams, *p)
		}
	}

	return bin, nil
}

/* Publishes a pcap to azul using the virustotal v2 API. */
func downloadPcapV2(source, hash string) (*events.BinaryEntityDatastream, error) {
	var label = events.DataLabelPcap
	resp, err := client.Get(fmt.Sprintf("%s/vtapi/v2/file/network-traffic?apikey=%s&hash=%s",
		st.VirustotalApiServer, st.VirustotalApiKey, hash))
	if err != nil {
		log.Printf("Unable to download PCAP: %s", err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("VirusTotal HTTP Status Code: %d", resp.StatusCode)
		log.Println(err)
		return nil, err
	}

	// we read this all into memory so we can do some further checks before uploading
	buf, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Printf("Unable to read PCAP from HTTP Body")
		return nil, err
	}

	if resp.Header.Get("Content-Type") != "application/cap" && resp.Header.Get("Content-Type") != "application/vnd.tcpdump.pcap" {
		err = fmt.Errorf("PCAP Download has mismatched Content-Type: %s", resp.Header.Get("Content-Type"))
		log.Println(err)
		return nil, err
	}

	if len(buf) <= 24 {
		err = fmt.Errorf("empty PCAP returned, size: %d", len(buf))
		return nil, err
	}

	log.Println("Uploading sample PCAP to dispatcher store")
	bin, err := dpclient.PostStream(source, label, bytes.NewReader(buf), &bedclient.PostStreamStruct{})
	return bin, err
}

// notify with generate and publish a 'download' event for error/success download
func notify(event *events.DownloadEvent, hash string, status events.DownloadAction) {
	now := time.Now()
	event.Author = author.Summary()
	event.Action = status
	event.Timestamp = now
	bulk := events.BulkDownloadEvent{Events: []*events.DownloadEvent{event}}
	resp, err := dpclient.PostEvents(&bulk, &bedclient.PublishEventsOptions{Sync: true})
	if err != nil {
		panic(err)
	}
	if resp.TotalFailures > 0 {
		panic("docs failed to publish")
	}
}

// publish will generate and publish a binary event for the downloaded file
func publish(event *events.DownloadEvent, bin *events.BinaryEntity) {
	now := time.Now()
	options := events.NewValidationOptions()
	_, err := bin.ProcessAndValidateBinaryFeatures(options)
	if err != nil {
		panic(err)
	}
	ob := events.BinaryEvent{
		ModelVersion: 3,
		Author:       author.Summary(),
		Timestamp:    now,
		Action:       events.ActionSourced,
		Source:       event.Source,
		Entity:       *bin,
	}

	ob.Source.Path = []events.EventSourcePathNode{{
		Author:           author.Summary(),
		Action:           events.ActionSourced,
		Sha256:           bin.Sha256,
		FileFormatLegacy: bin.FileFormatLegacy,
		FileFormat:       bin.FileFormat,
		Size:             bin.Size,
		Timestamp:        now,
	}}
	bulk := events.BulkBinaryEvent{Events: []*events.BinaryEvent{&ob}}
	resp, err := dpclient.PostEvents(&bulk, &bedclient.PublishEventsOptions{Sync: true})
	if err != nil {
		panic(err)
	}
	if resp.TotalFailures > 0 {
		panic("no valid events submitted")
	}
}

// monitor will find successful download messages to track quotas for categories
func monitor(scoreboard *Scoreboard) {
	for {
		bulk, _, err := dpclient.GetDownloadEvents(&bedclient.FetchEventsStruct{
			Count:       batchSize,
			Deadline:    30,
			RequireLive: true,
			IsTask:      true,
		})
		if err != nil {
			panic(err)
		}
		if len(bulk.Events) == 0 {
			time.Sleep(2000 * time.Millisecond)
			continue
		}
		for _, d := range bulk.Events {
			scoreboard.Feed(&d.Entity, d.Timestamp)
		}
	}
}

func Entrypoint() {
	var err error
	dpclient = bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, st.DeploymentKey)
	err = dpclient.PublishPlugin()
	if err != nil {
		log.Fatal(err)
	}
	scoreboard := NewScoreboard()
	go monitor(scoreboard)

	log.Println("vtdownload plugin starting")

	for {
		bulk, _, err := dpclient.GetDownloadEvents(&bedclient.FetchEventsStruct{
			Count:       batchSize,
			Deadline:    30,
			RequireLive: true,
			IsTask:      true,
		})
		if err != nil {
			panic(err)
		}
		log.Printf("Processing %d downloaded message data.", len(bulk.Events))
		for _, ev := range bulk.Events {
			if ev.Action != events.DownloadActionRequested {
				// skip non-request events
				continue
			}
			log.Printf("Try download author:%s source:%s category:%s for '%s' (source time: %s)", ev.Author.Name, ev.Source.Name, ev.Entity.Category, ev.Entity.Hash, ev.Source.Timestamp)
			if len(ev.Entity.Category) > 0 && ev.Entity.CategoryQuota > 0 && scoreboard.Count(ev.Entity.Category) >= ev.Entity.CategoryQuota {
				log.Printf("Reached Category Quota for: %s of: %d, skipping download", ev.Entity.Category, ev.Entity.CategoryQuota)
				continue
			}
			if len(ev.Entity.Hash) != 64 {
				log.Printf("Bad hash, is not sha256: %s", ev.Entity.Hash)
				continue
			}

			// Check for dupes
			exists, err := dpclient.Exists(ev.Source.Name, events.DataLabelContent, ev.Entity.Hash)
			if err != nil {
				panic(err)
			}
			if exists {
				log.Printf("Already have hash %s in store, skipping download request", ev.Entity.Hash)
				continue
			}
			// V3 API doesn't support PCAP, so the V2 API is used to get PCAPs for files found using the V3 API.

			// Use direct download link
			if len(ev.Entity.DirectURL) > 0 {
				if !time.Now().Before(ev.Entity.DirectExpiry) {
					// save hash lookups for others to use as the api is quota'd
					log.Println("Direct download is expired, not going to download via hash lookup either")
					continue
				}
				// sanity check the url we are going to attempt??
				log.Printf("Category: %s direct downloading from %s", ev.Entity.Category, ev.Entity.DirectURL)
				// No API key required, so API version doesn't matter
				bin, err := download(ev.Source.Name, ev.Entity.DirectURL, ev.Entity.PCAP)

				if err == nil {
					publish(ev, bin)
					notify(ev, ev.Entity.Hash, events.DownloadActionSuccess)
					continue
				} else {
					log.Println("Direct Download Failed, falling back to download via Quota'ed API")
				}
			}

			// use the VT quota'ed API to download via hash
			url := fmt.Sprintf("%s/api/v3/files/%s/download", st.VirustotalApiServer, ev.Entity.Hash)
			bin, err := download(ev.Source.Name, url, ev.Entity.PCAP)
			if err != nil {
				notify(ev, ev.Entity.Hash, events.DownloadActionFailed)
			} else {
				publish(ev, bin)
				notify(ev, ev.Entity.Hash, events.DownloadActionSuccess)
			}
		}
	}
}
