/*
Vtquery plugin reads binary events from other sources and looks up VT for any corresponding metadata.
Actual metadata is mapped to binary feature model by publishing the file scan messages to vtmap plugin.
This means we have consistent mapping of fields regardless if vt metadata is coming via bulk loading
with vtload or this plugin's queries (or both).

One difficulty in current approach is that the json format returned via the VT Report API (v2) has
slight differences to the json messages from the bulk File Feed API as loaded by vtload plugin.  The
query API presents aggregated submission information (and is missing submitter details), whereas
the feed API provides per submission/scan including submitter source.

VTMirror/VirusLocal is a python project maintained by the Azul team for creating an indexed, on premise mirror
of VT submission metadata.  This plugin can make use of that project's extended API to get the per
submission messages for mapping if desired.  Alternately, viruslocal or VT proper can be queried via the
V3 report API and produce a single source/submission message based on the last 'scan_time'.  This
behaviour can be controlled via the VIRUSTOTAL_APITYPE and env to 'ReportV3' (default) or 'Submissions'.

API Key to use for querying is specified via VIRUSTOTAL_APIKEY env variable.  Webserver address to query
is specified via VIRUSTOTAL_APISERVER env variable (default: https://www.virustotal.com).

NOTE: reusing the vtmap plugin causes the following consequences:
  - users will see vtquery 'completed' before any mapping may be performed/stored
*/
package vtfilelookup

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"log"
	"net/http"
	"time"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap"

	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
)

const batchSize = 1

var client = &http.Client{}
var author = events.PluginEntity{
	Name:        "VirustotalFileLookup",
	Version:     "2.2.0",
	Contact:     "azul@asd.gov.au",
	Category:    "plugin",
	Description: "Lookup hashes from binary events in virustotal or an offline mirror.",
	Features:    vtmap.TotalFeatureDescriptions(),
}
var authorSummary = author.Summary()
var dpclient *bedclient.Client

// getEventsFromDP sends dispatcher events to channel
func getEventsFromDP(ch chan *events.BinaryEvent) {
	defer close(ch)
	timer := time.Now()
	var count, size int
	for {
		bulk, _, err := dpclient.GetBinaryEvents(&bedclient.FetchEventsStruct{
			Count:          batchSize,
			Deadline:       30,
			RequireLive:    true,
			DenySelf:       true,
			IsTask:         true,
			RequireActions: []events.BinaryAction{events.ActionExtracted, events.ActionSourced},
			RequireSources: strings.Split(st.LookupSources, ","),
		})
		if err != nil {
			panic(err)
		}
		if len(bulk.Events) == 0 {
			if count > 0 {
				duration := float64(time.Since(timer)) / float64(time.Second)
				log.Printf("%d jobs processed in %0.04f seconds", count, duration)
				log.Printf("%0.02f jobs/s %0.02f MB/s", float64(count)/duration, float64(size)/duration/1000/1000)
			}
			log.Println("No jobs waiting, retrying...")
			count = 0
			size = 0
			timer = time.Now()
			time.Sleep(1 * time.Second)
			continue
		}
		for _, event := range bulk.Events {
			count++
			ch <- event
		}
	}
}

func queryVT3FileReport(sha256 string) ([][]byte, error) {
	var resp *http.Response
	var scans [][]byte
	var err error
	get_url := fmt.Sprintf(
		"%s/api/v3/files/%s",
		st.VirustotalApiServer,
		sha256,
	)
	req, _ := http.NewRequest("GET", get_url, nil)
	req.Header.Set("x-apikey", st.VirustotalApiKey)
	resp, err = client.Do(req)

	if err != nil {
		log.Fatalf("ReportV3 failed to get url %s", get_url)
		panic(err)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		// result found add it in.
		scans = [][]byte{buf}
	case 401:
		fallthrough
	case 403:
		log.Printf("%d returned. Did you forget to set VIRUSTOTAL_APIKEY?", resp.StatusCode)
		panic(string(buf))
	case 404:
		// viruslocal returns a 404, not a 200 with response_code
	case 429:
		log.Printf("429 returned; API Quota Exceeded, or too many requests.")
		panic(string(buf))
	default:
		// treat other errors as fatal
		log.Fatalf("Recieved a non 200 status code of %d and response %s", resp.StatusCode, resp.Status)
		log.Fatalf("Get request to get the non 200 response was %s", get_url)
		panic(string(buf))
	}
	return scans, nil

}

func makeCompletionEventV3(scans [][]byte, evIn *events.BinaryEvent, startAt time.Time) (int, *events.StatusEvent, error) {
	// The status event with the filescan results (if any)
	ev := events.StatusEvent{
		ModelVersion: 3,
		Author:       author.Summary(),
		// Timestamp:    st.Now(),
		Entity: events.StatusEntity{
			Status:  events.StatusTypeCompleted,
			Input:   *evIn,
			Results: []events.BinaryEvent{}, // empty 'processing' results
		},
	}

	for _, scan := range scans {
		var msgs []events.BinaryEvent
		var err error
		msgs, err = vtmap.TransformFileReportSingleV3(scan, &authorSummary, &evIn.Source)
		if err != nil {
			panic(err)
		}

		ev.Entity.Results = append(ev.Entity.Results, msgs...)
	}

	// no results from virustotal, optout
	if len(ev.Entity.Results) == 0 {
		ev.Entity.Status = events.StatusTypeOptOut
	}
	duration := float64(time.Since(startAt)) / float64(time.Second)
	ev.Timestamp = st.Now()
	ev.Entity.RunTime = duration
	return len(ev.Entity.Results), &ev, nil
}

func processEvent(ev *events.BinaryEvent) {
	var err error
	startAt := st.Now()
	// list of filescan json messages publish/return
	scans, err := queryVT3FileReport(ev.Entity.Sha256)
	if err != nil {
		panic(err)
	}

	numResults, completion, err := makeCompletionEventV3(scans, ev, startAt)
	if err != nil {
		panic(fmt.Sprintf("failed to generate lookup event %s", ev.Entity.Sha256))
	}
	log.Printf("lookup author:%s source:%s '%s' publishing %d binary events out of %d scan results", ev.Author.Name, ev.Source.Name, ev.Entity.Sha256, numResults, len(scans))
	bulk := events.BulkStatusEvent{Events: []*events.StatusEvent{completion}}
	resp, err := dpclient.PostEvents(&bulk, &bedclient.PublishEventsOptions{Sync: true})
	if err != nil {
		panic("failed to upload")
	}
	if resp.TotalFailures > 0 {
		panic("no valid events submitted")
	}
}

// Entrypoint for running the plugin event loop from the command-line.
func Entrypoint() {
	const workers = 10
	// disable vt records being too old (doesn't make sense here)
	st.MaxAgeHours = -1
	var err error
	log.Println("vtfilelookup starting")
	if len(st.LookupSources) == 0 {
		panic("must set LOOKUP_SOURCES")
	}
	dpclient = bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, st.DeploymentKey)
	err = dpclient.PublishPlugin()
	if err != nil {
		log.Fatal(err)
	}
	chEventsFromDP := make(chan *events.BinaryEvent, workers)
	go getEventsFromDP(chEventsFromDP)

	// start workers to process data
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for d := range chEventsFromDP {
				processEvent(d)
			}
		}()
		wg.Add(1)
	}
	wg.Wait()
}
