package vthuntfeed

import (
	"fmt"
	"io"

	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/client"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/tidwall/gjson"
)

const source = "vtlivehunt"
const requestBatch = 40

var client = &http.Client{}
var author = events.PluginEntity{
	Name:        "VirustotalHuntFeed",
	Version:     "2.2.0",
	Category:    "loader",
	Contact:     "azul@asd.gov.au",
	Description: "Use periodically to poll for latest livehunt notifications and trigger download of hits.",
}

// FUTURE: allow filtering by ruleset name/prefix
var dpclient *bedclient.Client
var virustotal = "https://www.virustotal.com/api/v3/intelligence"
var stateDir string
var resultLimit uint32
var deploymentKey string

// FUTURE: enable rule regex
//var ruleRegex *regexp.Regexp

func setup() {
	stateDir = os.Getenv("STATEDIR")
	if len(stateDir) == 0 {
		stateDir = ".huntstate"
	}
	err := os.MkdirAll(stateDir, 0755)
	if err != nil {
		panic(err)
	}
	limit := os.Getenv("RESULT_LIMIT")
	if len(limit) == 0 {
		resultLimit = 50
	} else {
		tmp, err := strconv.Atoi(limit)
		if err != nil {
			panic(err)
		}
		resultLimit = uint32(tmp)
	}
	deploymentKey = os.Getenv("PLUGIN_DEPLOYMENT_KEY")
	if len(deploymentKey) == 0 {
		deploymentKey = "plugin-vthuntfeed"
	}
	// FUTURE: enable rule regex
	//ruleRegex = regexp.MustCompile(`rule\s+(\w+)[\s{]`)
}

// Download sends a binary_matched event and triggers a download_request from VT.
func download(hash string, source events.EventSource) {
	var err error
	now := time.Now()
	// send download request
	de := events.DownloadEvent{
		ModelVersion: 3,
		Author:       author.Summary(),
		Timestamp:    now,
		Action:       events.DownloadActionRequested,
		Source:       source,
		Entity: events.DownloadEntity{
			Hash:          hash,
			Category:      fmt.Sprintf("%s/%s", source.Name, source.References["subject"]),
			CategoryQuota: resultLimit,
		},
	}
	de.Source.Path = append(source.Path, events.EventSourcePathNode{
		Author:    author.Summary(),
		Sha256:    hash,
		Timestamp: now,
	})
	bulk := events.BulkDownloadEvent{Events: []*events.DownloadEvent{&de}}
	resp, err := dpclient.PostEvents(&bulk, &bedclient.PublishEventsOptions{Sync: true})
	if err != nil {
		panic(err)
	}
	if resp.TotalFailures > 0 {
		panic("no valid events submitted")
	}
}

// Fetch polls the VT API for the latest batch of livehunt notifications and then downloads any hits.
func fetch() {
	var err error
	dpclient = bedclient.NewClient(st.DispatcherEventsUrl, st.DispatcherDataUrl, author, deploymentKey)
	err = dpclient.PublishPlugin()
	if err != nil {
		log.Fatal(err)
	}
	liveState, err := NewState(path.Join(stateDir, "livehunt"))
	if err != nil {
		panic(err)
	}
	// making assumption most recent results are first
	log.Println("Fetching latest batch of live hunt notifications...")
	get_url := fmt.Sprintf(`%s/hunting_notification_files?limit=%d`, virustotal, requestBatch)
	req, _ := http.NewRequest("GET", get_url, nil)
	req.Header.Set("x-apikey", st.VirustotalApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Hunt notifications not found at Get url: %s", get_url)
		panic(err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Unexpected HTTP status returned: %d", resp.StatusCode)
		panic(body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed reading response body: %s", err)
	}
	resp.Body.Close()
	log.Println("Huntfeed parsing body of get file request.")
	doc := gjson.ParseBytes(body)
	if !doc.Exists() {
		panic("parsing error")
	}
	doc.Get("data|@reverse").ForEach(func(_, field gjson.Result) bool {
		date := field.Get("context_attributes.hunting_notification_date").Uint()
		if liveState.After(date) {
			return true
		}
		// new notification
		hash := field.Get("attributes.sha256").String()
		subject := field.Get("context_attributes.hunting_notification_subject").String()
		ruleset := field.Get("context_attributes.hunting_ruleset_id").Uint()
		source := events.EventSource{
			Name: source,
			References: map[string]string{
				"subject": subject,
				"ruleset": strconv.FormatUint(ruleset, 10), // FUTURE: enrich with context
			},
			Path:      []events.EventSourcePathNode{},
			Timestamp: time.Unix(int64(date), 0),
		}
		log.Printf("Live Hit Found: %s %s %d - Requesting Download", subject, hash, date)
		download(hash, source)
		err = liveState.Update(date)
		if err != nil {
			log.Printf("unable to update state: %s", err)
		}
		return true
	})
}

func Entrypoint() {
	setup()
	fetch()
	log.Println("Successfully finished latest hunt notifications.")
}
