package vtselect

import (
	"fmt"

	"path"
	"strings"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtselect/query"
)

var linkExpiryDuration = time.Hour * 24

func makeDownloadEventsV3(rawScan []byte, hits []Rule, author *events.EventAuthor) ([]*events.DownloadEvent, error) {
	// parse vt record metadata
	// FUTURE merge this and the map function's parsing.
	var err error
	vtmsg, err := virustotal.ParseVTInfoV3(rawScan)

	var source *events.EventSource

	if err != nil {
		return nil, fmt.Errorf("parseVTInfo %v", err)
	}
	if vtmsg == nil {
		return nil, fmt.Errorf("unable to parseVTInfo and convert to a message struct")
	}
	// build source information
	source, err = virustotal.BuildSourceV3(vtmsg, author)
	if err != nil {
		return nil, fmt.Errorf("BuildSourceV3 %v", err)
	}
	if source == nil {
		// record was too old
		return nil, nil
	}
	// remove action info
	source.Path[0].Action = ""

	// Validate the Vtmsg
	if len(vtmsg.Sha256) != 64 {
		return nil, fmt.Errorf("bad sha256 %s", vtmsg.Sha256)
	}
	if vtmsg.Size == 0 {
		return nil, fmt.Errorf("bad size %v", vtmsg.Size)
	}

	// ensure it is a reasonable size sample to grab/insert
	if int64(vtmsg.Size) > int64(st.DownloadSizeLimit) {
		// fmt.Printf("skipping download for %s as %d exceeds the size limit of %d bytes", sha256, size, st.DownloadSizeLimit)
		return nil, nil
	}

	// we send a separate download event per hit.. this allows different rules to have different quotas
	ev := events.DownloadEvent{
		ModelVersion: 3,
		Author:       *author,
		Timestamp:    st.Now(),
		Source:       *source,
		Action:       events.DownloadActionRequested,
		Entity:       events.DownloadEntity{Hash: vtmsg.Sha256},
	}

	// if download url missing for some reason, downloader will try with hash instead
	if len(vtmsg.DownloadUrl) > 0 {
		ev.Entity.DirectURL = vtmsg.DownloadUrl
	}

	scantime := vtmsg.LastScanDate
	if !scantime.IsZero() {
		ev.Entity.DirectExpiry = scantime.Add(linkExpiryDuration)
	}

	events := []*events.DownloadEvent{}
	for _, h := range hits {
		group := strings.Split(path.Base(h.path), ".")[0]
		ev.Entity.Category = fmt.Sprintf("%s/%s", group, h.name)
		ev.Entity.CategoryQuota = h.DailyQuota
		// if user has specified to try and collect associated pcap add to request
		// note: this will be a quota'ed api request regardless if direct url link valid
		// in future could be smart and check if vt meta has sandbox results, etc. too
		if h.CollectPCAP {
			ev.Entity.PCAP = true
		}

		events = append(events, &ev)
	}
	return events, nil
}

func findMatchingRules(rawscan []byte) ([]Rule, error) {
	var hits []Rule
	// rules can contain implicitly and'ed filters with semicolons.
	semi := func(c rune) bool {
		return c == ';'
	}

	if !query.Valid(rawscan) {
		return nil, fmt.Errorf("invalid message format: %s", rawscan)
	}

	for _, r := range rules {
		if !query.Matches(rawscan, strings.FieldsFunc(r.Rule, semi)) {
			continue
		}
		hits = append(hits, r)
	}
	return hits, nil
}

func SelectForDownloadV3(raw []byte, author *events.EventAuthor) ([]*events.DownloadEvent, error) {
	hits, err := findMatchingRules(raw)
	if err != nil {
		return nil, err
	}
	events, err := makeDownloadEventsV3(raw, hits, author)

	return events, err
}
