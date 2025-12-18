package virustotal

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
)

var testAuthor = events.PluginEntity{
	Name:        "TestAuthor",
	Version:     "2.0.0",
	Contact:     "azul@asd.gov.au",
	Category:    "plugin",
	Description: "Load vt metadata into kafka.",
	Features:    []events.PluginEntityFeature{},
}
var testAuthorSummary = testAuthor.Summary()

func TestParseVTAndBuildSourceV3(t *testing.T) {
	st.MaxAgeHours = -1
	scan := testdata.GetFileBytes("data/load/v3_feed_example.first.json")
	vtmsg, err := ParseVTInfoV3(scan)
	require.Nil(t, err)
	require.Equal(t, &VtMessageCommon{Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8",
		LastScanDate:     time.Date(2024, time.July, 1, 3, 19, 22, 0, time.Local),
		Submission:       VTSubmissionCommon{Id: "a96f7a0a", Region: "?", City: "?", Country: "US", Interface: "api", Filename: ""},
		FileFormatLegacy: "android",
		Size:             25317852,
		DownloadUrl:      "https://www.virustotal.com/api/v3/feeds/files/YmViZGZkODIxNmJjZTVjODFlYmZkY2RmNDk2ZTY5ZDAwZTNhOTIyZmFhNzAxMTBmZWQ4MGQyZTQyODdhMDdmOHx8djN8fDE3MTk4MDYxNTl8fGNiNWQ5OGJmNTA2MzY3ZTUzMzJhZDUyOWEwNjA3OTM0MmJjZGRkZTI5YTAzZTEwYzYxZTQ2ZGVmNTJkNjg2ZDQ/download"},
		vtmsg)

	src, err := BuildSourceV3(vtmsg, &testAuthorSummary)
	require.Nil(t, err)
	require.Equal(t, &events.EventSource{
		Name:       "virustotal",
		References: map[string]string{"interface": "api", "submitter_country": "US", "submitter_id": "a96f7a0a"},
		Security:   "",
		Path: []events.EventSourcePathNode{{
			Author: events.EventAuthor{Name: "TestAuthor", Version: "2.0.0", Category: "plugin", Security: ""},
			Action: "mapped",
			Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8",
			Size:   25317852, FileFormatLegacy: "android", FileFormat: "android/apk",
			Relationship: nil,
			Timestamp:    time.Date(2024, time.July, 1, 3, 19, 22, 0, time.Local)}},
		Timestamp: time.Date(2024, time.July, 1, 3, 19, 22, 0, time.Local)}, src)
}
