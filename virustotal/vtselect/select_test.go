package vtselect

import (
	"encoding/json"
	"os"
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

func TestSelectForDownloadV3(t *testing.T) {
	st.SelectRulesPath = testdata.Dir + "/select_rules/basicv3"
	st.MaxAgeHours = -1
	numRules, err := LoadRules()
	require.Nil(t, err)
	require.Equal(t, numRules, 1)
	require.Equal(t, len(rules), numRules)
	msgs, err := SelectForDownloadV3([]byte(`{"sha256": "example"}`), &testAuthorSummary)
	require.NotNil(t, err)
	require.Equal(t, len(msgs), 0)

	msgs, err = SelectForDownloadV3(
		testdata.GetFileBytes("data/load/v3_feed_example.second.json"),
		&testAuthorSummary,
	)
	require.Nil(t, err)
	require.Equal(t, len(msgs), 1)
}

func TestMakeDownloadEventsV3(t *testing.T) {
	st.SelectRulesPath = testdata.Dir + "/select_rules/basicv3"
	st.MaxAgeHours = -1
	numRules, err := LoadRules()
	require.Nil(t, err)
	require.Equal(t, numRules, 1)
	require.Equal(t, len(rules), numRules)

	evs, err := makeDownloadEventsV3(
		testdata.GetFileBytes("data/load/v3_feed_example.second.json"),
		rules,
		&testAuthorSummary,
	)
	require.Nil(t, err)
	require.Equal(t, len(evs), 1)

	require.EqualExportedValues(t, evs[0], &events.DownloadEvent{
		KafkaKey: "",
		Author: events.EventAuthor{
			Name:     "TestAuthor",
			Version:  "2.0.0",
			Category: "plugin",
			Security: "",
		},
		ModelVersion: 3,
		Timestamp:    time.Date(2024, time.January, 1, 1, 0, 0, 0, time.UTC),
		Source: events.EventSource{
			Name: "virustotal",
			References: map[string]string{
				"interface":         "api",
				"submitter_country": "US",
				"submitter_id":      "a96f7a0a",
			},
			Security: "",
			Path: []events.EventSourcePathNode{
				{
					Author: events.EventAuthor{
						Name:     "TestAuthor",
						Version:  "2.0.0",
						Category: "plugin",
						Security: "",
					},
					Sha256: "f03e48789fe941fdace93275f5e8b9ad3ced7b948b70dc33973f90c4027f7310",
					Size:   1048458, FileFormatLegacy: "android", FileFormat: "android/apk",
					Relationship: map[string]string(nil),
					Timestamp:    time.Date(2024, time.July, 1, 3, 19, 25, 0, time.Local),
				},
			},
			Timestamp: time.Date(2024, time.July, 1, 3, 19, 25, 0, time.Local),
		},
		Action: events.DownloadActionRequested,
		Entity: events.DownloadEntity{
			Hash:          "f03e48789fe941fdace93275f5e8b9ad3ced7b948b70dc33973f90c4027f7310",
			DirectURL:     "https://www.virustotal.com/api/v3/feeds/files/ZjAzZTQ4Nzg5ZmU5NDFmZGFjZTkzMjc1ZjVlOGI5YWQzY2VkN2I5NDhiNzBkYzMzOTczZjkwYzQwMjdmNzMxMHx8djN8fDE3MTk4MDYxNTl8fDJiNWM1NjE4NTA2Yzc0MmY2NjBlY2NlN2NjMDc1MDZlMGIzNzc2OGYzMWRiODZiZTQ5M2FkMjdkZjkyZWZlZmU/download",
			DirectExpiry:  time.Date(2024, time.July, 2, 3, 19, 25, 0, time.Local),
			PCAP:          false,
			Category:      "basicv3/any_av_timeout",
			CategoryQuota: 10,
			Metadata:      json.RawMessage(nil),
		},
	})
}

func TestMain(m *testing.M) {
	st.SetNowToISO("2024-01-01T01:00:00Z")
	ret := m.Run()
	os.Exit(ret)
}
