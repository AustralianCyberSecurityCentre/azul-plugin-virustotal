package vtfilelookup

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
)

func TestAuthorGetsFeatures(t *testing.T) {
	require.Greater(t, len(author.Features), 30)
}

func SortFeaturesForTests(featuresRef []events.BinaryEntityFeature) {
	sort.Slice(featuresRef, func(i, j int) bool {
		return fmt.Sprintf(
			"%s.%s",
			featuresRef[i].Name,
			featuresRef[i].Value,
		) < fmt.Sprintf(
			"%s.%s",
			featuresRef[j].Name,
			featuresRef[j].Value,
		)
	})
}

/*Dump a EntityBinary to file as json.*/
func DumpExpectedEventToFile(model events.BinaryEvent, filePath []string) {
	rawBytes, err := json.Marshal(model)
	if err != nil {
		panic(err)
	}
	err = testdata.WriteFileBytes(rawBytes, filePath)
	if err != nil {
		panic(err)
	}
}

/*Load a EntityBinary to file as json.*/
func loadEventFromFile(filePath []string) *events.BinaryEvent {
	rawBytes, err := testdata.Data.ReadFile(path.Join(filePath...))
	if err != nil {
		panic(err)
	}
	var returnEvent events.BinaryEvent
	err = json.Unmarshal(rawBytes, &returnEvent)
	if err != nil {
		panic(err)
	}
	return &returnEvent
}

// marshalRound stabilises feature values which can otherwise have time.Time instead of string
func marshalRound(ev *events.BinaryEvent) *events.BinaryEvent {
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	var blah events.BinaryEvent
	err = json.Unmarshal(b, &blah)
	if err != nil {
		panic(err)
	}
	return &blah
}

func TestMakeCompletionEventV3(t *testing.T) {
	st.SetNowToISO("2024-01-01T01:00:00Z")
	st.MaxAgeHours = -1

	raw := testdata.GetFileBytes("data/file_report/v3_sample.content.json")
	datas := [][]byte{raw}
	evIn := events.BinaryEvent{
		Timestamp: time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
		Source: events.EventSource{
			Name: "mysource",
			Path: []events.EventSourcePathNode{{
				Author: events.EventAuthor{
					Name:     "Myplugin",
					Version:  "2.1.0",
					Category: "plugin",
					Security: "",
				},
				Action:           "sourced",
				Sha256:           "0848437c2a0842ea269586b5d26f18ac3df24cf48970ccdc1a49bdb23b78dd85",
				Size:             16512,
				FileFormatLegacy: "HTML",
				FileFormat:       "code/html/component",
				Relationship:     nil,
				Timestamp:        time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
			}},
			Timestamp: time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
		},
		Dequeued: "123",
	}
	numEvents, ev, err := makeCompletionEventV3(datas, &evIn, time.Now())
	require.Nil(t, err)
	require.Equal(t, numEvents, 1)
	// statusEvent, err := event.GetEntityStatus()
	ev.Entity.RunTime = 0
	// require.Nil(t, err)
	results := ev.Entity.Results
	ev.Entity.Results = nil
	// ev.Entity = nil
	require.Equal(t, ev, &events.StatusEvent{
		KafkaKey: "",
		Author: events.EventAuthor{
			Name:     "VirustotalFileLookup",
			Version:  "2.2.0",
			Category: "plugin",
			Security: "",
		},
		ModelVersion: 3,
		Timestamp:    time.Date(2024, time.January, 1, 1, 0, 0, 0, time.UTC),
		Entity: events.StatusEntity{
			Status: "completed",
			Error:  "",
			Input: events.BinaryEvent{
				KafkaKey: "",
				Author: events.EventAuthor{
					Name:     "",
					Version:  "",
					Category: "",
					Security: "",
				},
				ModelVersion: 0,
				Timestamp:    time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
				Source: events.EventSource{
					Name:       "mysource",
					References: map[string]string(nil),
					Security:   "",
					Path: []events.EventSourcePathNode{
						{
							Author: events.EventAuthor{
								Name:     "Myplugin",
								Version:  "2.1.0",
								Category: "plugin",
								Security: "",
							},
							Action: "sourced",
							Sha256: "0848437c2a0842ea269586b5d26f18ac3df24cf48970ccdc1a49bdb23b78dd85",
							Size:   16512, FileFormatLegacy: "HTML", FileFormat: "code/html/component",
							Relationship: nil,
							Timestamp:    time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
						}},
					Timestamp: time.Date(2022, time.September, 12, 23, 36, 47, 0, time.UTC),
				},
				Action:   "",
				Retries:  0,
				Dequeued: "123",
				Entity:   events.BinaryEntity{},
			},
			Results: []events.BinaryEvent(nil),
			RunTime: 0,
		},
	})
	require.Equal(t, len(results), 1)

	// Dump/Load expected event and binary envet.
	filePath := []string{"data", "file_report", "v3_expected_binary_event.json"}
	// DumpExpectedEventToFile(results[0], filePath) // Only needed if model changes
	expectedEvent := loadEventFromFile(filePath)

	SortFeaturesForTests(results[0].Entity.Features)
	SortFeaturesForTests(expectedEvent.Entity.Features)

	require.JSONEq(t, string(expectedEvent.Entity.Info), string(results[0].Entity.Info))
	expectedEvent.Entity.Info = nil
	results[0].Entity.Info = nil

	require.Equal(t, expectedEvent, marshalRound(&results[0]))
}
