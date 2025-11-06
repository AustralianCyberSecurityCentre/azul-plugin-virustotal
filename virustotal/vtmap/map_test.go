package vtmap

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
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

func SortFeaturesForTests(featuresRef []events.BinaryEntityFeature) {
	sort.Slice(featuresRef, func(i, j int) bool {
		return fmt.Sprintf("%s.%s", featuresRef[i].Name, featuresRef[i].Value) < fmt.Sprintf("%s.%s", featuresRef[j].Name, featuresRef[j].Value)
	})
}

func TestProcessFileReportCorruptV3(t *testing.T) {
	// file report is missing submitter information, unlike the file feed
	st.MaxAgeHours = -1
	eventIn := []byte(`{"md5": "a77a7a77a7a777a7"}`)
	res, err := TransformFileFeedSingleV3(eventIn, &testAuthorSummary)
	require.Nil(t, err)
	require.Nil(t, res)
}

func TestProcessFileReportSingleV3(t *testing.T) {
	// file report is missing submitter information, unlike the file feed
	st.MaxAgeHours = -1
	now, _ := time.Parse("2006-01-02 15:04:05Z", "2006-01-01 01:00:00Z")
	eventIn := testdata.GetFileBytes("data/load/v3_feed_example.first.json")
	res, err := TransformFileFeedSingleV3(eventIn, &testAuthorSummary)
	require.Nil(t, err)
	require.Equal(t, 1, len(res))
	ev := res[0]
	ev.Timestamp = now
	ev.Source.Path[len(ev.Source.Path)-1].Timestamp = now
	ev.Entity.Info = nil
	// Sort for consistent ordering of features.
	SortFeaturesForTests(ev.Entity.Features)
	require.EqualExportedValues(t, ev, &events.BinaryEvent{
		KafkaKey: "",
		Author: events.EventAuthor{
			Name:     "TestAuthor",
			Version:  "2.0.0",
			Category: "plugin",
			Security: "",
		},
		ModelVersion: 3,
		Timestamp:    now,
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
						Security: ""},
					Action: events.ActionMapped,
					Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8",
					Size:   2.5317852e+07, FileFormatLegacy: "android", FileFormat: "android/apk",
					Relationship: nil,
					Timestamp:    now,
				},
			},
			Timestamp: time.Date(2024, time.July, 1, 3, 19, 22, 0, time.UTC)},
		Action:   "mapped",
		Flags:    events.BinaryFlags{},
		Retries:  0,
		Dequeued: "",
		Entity: events.BinaryEntity{
			Size: 0x18251dc, Sha512: "", Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8", Sha1: "7bf012b3042f4065a0071c08fc45e1af0addeafa", Md5: "56daa605606d14f73f59590db0fb5ad9", Ssdeep: "393216:2qPC+mDx0A5YXA3r8ucDNWhxoKe517BwByloVbZUJ17BPrHudq80kBRjpG5NdNo:xE3rgNIDe517BnlYZ817BidqFkBT", Tlsh: "T197473353FB69941FE47AA53A086901B4D5264F09C243B31B74AC3738777BA880F86BF5", Mime: "application/zip", Magic: "Zip archive data, at least v0.0 to extract, compression method=store", FileFormatLegacy: "android", FileFormat: "android/apk", FileExtension: "apk",
			Features: []events.BinaryEntityFeature{
				{Name: "av_verdict", Value: "failure", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "timeout", Type: "string", Label: "15", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "type-unsupported", Type: "string", Label: "10", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "undetected", Type: "string", Label: "52", Size: 0x0, Offset: 0x0},
				{Name: "extension", Value: "zip", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "dex", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "jsc", Type: "string", Label: "2", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "mp3", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "png", Type: "string", Label: "29", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "so", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type", Value: "ZIP", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "DEX", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "ELF", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "JSON", Type: "string", Label: "3", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "PNG", Type: "string", Label: "29", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "unknown", Type: "string", Label: "966", Size: 0x0, Offset: 0x0},
				{Name: "file_type_vt", Value: "android", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "highest_datetime", Value: "1981-01-01T01:01:02Z", Type: "datetime", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "lowest_datetime", Value: "1981-01-01T01:01:02Z", Type: "datetime", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "magic", Value: "Zip archive data, at least v0.0 to extract, compression method=store", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "mime", Value: "application/zip", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "num_children", Value: "1830", Type: "integer", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "rule_match_crowd_sourced", Value: "low", Type: "string", Label: "4", Size: 0x0, Offset: 0x0},
				{Name: "ssdeep", Value: "393216:2qPC+mDx0A5YXA3r8ucDNWhxoKe517BwByloVbZUJ17BPrHudq80kBRjpG5NdNo:xE3rgNIDe517BnlYZ817BidqFkBT", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "android", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "apk", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-cpu-name", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-gps", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-network-adapters", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "contains-elf", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "obfuscated", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "reflection", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "runtime-modules", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "telephony", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tlsh", Value: "T197473353FB69941FE47AA53A086901B4D5264F09C243B31B74AC3738777BA880F86BF5", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "type", Value: "APK", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "uncompressed_size", Value: "32217115", Type: "integer", Label: "", Size: 0x0, Offset: 0x0}},
			Datastreams: []events.BinaryEntityDatastream{},
			Info:        nil,
		},
	})
}

func TestProcessFileFeedSingleV3(t *testing.T) {
	st.MaxAgeHours = -1
	now, _ := time.Parse("2006-01-02 15:04:05Z", "2006-01-01 01:00:00Z")
	eventIn := testdata.GetFileBytes("data/load/v3_feed_example.first.json")
	res, err := TransformFileFeedSingleV3(eventIn, &testAuthorSummary)
	require.Nil(t, err)
	require.Equal(t, len(res), 1)
	ev := res[0]
	ev.Timestamp = now
	ev.Source.Path[len(ev.Source.Path)-1].Timestamp = now
	ev.Entity.Info = nil
	SortFeaturesForTests(ev.Entity.Features)
	require.EqualExportedValues(t, ev, &events.BinaryEvent{
		KafkaKey:     "",
		Author:       events.EventAuthor{Name: "TestAuthor", Version: "2.0.0", Category: "plugin", Security: ""},
		ModelVersion: 3,
		Timestamp:    time.Date(2006, time.January, 1, 1, 0, 0, 0, time.UTC),
		Source:       events.EventSource{Name: "virustotal", References: map[string]string{"interface": "api", "submitter_country": "US", "submitter_id": "a96f7a0a"}, Security: "", Path: []events.EventSourcePathNode{{Author: events.EventAuthor{Name: "TestAuthor", Version: "2.0.0", Category: "plugin", Security: ""}, Action: "mapped", Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8", Size: 2.5317852e+07, FileFormatLegacy: "android", FileFormat: "android/apk", Relationship: nil, Timestamp: time.Date(2006, time.January, 1, 1, 0, 0, 0, time.UTC)}}, Timestamp: time.Date(2024, time.July, 1, 3, 19, 22, 0, time.UTC)},
		Action:       "mapped",
		Flags:        events.BinaryFlags{},
		Retries:      0,
		Dequeued:     "",
		Entity: events.BinaryEntity{
			Size: 0x18251dc, Sha512: "",
			Sha256: "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8",
			Sha1:   "7bf012b3042f4065a0071c08fc45e1af0addeafa",
			Md5:    "56daa605606d14f73f59590db0fb5ad9",
			Ssdeep: "393216:2qPC+mDx0A5YXA3r8ucDNWhxoKe517BwByloVbZUJ17BPrHudq80kBRjpG5NdNo:xE3rgNIDe517BnlYZ817BidqFkBT",
			Tlsh:   "T197473353FB69941FE47AA53A086901B4D5264F09C243B31B74AC3738777BA880F86BF5",
			Mime:   "application/zip", Magic: "Zip archive data, at least v0.0 to extract, compression method=store",
			FileFormatLegacy: "android", FileFormat: "android/apk", FileExtension: "apk", Features: []events.BinaryEntityFeature{
				{Name: "av_verdict", Value: "failure", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "timeout", Type: "string", Label: "15", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "type-unsupported", Type: "string", Label: "10", Size: 0x0, Offset: 0x0},
				{Name: "av_verdict", Value: "undetected", Type: "string", Label: "52", Size: 0x0, Offset: 0x0},
				{Name: "extension", Value: "zip", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "dex", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "jsc", Type: "string", Label: "2", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "mp3", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "png", Type: "string", Label: "29", Size: 0x0, Offset: 0x0},
				{Name: "extensions", Value: "so", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type", Value: "ZIP", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "DEX", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "ELF", Type: "string", Label: "1", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "JSON", Type: "string", Label: "3", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "PNG", Type: "string", Label: "29", Size: 0x0, Offset: 0x0},
				{Name: "file_type_counts", Value: "unknown", Type: "string", Label: "966", Size: 0x0, Offset: 0x0},
				{Name: "file_type_vt", Value: "android", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "highest_datetime", Value: "1981-01-01T01:01:02Z", Type: "datetime", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "lowest_datetime", Value: "1981-01-01T01:01:02Z", Type: "datetime", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "magic", Value: "Zip archive data, at least v0.0 to extract, compression method=store", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "mime", Value: "application/zip", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "num_children", Value: "1830", Type: "integer", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "rule_match_crowd_sourced", Value: "low", Type: "string", Label: "4", Size: 0x0, Offset: 0x0},
				{Name: "ssdeep", Value: "393216:2qPC+mDx0A5YXA3r8ucDNWhxoKe517BwByloVbZUJ17BPrHudq80kBRjpG5NdNo:xE3rgNIDe517BnlYZ817BidqFkBT", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "android", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "apk", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-cpu-name", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-gps", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "checks-network-adapters", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "contains-elf", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "obfuscated", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "reflection", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "runtime-modules", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tags", Value: "telephony", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "tlsh", Value: "T197473353FB69941FE47AA53A086901B4D5264F09C243B31B74AC3738777BA880F86BF5", Type: "string", Label: "", Size: 0x0, Offset: 0x0},
				{Name: "type", Value: "APK", Type: "string", Label: "", Size: 0x0, Offset: 0x0}, {Name: "uncompressed_size", Value: "32217115", Type: "integer", Label: "", Size: 0x0, Offset: 0x0}},
			Datastreams: []events.BinaryEntityDatastream{},
			Info:        nil,
		},
	})
}

/*Sort features, which is useful for V3 which uses maps and therefore has randomly ordered features.*/
func sortRawBinaryEvent(data []byte) []byte {
	var ev events.BinaryEvent
	err := json.Unmarshal([]byte(data), &ev)
	if err != nil {
		log.Println("Failed during unmarshal of Event")
	}
	SortFeaturesForTests(ev.Entity.Features)
	finalData, err := json.Marshal(&ev)
	if err != nil {
		panic(err)
	}
	return finalData
}

func TestConvertMessageV3(t *testing.T) {
	var err error
	st.MaxAgeHours = -1
	st.SetNowToISO("2024-01-01T01:00:00Z")
	lines := strings.Split(string(testdata.GetFileBytes("data/load/v3_feed_example.json")), "\n")
	line := lines[0]
	datas, err := TransformFileFeedSingleV3([]byte(line), &testAuthorSummary)
	require.Nil(t, err)
	require.Equal(t, 1, len(datas))
	data := datas[0]
	require.NotNil(t, data)
	data.Flags = events.BinaryFlags{}
	cleaned, err := json.Marshal(&data)
	require.Nil(t, err)
	// Marshal and unmarshal to sort events
	cleaned = sortRawBinaryEvent(cleaned)
	cleaned, err = sjson.DeleteBytes(cleaned, "flags")
	require.Nil(t, err)
	require.JSONEq(t, string(cleaned), string(testdata.GetFileBytes("data/load/testConvertMessageV3.expected.json")))
}

func TestConvertMessagesV3(t *testing.T) {
	st.MaxAgeHours = -1
	st.SetNowToISO("2024-01-01T01:00:00Z")
	lines := strings.Split(string(testdata.GetFileBytes("data/load/v3_feed_example.json")), "\n")
	linesExpected := strings.Split(string(testdata.GetFileBytes("data/load/feed_exampleV3.expected_reduced.json")), "\n")
	for i, line := range lines {
		datas, err := TransformFileFeedSingleV3([]byte(line), &testAuthorSummary)
		require.Equal(t, len(datas), 1, fmt.Sprintf("Failed on line (start): %d", i))
		data := datas[0]
		require.Nil(t, err)
		// too much to verify/copy paste for regression testing this stuff
		// other tests check if entity is correct
		cleaned, err := json.Marshal(data)
		require.Nil(t, err)
		cleaned, err = sjson.DeleteBytes(cleaned, "entity")
		require.Nil(t, err)
		cleaned, err = sjson.DeleteBytes(cleaned, "flags")
		require.Nil(t, err)
		fmt.Printf("%v\n", string(cleaned))
		require.JSONEq(t, string(cleaned), linesExpected[i], fmt.Sprintf("Failed on line (compare): %d", i))
	}
}

func TestDropOldDataV3(t *testing.T) {
	st.MaxAgeHours = 72
	hoursAgo := 500
	st.ResetNow()
	newDate := time.Now().UTC().Add(time.Hour * -time.Duration(hoursAgo))
	json := fmt.Sprintf(
		`{"attributes": {"sha256": "random_id", "last_analysis_date": %d, "type_tag": "file-type", "size": 123}}`,
		newDate.Unix())
	datas, err := TransformFileFeedSingleV3([]byte(json), &testAuthorSummary)
	require.Nil(t, err)
	require.GreaterOrEqual(t, len(datas), 0)
}

func TestKeepNewDataV3(t *testing.T) {
	st.MaxAgeHours = 72
	hoursAgo := 2
	st.ResetNow()
	newDate := time.Now().UTC().Add(time.Hour * -time.Duration(hoursAgo))
	json := fmt.Sprintf(
		`{"attributes": {"sha256": "random_id", "last_analysis_date": %d, "type_tag": "file-type", "size": 123}}`,
		newDate.Unix())
	datas, err := TransformFileFeedSingleV3([]byte(json), &testAuthorSummary)
	require.Nil(t, err)
	require.GreaterOrEqual(t, len(datas), 1)
	require.NotNil(t, datas[0])
}

func BenchmarkConvertMessageV3(t *testing.B) {
	st.MaxAgeHours = -1
	lines := strings.Split(string(testdata.GetFileBytes("data/load/v3_feed_example.json")), "\n")
	for n := 0; n < t.N; n++ {
		for _, line := range lines {
			if len(line) > 0 {
				datas, err := TransformFileFeedSingleV3([]byte(line), &testAuthorSummary)
				require.Nil(t, err)
				require.GreaterOrEqual(t, len(datas), 1)
				require.NotNil(t, datas[0])
			}
		}
	}
}
