package handlersv3

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_peInfo_response = testdata.GetFileReportGjson("data/handlersV3/known_distributor_file.json")
var test_peInfo_huge_response = testdata.GetFileReportGjson("data/handlersV3/too_many_feature_values.json")
var test_peInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")
var test_peInfo_very_long_import_name = testdata.GetFileReportGjson("data/handlersV3/win32_odd_import_library.json")

const MAX_VALUE_DB_STRING = 32766

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionPeInfo(t *testing.T) {
	description := PeInfo.Description
	require.Equal(t, 27, len(description))
}

/*Test a file known to have a peInfo features.*/
func TestGetPeInfo(t *testing.T) {
	result, err := PeInfo.GetFeatures(test_peInfo_response)
	require.Equal(t, 113, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "entry_point", Value: "7047", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "imphash", Value: "e38062877caac65585afa2d2c3200df4", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "machine_type", Value: "332", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "resource_langs", Value: "ENGLISH US", Type: bh.AzFTString, Label: "1"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "timestamp", Value: time.Date(2023, time.May, 20, 1, 52, 26, 0, time.Local).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "sections_virtual_address", Value: "4096", Type: bh.AzFTInteger, Label: ".text"}) // FUTURE - virtual address and size handling
	require.Contains(t, result, events.BinaryEntityFeature{Name: "resource_details_sha256", Value: "4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df", Type: bh.AzFTString, Label: "4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df"})

	require.Nil(t, err)
}

/*Test a value that has a very long string and ensure the value doesn't come through.*/
func TestPEWithLongString(t *testing.T) {
	result, err := PeInfo.GetFeatures(test_peInfo_very_long_import_name)
	require.Equal(t, 30, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "entry_point", Value: "11334", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "sections_md5", Value: "4e8c8bf49149635915b3c6683a7179e5", Type: bh.AzFTString, Label: ".idata2"})
	for _, r := range result {
		require.Less(t, len(r.Value), MAX_VALUE_DB_STRING, "There is a string value that is too long!")
	}
	require.Nil(t, err)
}

/*Test result that provides a 14,000 values to PeInfo gets clipped to a reasonable size.*/
func TestGetPeInfoTooManyValues(t *testing.T) {
	result, err := PeInfo.GetFeatures(test_peInfo_huge_response)
	require.Equal(t, 1679, len(result))
	require.Nil(t, err)
}

/*Test a file known to have no peInfo features.*/
func TestFailToGetPeInfo(t *testing.T) {
	result, err := PeInfo.GetFeatures(test_peInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*PeInfo has no info so it should be none.*/
func TestGetInfoPeInfo(t *testing.T) {
	result, err := PeInfo.GetInfo(test_peInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
