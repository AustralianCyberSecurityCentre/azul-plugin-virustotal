package handlersv3

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_bundleInfo_response = testdata.GetFileReportGjson("data/handlersV3/android_apk.json")
var test_bundleInfo_zip_bomb_response = testdata.GetFileReportGjson("data/handlersV3/bundle_info_zip_bomb.json")
var test_bundleInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionBundleInfo(t *testing.T) {
	description := BundleInfo.Description
	require.Equal(t, 10, len(description))
}

/*Test a file known to have a bundleInfo features.*/
func TestGetBundleInfo(t *testing.T) {
	result, err := BundleInfo.GetFeatures(test_bundleInfo_response)
	require.Equal(t, 23, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "file_type_counts", Value: "PNG", Type: bh.AzFTString, Label: "28"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "num_children", Value: "1665", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "highest_datetime", Value: time.Date(1981, time.January, 1, 1, 1, 2, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "uncompressed_size", Value: "47768573", Type: bh.AzFTInteger})
	require.Nil(t, err)
}

/* float file size test case. */
func TestGetBundleInfoFloatFileSize(t *testing.T) {
	result, err := BundleInfo.GetFeatures(test_bundleInfo_zip_bomb_response)
	require.Equal(t, 12, len(result))

	require.Contains(t, result, events.BinaryEntityFeature{Name: "extensions", Value: "png", Type: "string", Label: "257"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "num_children", Value: "614", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "type", Value: "ZIP", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no bundleInfo features.*/
func TestFailToGetBundleInfo(t *testing.T) {
	result, err := BundleInfo.GetFeatures(test_bundleInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*BundleInfo has no info so it should be none.*/
func TestGetInfoBundleInfo(t *testing.T) {
	result, err := BundleInfo.GetInfo(test_bundleInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
