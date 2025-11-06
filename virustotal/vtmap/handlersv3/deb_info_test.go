package handlersv3

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_debInfo_response = testdata.GetFileReportGjson("data/handlersV3/debian_package.json")
var test_debInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionDebInfo(t *testing.T) {
	description := DebInfo.Description
	require.Equal(t, 23, len(description))
}

/*Test a file known to have a debInfo features.*/
func TestGetDebInfo(t *testing.T) {
	result, err := DebInfo.GetFeatures(test_debInfo_response)
	require.Equal(t, 18, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "changelog_author", Value: "Andreas Metzler <ametzler@debian.org>", Type: bh.AzFTString})
	// Timezone provided is UTC +0100 with no location given, creating that here.
	timeOne := time.Date(2023, time.January, 8, 19, 7, 53, 0, time.FixedZone("", 60*60))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "changelog_date", Value: timeOne.Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "control_metadata_maintainer", Value: "Andreas Metzler <ametzler@debian.org>", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "structural_metadata_contained_files", Value: "55", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "structural_metadata_max_date", Value: time.Date(2023, time.January, 8, 18, 7, 53, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Nil(t, err)
}

/*Test a file known to have no debInfo features.*/
func TestFailToGetDebInfo(t *testing.T) {
	result, err := DebInfo.GetFeatures(test_debInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*DebInfo has no info so it should be none.*/
func TestGetInfoDebInfo(t *testing.T) {
	result, err := DebInfo.GetInfo(test_debInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
