package handlersv3

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_officeInfo_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")
var test_officeInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/android_apk.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionOfficeInfo(t *testing.T) {
	description := OfficeInfo.Description
	require.Equal(t, 38, len(description))
}

/*Test a file known to have a officeInfo features.*/
func TestGetOfficeInfo(t *testing.T) {
	result, err := OfficeInfo.GetFeatures(test_officeInfo_response)
	require.Equal(t, 41, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_application_name", Value: "Microsoft Word 10.0", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_character_count", Value: "877", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_code_page", Value: "Simplified Chinese GBK", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_creation_datetime", Value: time.Date(2009, time.March, 23, 21, 52, 0, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_revision_number", Value: "2", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "summary_info_last_saved", Value: time.Date(2009, time.March, 23, 21, 52, 0, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "entries_clsid", Value: "00020906-0000-0000-c000-000000000046", Type: bh.AzFTString, Label: "Root Entry"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "entries_type_literal", Value: "root", Type: bh.AzFTString, Label: "Root Entry"})
	require.Nil(t, err)
}

/*Test a file known to have no officeInfo features.*/
func TestFailToGetOfficeInfo(t *testing.T) {
	result, err := OfficeInfo.GetFeatures(test_officeInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*OfficeInfo has no info so it should be none.*/
func TestGetInfoOfficeInfo(t *testing.T) {
	result, err := OfficeInfo.GetInfo(test_officeInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
