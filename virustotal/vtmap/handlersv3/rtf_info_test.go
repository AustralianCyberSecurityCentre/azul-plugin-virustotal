package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_rtfInfo_response = testdata.GetFileReportGjson("data/handlersV3/rft_file.json")
var test_rtfInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionRtfInfo(t *testing.T) {
	description := RtfInfo.Description
	require.Equal(t, 28, len(description))
}

/*Test a file known to have a rtfInfo features.*/
func TestGetRtfInfo(t *testing.T) {
	result, err := RtfInfo.GetFeatures(test_rtfInfo_response)
	require.Equal(t, 5, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "document_properties_default_character_set", Value: "ANSI", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "document_properties_longest_hex_string", Value: "5", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "document_properties_read_only_protection", Value: "false", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "document_properties_rtf_header", Value: "rtf", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no rtfInfo features.*/
func TestFailToGetRtfInfo(t *testing.T) {
	result, err := RtfInfo.GetFeatures(test_rtfInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*RtfInfo has no info so it should be none.*/
func TestGetInfoRtfInfo(t *testing.T) {
	result, err := RtfInfo.GetInfo(test_rtfInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
