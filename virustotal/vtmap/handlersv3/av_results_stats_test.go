package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_avResultsStats_response = testdata.GetFileReportGjson("data/handlersV3/android_apk.json")
var test_avResultsStats_response_2 = testdata.GetFileReportGjson("data/handlersV3/vba_info.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionAvResultsStats(t *testing.T) {
	description := AvResultsStats.Description
	require.Equal(t, 8, len(description))
}

/*Test a file known to have a AvResultsStats features.*/
func TestGetAvResultsStats(t *testing.T) {
	result, err := AvResultsStats.GetFeatures(test_avResultsStats_response)
	require.Equal(t, 4, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "failure", Type: bh.AzFTString, Label: "1"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "timeout", Type: bh.AzFTString, Label: "1"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "type-unsupported", Type: bh.AzFTString, Label: "10"})
	require.Nil(t, err)
}

/*Test another file known to have a AvResultsStats features.*/
func TestGetAvResultsStats2(t *testing.T) {
	result, err := AvResultsStats.GetFeatures(test_avResultsStats_response_2)
	require.Equal(t, 3, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "malicious", Type: bh.AzFTString, Label: "26"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "type-unsupported", Type: bh.AzFTString, Label: "14"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_verdict", Value: "undetected", Type: bh.AzFTString, Label: "39"})
	require.Nil(t, err)
}

/*AvResultsStats has no info so it should be none.*/
func TestGetInfoAvResultsStats(t *testing.T) {
	result, err := AvResultsStats.GetInfo(test_avResultsStats_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
