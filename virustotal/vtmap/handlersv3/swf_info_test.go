package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_swfInfo_response = testdata.GetFileReportGjson("data/handlersV3/shock_wave_file.json")
var test_swfInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSwfInfo(t *testing.T) {
	description := SwfInfo.Description
	require.Equal(t, 12, len(description))
}

/*Test a file known to have a swfInfo features.*/
func TestGetSwfInfo(t *testing.T) {
	result, err := SwfInfo.GetFeatures(test_swfInfo_response)
	require.Equal(t, 5, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "duration", Value: "0.03333333333333333", Type: bh.AzFTFloat})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "frame_count", Value: "1", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "frame_size", Value: "480.0x480.0", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "num_swf_tags", Value: "782", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "version", Value: "8", Type: bh.AzFTInteger})
	require.Nil(t, err)
}

/*Test a file known to have no swfInfo features.*/
func TestFailToGetSwfInfo(t *testing.T) {
	result, err := SwfInfo.GetFeatures(test_swfInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*SwfInfo has no info so it should be none.*/
func TestGetInfoSwfInfo(t *testing.T) {
	result, err := SwfInfo.GetInfo(test_swfInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
