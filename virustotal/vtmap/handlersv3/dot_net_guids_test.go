package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_dotNetGuids_response = testdata.GetFileReportGjson("data/handlersV3/dotnet_binary.json")
var test_dotNetGuids_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionDotNetGuids(t *testing.T) {
	description := DotNetGuids.Description
	require.Equal(t, 2, len(description))
}

/*Test a file known to have a dotNetGuids features.*/
func TestGetDotNetGuids(t *testing.T) {
	result, err := DotNetGuids.GetFeatures(test_dotNetGuids_response)
	require.Equal(t, 2, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "mvid", Value: "4b61e161-aeca-41eb-afba-df3fe97d0d63", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "typelib_id", Value: "6104579d-2ee7-414d-b467-aa4a1e2d440a", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no dotNetGuids features.*/
func TestFailToGetDotNetGuids(t *testing.T) {
	result, err := DotNetGuids.GetFeatures(test_dotNetGuids_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*DotNetGuids has no info so it should be none.*/
func TestGetInfoDotNetGuids(t *testing.T) {
	result, err := DotNetGuids.GetInfo(test_dotNetGuids_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
