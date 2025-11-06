package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_powershellInfo_response = testdata.GetFileReportGjson("data/handlersV3/powershell_script.json")
var test_powershellInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionPowershellInfo(t *testing.T) {
	description := PowershellInfo.Description
	require.Equal(t, 5, len(description))
}

/*Test a file known to have a powershellInfo features.*/
func TestGetPowershellInfo(t *testing.T) {
	result, err := PowershellInfo.GetFeatures(test_powershellInfo_response)
	require.Equal(t, 190, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "cmdlets", Value: "add-type", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "cmdlets_alias", Value: "type", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "dotnet_calls", Value: "Security.Principal.WindowsIdentity", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "functions", Value: "Copy-Files", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "ps_variables", Value: "$args", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no powershellInfo features.*/
func TestFailToGetPowershellInfo(t *testing.T) {
	result, err := PowershellInfo.GetFeatures(test_powershellInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*PowershellInfo has no info so it should be none.*/
func TestGetInfoPowershellInfo(t *testing.T) {
	result, err := PowershellInfo.GetInfo(test_powershellInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
