package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_dotNetAssembly_response = testdata.GetFileReportGjson("data/handlersV3/dotnet_binary.json")
var test_dotNetAssembly_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionDotNetAssembly(t *testing.T) {
	description := DotNetAssembly.Description
	require.Equal(t, 27, len(description))
}

/*Test a file known to have a dotNetAssembly features.*/
func TestGetDotNetAssembly(t *testing.T) {
	result, err := DotNetAssembly.GetFeatures(test_dotNetAssembly_response)
	require.Equal(t, 17, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "assembly_version", Value: "0.10.5.0", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "assembly_flags_text", Value: "afPA_None", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "assembly_name", Value: "clist", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "external_assemblies", Value: "mscorlib", Label: "4.0.0.0", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no dotNetAssembly features.*/
func TestFailToGetDotNetAssembly(t *testing.T) {
	result, err := DotNetAssembly.GetFeatures(test_dotNetAssembly_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*DotNetAssembly has no info so it should be none.*/
func TestGetInfoDotNetAssembly(t *testing.T) {
	result, err := DotNetAssembly.GetInfo(test_dotNetAssembly_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
