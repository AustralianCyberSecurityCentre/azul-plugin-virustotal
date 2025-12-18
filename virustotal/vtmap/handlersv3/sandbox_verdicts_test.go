package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_sandboxVerdicts_response = testdata.GetFileReportGjson("data/handlersV3/crowdsourced.json")
var test_sandboxVerdicts_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSandboxVerdicts(t *testing.T) {
	description := SandboxVerdicts.Description
	require.Equal(t, 5, len(description))
}

/*Test a file known to have a sandboxVerdicts features.*/
func TestGetSandboxVerdicts(t *testing.T) {
	result, err := SandboxVerdicts.GetFeatures(test_sandboxVerdicts_response)
	require.Equal(t, 17, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "category", Value: "malicious", Type: bh.AzFTString, Label: "CAPE Sandbox"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "category", Value: "malicious", Type: bh.AzFTString, Label: "Zenbox"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "confidence", Value: "100", Type: bh.AzFTInteger, Label: "Zenbox"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "malware_classification", Value: "RAT", Type: bh.AzFTString, Label: "CAPE Sandbox"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "malware_classification", Value: "MALWARE", Type: bh.AzFTString, Label: "CAPE Sandbox"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "sandbox_name", Value: "CAPE Sandbox", Type: bh.AzFTString, Label: "CAPE Sandbox"})
	require.Nil(t, err)
}

/*Test a file known to have no sandboxVerdicts features.*/
func TestFailToGetSandboxVerdicts(t *testing.T) {
	result, err := SandboxVerdicts.GetFeatures(test_sandboxVerdicts_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*SandboxVerdicts has no info so it should be none.*/
func TestGetInfoSandboxVerdicts(t *testing.T) {
	result, err := SandboxVerdicts.GetInfo(test_sandboxVerdicts_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
