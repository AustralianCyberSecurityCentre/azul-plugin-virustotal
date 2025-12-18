package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_sigmaAnalysisResults_response = testdata.GetFileReportGjson("data/handlersV3/crowdsourced.json")
var test_sigmaAnalysisResults_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSigmaAnalysisResults(t *testing.T) {
	description := SigmaAnalysisResults.Description
	require.Equal(t, 6, len(description))
}

/*Test a file known to have a sigmaAnalysisResults features.*/
func TestGetSigmaAnalysisResults(t *testing.T) {
	result, err := SigmaAnalysisResults.GetFeatures(test_sigmaAnalysisResults_response)
	require.Equal(t, 12, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "rule_title", Value: "Hidden Executable In NTFS Alternate Data Stream", Type: bh.AzFTString, Label: "5be9da0a90b142239a3ff2819edf2283938855da3b4c80d63d8e6db63c2c4fe7"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "rule_title", Value: "Unsigned DLL Loaded by Windows Utility", Type: bh.AzFTString, Label: "683818f24875a562c0b792edd4183d333b6b0b284ca8a88cc47fb2c9ae5b1473"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "rule_source", Value: "Sigma Integrated Rule Set (GitHub)", Type: bh.AzFTString, Label: "5be9da0a90b142239a3ff2819edf2283938855da3b4c80d63d8e6db63c2c4fe7"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "rule_description", Value: "Detects the creation of an ADS (Alternate Data Stream) that contains an executable by looking at a non-empty Imphash", Type: bh.AzFTString, Label: "5be9da0a90b142239a3ff2819edf2283938855da3b4c80d63d8e6db63c2c4fe7"})
	require.Nil(t, err)
}

/*Test a file known to have no sigmaAnalysisResults features.*/
func TestFailToGetSigmaAnalysisResults(t *testing.T) {
	result, err := SigmaAnalysisResults.GetFeatures(test_sigmaAnalysisResults_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*SigmaAnalysisResults has no info so it should be none.*/
func TestGetInfoSigmaAnalysisResults(t *testing.T) {
	result, err := SigmaAnalysisResults.GetInfo(test_sigmaAnalysisResults_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
