package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_sigmaAnalysisStats_response = testdata.GetFileReportGjson("data/handlersV3/crowdsourced.json")
var test_sigmaAnalysisStats_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSigmaAnalysisStats(t *testing.T) {
	description := SigmaAnalysisStats.Description
	require.Equal(t, 4, len(description))
}

/*Test a file known to have a sigmaAnalysisStats features.*/
func TestGetSigmaAnalysisStats(t *testing.T) {
	result, err := SigmaAnalysisStats.GetFeatures(test_sigmaAnalysisStats_response)
	require.Equal(t, 1, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "sigma_severity", Value: "medium", Type: bh.AzFTString, Label: "2"})
	require.Nil(t, err)
}

/*Test a file known to have no sigmaAnalysisStats features.*/
func TestFailToGetSigmaAnalysisStats(t *testing.T) {
	result, err := SigmaAnalysisStats.GetFeatures(test_sigmaAnalysisStats_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*SigmaAnalysisStats has no info so it should be none.*/
func TestGetInfoSigmaAnalysisStats(t *testing.T) {
	result, err := SigmaAnalysisStats.GetInfo(test_sigmaAnalysisStats_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
