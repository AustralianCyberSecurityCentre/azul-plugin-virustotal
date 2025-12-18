package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_avResults_response = testdata.GetFileReportGjson("data/handlersV3/crowdsourced.json")
var test_avResults_response_2 = testdata.GetFileReportGjson("data/handlersV3/vba_info.json")
var test_avResults_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionAvResults(t *testing.T) {
	description := AvResults.Description
	require.Equal(t, 1, len(description))
}

/*Test a file known to have a AvResults features.*/
func TestGetAvResults(t *testing.T) {
	result, err := AvResults.GetFeatures(test_avResults_response)
	require.Equal(t, 54, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Win-Trojan/OrcusRAT.Exp", Type: bh.AzFTString, Label: "AhnLab-V3"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Generic.OrcusRAT.A.2DC79B36", Type: bh.AzFTString, Label: "MicroWorld-eScan"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "BKDR_ORCUSRAT.SM", Type: bh.AzFTString, Label: "TrendMicro-HouseCall"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Trojan[Spy]/Win32.Agent.foqx", Type: bh.AzFTString, Label: "Antiy-AVL"})
	require.Nil(t, err)
}

/*Test another file known to have a AvResults features.*/
func TestGetAvResults2(t *testing.T) {
	result, err := AvResults.GetFeatures(test_avResults_response_2)
	require.Equal(t, 26, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Virus.MSWord.Hidden.a", Type: bh.AzFTString, Label: "VBA32"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Heur:Trojan.Script.LS_Gencirc.7072535.0", Type: bh.AzFTString, Label: "Tencent"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "malware (ai score=98)", Type: bh.AzFTString, Label: "MAX"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "av_signature", Value: "Virus/MSWord.Hidden", Type: bh.AzFTString, Label: "Antiy-AVL"})
	require.Nil(t, err)
}

/*Test a file known to have no non none AvResults features.*/
func TestFailToGetAvResults(t *testing.T) {
	result, err := AvResults.GetFeatures(test_avResults_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*AvResults has no info so it should be none.*/
func TestGetInfoAvResults(t *testing.T) {
	result, err := AvResults.GetInfo(test_avResults_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
