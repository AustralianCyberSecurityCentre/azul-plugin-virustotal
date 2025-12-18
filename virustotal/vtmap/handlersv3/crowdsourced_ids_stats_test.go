package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_crowdsourcedIdsStats_response = testdata.GetFileReportGjson("data/handlersV3/crowdsourced.json")
var test_crowdsourcedIdsStats_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionCrowdsourcedIdsStats(t *testing.T) {
	description := CrowdsourcedIdsStats.Description
	require.Equal(t, 4, len(description))
}

/*Test a file known to have a crowdsourcedIdsStats features.*/
func TestGetCrowdsourcedIdsStats(t *testing.T) {
	result, err := CrowdsourcedIdsStats.GetFeatures(test_crowdsourcedIdsStats_response)
	require.Equal(t, 1, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "rule_match_crowd_sourced", Value: "low", Type: bh.AzFTString, Label: "4"})
	require.Nil(t, err)
}

/*Test a file known to have no crowdsourcedIdsStats features.*/
func TestFailToGetCrowdsourcedIdsStats(t *testing.T) {
	result, err := CrowdsourcedIdsStats.GetFeatures(test_crowdsourcedIdsStats_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*CrowdsourcedIdsStats has no info so it should be none.*/
func TestGetInfoCrowdsourcedIdsStats(t *testing.T) {
	result, err := CrowdsourcedIdsStats.GetInfo(test_crowdsourcedIdsStats_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
