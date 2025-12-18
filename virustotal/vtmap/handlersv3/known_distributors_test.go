package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_knownDistributors_response = testdata.GetFileReportGjson("data/handlersV3/known_distributor_file.json")
var test_knownDistributors_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionKnownDistributors(t *testing.T) {
	description := KnownDistributors.Description
	require.Equal(t, 5, len(description))
}

/*Test a file known to have a knownDistributors features.*/
func TestGetKnownDistributors(t *testing.T) {
	result, err := KnownDistributors.GetFeatures(test_knownDistributors_response)
	require.Equal(t, 34, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "data_sources", Value: "HashDB", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "distributors", Value: "Linux", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "filenames", Value: "cli-32.exe", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "products", Value: "rocky-linux-cloud-rocky-linux-8-optimized-gcp-v20240611", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "products", Value: "rhel-sap-cloud-rhel-9-2-sap-v20240709", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no knownDistributors features.*/
func TestFailToGetKnownDistributors(t *testing.T) {
	result, err := KnownDistributors.GetFeatures(test_knownDistributors_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*KnownDistributors has no info so it should be none.*/
func TestGetInfoKnownDistributors(t *testing.T) {
	result, err := KnownDistributors.GetInfo(test_knownDistributors_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
