package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_suricata_response = testdata.GetFileReportGjson("data/handlersV3/wireshark_and_suricata.json")
var test_suricata_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSuricata(t *testing.T) {
	description := Suricata.Description
	require.Equal(t, 3, len(description))
}

/*Test a file known to have a suricata features.*/
func TestGetSuricata(t *testing.T) {
	result, err := Suricata.GetFeatures(test_suricata_response)
	require.Equal(t, 79, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "alert", Value: "ET POLICY Unallocated IP Space Traffic - Bogon Nets", Type: bh.AzFTString, Label: "2002749"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "alert", Value: "ET POLICY Reserved Internal IP Traffic", Type: bh.AzFTString, Label: "2002752"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "classification", Value: "Potentially Bad Traffic", Type: bh.AzFTString, Label: "2001115"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "destinations", Value: "2016-01-07 23:10:41.347453 {TCP} 192.168.122.130:49216 -> 124.108.101.10:443", Type: bh.AzFTString, Label: "2002752"})
	require.Nil(t, err)
}

/*Test a file known to have no suricata features.*/
func TestFailToGetSuricata(t *testing.T) {
	result, err := Suricata.GetFeatures(test_suricata_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*Suricata has no info so it should be none.*/
func TestGetInfoSuricata(t *testing.T) {
	result, err := Suricata.GetInfo(test_suricata_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
