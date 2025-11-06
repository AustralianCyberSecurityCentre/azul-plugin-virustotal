package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_snort_response = testdata.GetFileReportGjson("data/handlersV3/wireshark_and_suricata.json")
var test_snort_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSnort(t *testing.T) {
	description := Snort.Description
	require.Equal(t, 3, len(description))
}

/*Test a file known to have a snort features.*/
func TestGetSnort(t *testing.T) {
	result, err := Snort.GetFeatures(test_snort_response)
	require.Equal(t, 152, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "alert", Value: "DELETED ATTACK RESPONSES directory listing", Type: bh.AzFTString, Label: "496"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "classification", Value: "A Network Trojan was detected", Type: bh.AzFTString, Label: "34335"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "destinations", Value: "2016-01-07 23:10:13.091779 {TCP} 92.51.131.150:80 -> 192.168.122.132:49182", Type: bh.AzFTString, Label: "1394"})
	require.Nil(t, err)
}

/*Test a file known to have no snort features.*/
func TestFailToGetSnort(t *testing.T) {
	result, err := Snort.GetFeatures(test_snort_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*Snort has no info so it should be none.*/
func TestGetInfoSnort(t *testing.T) {
	result, err := Snort.GetInfo(test_snort_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
