package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_vbaInfo_response = testdata.GetFileReportGjson("data/handlersV3/vba_info.json")
var test_vbaInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionVbaInfo(t *testing.T) {
	description := VbaInfo.Description
	require.Equal(t, 2, len(description))
}

/*Test a file known to have a vbaInfo features.*/
func TestGetVbaInfo(t *testing.T) {
	result, err := VbaInfo.GetFeatures(test_vbaInfo_response)
	require.Equal(t, 6, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "strings", Value: "Kernel32", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "strings", Value: "END_CODE", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no vbaInfo features.*/
func TestFailToGetVbaInfo(t *testing.T) {
	result, err := VbaInfo.GetFeatures(test_vbaInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*VbaInfo has no info so it should be none.*/
func TestGetInfoVbaInfo(t *testing.T) {
	result, err := VbaInfo.GetInfo(test_vbaInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
