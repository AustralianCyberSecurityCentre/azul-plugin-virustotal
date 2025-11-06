package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_passwordInfo_response = testdata.GetFileReportGjson("data/handlersV3/hash_cat_password_info.json")
var test_passwordInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionPasswordInfo(t *testing.T) {
	description := PasswordInfo.Description
	require.Equal(t, 1, len(description))
}

/*Test a file known to have a passwordInfo features.*/
func TestGetPasswordInfo(t *testing.T) {
	result, err := PasswordInfo.GetFeatures(test_passwordInfo_response)
	require.Equal(t, 1, len(result))
	// require.Contains(t, result, events.BinaryEntityFeature{Name:"type", Value:"hashcat" Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "hashcat_password", Value: "$office$*2007*20*128*16*6b196e3ea658bd554734852ca5911489*ca1835fd42a90d86c0c42c6cc985129a*d34cb58a858a6344c6679e0eea5adb15800805ae", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no passwordInfo features.*/
func TestFailToGetPasswordInfo(t *testing.T) {
	result, err := PasswordInfo.GetFeatures(test_passwordInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*PasswordInfo has no info so it should be none.*/
func TestGetInfoPasswordInfo(t *testing.T) {
	result, err := PasswordInfo.GetInfo(test_passwordInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
