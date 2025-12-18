package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_androguard_response = testdata.GetFileReportGjson("data/handlersV3/android_apk.json")
var test_androguard_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionAndroguard(t *testing.T) {
	description := Androguard.Description
	require.Equal(t, 28, len(description))
}

func CheckModelContainsValue(t *testing.T) {

}

/*Test a file known to have a androguard features.*/
func TestGetAndroguard(t *testing.T) {
	result, err := Androguard.GetFeatures(test_androguard_response)
	require.Equal(t, 190, len(result))
	// Check a sampling of the values are correct. (dict and string handlers.)
	require.Contains(t, result, events.BinaryEntityFeature{Name: "apk_activities", Value: "com.albamon.app.ui.splash.ActSplash", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "androguard_version", Value: "4.1.2", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "apk_cert_issuer", Value: "C=ko,CN=albamon,DN=C:ko, CN:albamon, L:Seoul, O:Albamon,L=Seoul,O=Albamo", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "apk_risk_indicator_perm", Value: "INTERNET", Type: bh.AzFTString, Label: "1"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "apk_permissions", Value: "android.permission.CHANGE_NETWORK_STATE", Type: bh.AzFTString, Label: "normal"})

	require.Nil(t, err)
}

/*Test a file known to have no androguard features.*/
func TestFailToGetAndroguard(t *testing.T) {
	result, err := Androguard.GetFeatures(test_androguard_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*Androguard has no info so it should be none.*/
func TestGetInfoAndroguard(t *testing.T) {
	result, err := Androguard.GetInfo(test_androguard_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
