package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_lnkInfo_response = testdata.GetFileReportGjson("data/handlersV3/lnk_file.json")
var test_lnkInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionLnkInfo(t *testing.T) {
	description := LnkInfo.Description
	require.Equal(t, 27, len(description))
}

/*Test a file known to have a lnkInfo features.*/
func TestGetLnkInfo(t *testing.T) {
	result, err := LnkInfo.GetFeatures(test_lnkInfo_response)
	require.Equal(t, 26, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header_hot_key", Value: "(0+0)", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "extra_data_dlt_properties_droid_file_id", Value: "d429bedc-4eef-11ef-ba1e-c46516e80701", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "local_path", Value: "C:\\Users\\george\\AppData\\Local\\Programs\\Opera\\opera.exe", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "link_target_id_list_clsid", Value: "59031a47-3f72-44a7-89c5-5595fe6b30ee", Type: bh.AzFTString, Label: "CLSID_ShellDesktop"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "link_target_id_list_item_type_str", Value: "CLSID_ShellDesktop", Type: bh.AzFTString, Label: "CLSID_ShellDesktop"})
	require.Nil(t, err)
}

/*Test a file known to have no lnkInfo features.*/
func TestFailToGetLnkInfo(t *testing.T) {
	result, err := LnkInfo.GetFeatures(test_lnkInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*LnkInfo has no info so it should be none.*/
func TestGetInfoLnkInfo(t *testing.T) {
	result, err := LnkInfo.GetInfo(test_lnkInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
