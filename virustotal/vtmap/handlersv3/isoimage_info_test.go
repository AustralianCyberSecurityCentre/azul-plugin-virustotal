package handlersv3

import (
	"testing"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_isoimageInfo_response = testdata.GetFileReportGjson("data/handlersV3/iso_file.json")
var test_isoimageInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionIsoimageInfo(t *testing.T) {
	description := IsoimageInfo.Description
	require.Equal(t, 19, len(description))
}

/*Test a file known to have a isoimageInfo features.*/
func TestGetIsoimageInfo(t *testing.T) {
	result, err := IsoimageInfo.GetFeatures(test_isoimageInfo_response)
	require.Equal(t, 12, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "application_id", Value: "CDIMAGE 2.39 (12/04/97 TM)", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "volume_id", Value: "WIN98 SE", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "min_date", Value: time.Date(1999, time.April, 23, 22, 22, 0, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "max_date", Value: time.Date(1999, time.April, 23, 22, 22, 0, 0, time.UTC).Format(time.RFC3339), Type: bh.AzFTDatetime})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "total_size", Value: "663457602", Type: bh.AzFTInteger})
	require.Nil(t, err)
}

/*Test a file known to have no isoimageInfo features.*/
func TestFailToGetIsoimageInfo(t *testing.T) {
	result, err := IsoimageInfo.GetFeatures(test_isoimageInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*IsoimageInfo has no info so it should be none.*/
func TestGetInfoIsoimageInfo(t *testing.T) {
	result, err := IsoimageInfo.GetInfo(test_isoimageInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
