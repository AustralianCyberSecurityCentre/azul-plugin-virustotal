package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_classInfo_response = testdata.GetFileReportGjson("data/handlersV3/java_class_bytecode_file.json")
var test_classInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionClassInfo(t *testing.T) {
	description := ClassInfo.Description
	require.Equal(t, 8, len(description))
}

/*Test a file known to have a classInfo features.*/
func TestGetClassInfo(t *testing.T) {
	result, err := ClassInfo.GetFeatures(test_classInfo_response)
	require.Equal(t, 338, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "constants", Value: " what the flip", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "name", Value: "additionallibraries.Additional_Libraries", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "provides", Value: "additionallibraries.Additional_Libraries.ReverseNumbers", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "requires", Value: "java.lang.reflect.Field.setBoolean(java.lang.Object,boolean):void", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no classInfo features.*/
func TestFailToGetClassInfo(t *testing.T) {
	result, err := ClassInfo.GetFeatures(test_classInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*ClassInfo has no info so it should be none.*/
func TestGetInfoClassInfo(t *testing.T) {
	result, err := ClassInfo.GetInfo(test_classInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
