package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_jarInfo_response = testdata.GetFileReportGjson("data/handlersV3/java_file.json")
var test_jarInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionJarInfo(t *testing.T) {
	description := JarInfo.Description
	require.Equal(t, 8, len(description))
}

/*Test a file known to have a jarInfo features.*/
func TestGetJarInfo(t *testing.T) {
	result, err := JarInfo.GetFeatures(test_jarInfo_response)
	require.Equal(t, 133, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "strings", Value: "-Lorg/spongepowered/asm/mixin/injection/Slice", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "packages", Value: "java.lang.Comparable<Ldev.isxander.debugify.fixes", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "max_depth", Value: "7", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "files_by_type", Value: "png", Type: bh.AzFTString, Label: "1"})
	require.Nil(t, err)
}

/*Test a file known to have no jarInfo features.*/
func TestFailToGetJarInfo(t *testing.T) {
	result, err := JarInfo.GetFeatures(test_jarInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*JarInfo has no info so it should be none.*/
func TestGetInfoJarInfo(t *testing.T) {
	result, err := JarInfo.GetInfo(test_jarInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
