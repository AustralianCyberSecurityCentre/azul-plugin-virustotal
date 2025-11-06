package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_detectiteasy_response = testdata.GetFileReportGjson("data/handlersV3/elf_file.json")
var test_detectiteasy_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionDetectiteasy(t *testing.T) {
	description := Detectiteasy.Description
	require.Equal(t, 5, len(description))
}

/*Test a file known to have a detectiteasy features.*/
func TestGetDetectiteasy(t *testing.T) {
	result, err := Detectiteasy.GetFeatures(test_detectiteasy_response)
	require.Equal(t, 8, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "filetype", Value: "ELF64", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "values_info", Value: "REL AMD64-64", Type: bh.AzFTString, Label: "Unix"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "values_info", Value: "REL AMD64-64", Type: bh.AzFTString, Label: "gcc"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "values_version", Value: "(GNU) 5.3.1 20160406 (Red Hat 5.3.1-6)", Type: bh.AzFTString, Label: "gcc"})

	require.Nil(t, err)
}

/*Test a file known to have no detectiteasy features.*/
func TestFailToGetDetectiteasy(t *testing.T) {
	result, err := Detectiteasy.GetFeatures(test_detectiteasy_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*Detectiteasy has no info so it should be none.*/
func TestGetInfoDetectiteasy(t *testing.T) {
	result, err := Detectiteasy.GetInfo(test_detectiteasy_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
