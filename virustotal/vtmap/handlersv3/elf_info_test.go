package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_elfInfo_response = testdata.GetFileReportGjson("data/handlersV3/elf_file.json")
var test_elfInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionElfInfo(t *testing.T) {
	description := ElfInfo.Description
	require.Equal(t, 25, len(description))
}

/*Test a file known to have a elfInfo features.*/
func TestGetElfInfo(t *testing.T) {
	result, err := ElfInfo.GetFeatures(test_elfInfo_response)
	require.Equal(t, 222, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header_type", Value: "REL (Relocatable file)", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header_os_abi", Value: "UNIX - System V", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header_data", Value: "2's complement, little endian", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header_class", Value: "ELF64", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "export_list_name", Value: "ares_init", Type: bh.AzFTString, Label: "ares_init"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "import_list_name", Value: "gethostname", Type: bh.AzFTString, Label: "gethostname"})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "import_list_name", Value: "ares_destroy_options", Type: bh.AzFTString, Label: "ares_destroy_options"})
	require.Nil(t, err)
}

/*Test a file known to have no elfInfo features.*/
func TestFailToGetElfInfo(t *testing.T) {
	result, err := ElfInfo.GetFeatures(test_elfInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*ElfInfo has no info so it should be none.*/
func TestGetInfoElfInfo(t *testing.T) {
	result, err := ElfInfo.GetInfo(test_elfInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
