package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_common_response = testdata.GetFileReportGjson("data/handlersV3/Win32DLL_multipurpose.json")
var test_common_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")
var test_common_no_tlsh = testdata.GetFileReportGjson("data/handlersV3/tiny_file_no_tlsh.json")

/*Test the description is valid.*/
func TestDescriptionCommon(t *testing.T) {
	description := Common.Description
	require.Equal(t, 5, len(description))
	require.Equal(t, bh.AzFTString, description[0].Type)
}

/*Test a file known to have a Common.*/
func TestGetCommon(t *testing.T) {
	result, err := Common.GetFeatures(test_common_response)
	require.Equal(t, 6, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "tlsh", Value: "T109545A00F6E504B2FA697F3410BA3B325639BE554B75CB9F9754EC1C4D32A82C92632B", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "magic", Value: "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "ssdeep", Value: "3072:qERzjWYWMVVc3RawscaNtIqCnyZio9iT4RXOSL9WnrvAuJ2oBvMpLCtdk6+gQrPW:dRPWNMVy0wsRTJ9LOSZWrvpM1", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "file_type_vt", Value: "pedll", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "tags", Value: "pedll", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "tags", Value: "armadillo", Type: bh.AzFTString})
	require.Nil(t, err)
}

func TestGetCommonNoTlsh(t *testing.T) {
	result, err := Common.GetFeatures(test_common_no_tlsh)
	require.Equal(t, 4, len(result))
	t.Logf("%v", result)
	require.Contains(t, result, events.BinaryEntityFeature{Name: "magic", Value: "Microsoft Windows Autorun file", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "ssdeep", Value: "3:0Vdh4JYh49:Sb4JG49", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "file_type_vt", Value: "ini", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "tags", Value: "ini", Type: bh.AzFTString})

	for _, foundFeat := range result {
		require.NotEqual(t, foundFeat.Name, "tlsh")
	}
	require.Nil(t, err)
}

/*Common has no info so it should be none.*/
func TestCommonInfo(t *testing.T) {
	result, err := Common.GetInfo(test_common_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
