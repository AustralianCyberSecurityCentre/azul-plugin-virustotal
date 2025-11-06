package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_exiftool_response = testdata.GetFileReportGjson("data/handlersV3/Win32DLL_multipurpose.json")
var test_exiftool_pdf_response = testdata.GetFileReportGjson("data/handlersV3/pdf_file.json")

/*Test the description is valid.*/
func TestDescriptionExifTool(t *testing.T) {
	description := ExifTool.Description
	require.Equal(t, 16, len(description))
}

/*Test a file known to have a ExifTool.*/
func TestGetExifToolPE(t *testing.T) {
	result, err := ExifTool.GetFeatures(test_exiftool_response)
	require.Equal(t, 10, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "code_size", Value: "192512", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "entry_point", Value: "0x28c15", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "file_os", Value: "Win32", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "version_number", Value: "2.1.0.22", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "pe_type", Value: "PE32", Type: bh.AzFTString})
	require.Nil(t, err)
}

func TestGetExifToolPdf(t *testing.T) {
	result, err := ExifTool.GetFeatures(test_exiftool_pdf_response)
	require.Equal(t, 8, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "extension", Value: "pdf", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "format", Value: "application/pdf", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "mime", Value: "application/pdf", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "modify_date", Value: "2009:05:11 08:52:14+02:00", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "PDF_version", Value: "1.4", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*ExifTool has no info so it should be none.*/
func TestExifToolInfo(t *testing.T) {
	result, err := ExifTool.GetInfo(test_exiftool_pdf_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
