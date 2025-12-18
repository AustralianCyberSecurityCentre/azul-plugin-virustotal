package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_pdfInfo_response = testdata.GetFileReportGjson("data/handlersV3/pdf_file.json")
var test_pdfInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionPdfInfo(t *testing.T) {
	description := PdfInfo.Description
	require.Equal(t, 22, len(description))
}

/*Test a file known to have a pdfInfo features.*/
func TestGetPdfInfo(t *testing.T) {
	result, err := PdfInfo.GetFeatures(test_pdfInfo_response)
	require.Equal(t, 9, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "num_endstream", Value: "9", Type: bh.AzFTInteger})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "header", Value: "%PDF-1.4", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "num_endobj", Value: "32", Type: bh.AzFTInteger})
	require.Nil(t, err)
}

/*Test a file known to have no pdfInfo features.*/
func TestFailToGetPdfInfo(t *testing.T) {
	result, err := PdfInfo.GetFeatures(test_pdfInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*PdfInfo has no info so it should be none.*/
func TestGetInfoPdfInfo(t *testing.T) {
	result, err := PdfInfo.GetInfo(test_pdfInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
