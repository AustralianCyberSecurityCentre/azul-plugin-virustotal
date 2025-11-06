package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_signatureInfo_response = testdata.GetFileReportGjson("data/handlersV3/dotnet_binary.json")
var test_signatureInfo_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")
var test_signatureInfo_complex = testdata.GetFileReportGjson("data/handlersV3/signature_info_complex.json")

/*Test the description is the appropriate length and sample some descriptions.*/
func TestDescriptionSignatureInfo(t *testing.T) {
	description := SignatureInfo.Description
	require.Equal(t, 9, len(description))
}

/*Test a file known to have a signatureInfo features.*/
func TestGetSignatureInfo(t *testing.T) {
	result, err := SignatureInfo.GetFeatures(test_signatureInfo_response)
	require.Equal(t, 7, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "comments", Value: "chocolatey", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "copyright", Value: "Copyright © 2017 Chocolatey Software, Inc.. Copyright © 2011 - 2017, RealDimensions Software, LLC - All Rights Reserved.", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "description", Value: "chocolatey - shim", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "file_version", Value: "0.10.5.0", Type: bh.AzFTString})
	require.Nil(t, err)
}

func TestGetSignatureInfoComplexCase(t *testing.T) {
	result, err := SignatureInfo.GetFeatures(test_signatureInfo_complex)
	require.Equal(t, 2, len(result))
	require.Contains(t, result, events.BinaryEntityFeature{Name: "counter_signers", Value: "DigiCert Timestamp 2022 - 2; DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA; DigiCert Trusted Root G4; DigiCert", Type: bh.AzFTString})
	require.Contains(t, result, events.BinaryEntityFeature{Name: "signing_date", Value: "06:48 AM 08/24/2022", Type: bh.AzFTString})
	require.Nil(t, err)
}

/*Test a file known to have no signatureInfo features.*/
func TestFailToGetSignatureInfo(t *testing.T) {
	result, err := SignatureInfo.GetFeatures(test_signatureInfo_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*SignatureInfo has no info so it should be none.*/
func TestGetInfoSignatureInfo(t *testing.T) {
	result, err := SignatureInfo.GetInfo(test_signatureInfo_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
