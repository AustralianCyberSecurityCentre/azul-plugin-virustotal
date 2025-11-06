package handlersv3

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/stretchr/testify/require"
)

var test_authentihash_response = testdata.GetFileReportGjson("data/handlersV3/Win32DLL_multipurpose.json")
var test__authentihash_not_present_response = testdata.GetFileReportGjson("data/handlersV3/worddoc.json")

/*Test the description is valid.*/
func TestDescriptionAuthentihash(t *testing.T) {
	description := Authentihash.Description
	require.Equal(t, 1, len(description))
	require.Equal(t, "pe_authentihash", description[0].Name)
	require.Equal(t, "Authentihash of the PE file", description[0].Description)
	require.Equal(t, bh.AzFTString, description[0].Type)
}

/*Test a file known to have a authentihash.*/
func TestGetAuthentihash(t *testing.T) {
	result, err := Authentihash.GetFeatures(test_authentihash_response)
	require.Equal(t, 1, len(result))
	require.Equal(t, "pe_authentihash", result[0].Name)
	require.Equal(t, bh.AzFTString, result[0].Type)
	require.Equal(t, "8680bb146d201c5282a5a8d24088f9e3e2041503e337bcd33b108a617bb07f08", result[0].Value)
	require.Nil(t, err)
}

/*Test a file known to have no authentihash.*/
func TestFailToGetAuthentihash(t *testing.T) {
	result, err := Authentihash.GetFeatures(test__authentihash_not_present_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}

/*Authentihash has no info so it should be none.*/
func TestGetInfo(t *testing.T) {
	result, err := Authentihash.GetInfo(test_authentihash_response)
	require.Equal(t, 0, len(result))
	require.Nil(t, err)
}
