package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatPasswordInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("type", bh.VtTypeString, "type", bh.AzFTString, "passwordInfo - type of returned value. It can only be 'hashcat'."),
	bh.NewVtPathToAzFeat("value", bh.VtTypeString, "hashcat_password", bh.AzFTString, "passwordInfo - hashcat value."),
}

var PasswordInfo = bh.NewHandlerV3(vtToAzFeatPasswordInfo, "password_info")
