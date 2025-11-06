package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatVbaInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("deobfuscated_strings", bh.VtTypeListOfStrings, "deobfuscated_strings", bh.AzFTString, "vbaInfo - contains a concatenation of found obfuscated strings."),
	bh.NewVtPathToAzFeat("strings", bh.VtTypeListOfStrings, "strings", bh.AzFTString, "vbaInfo - found strings having a length higher than two."),
}

var VbaInfo = bh.NewHandlerV3(vtToAzFeatVbaInfo, "vba_info")
