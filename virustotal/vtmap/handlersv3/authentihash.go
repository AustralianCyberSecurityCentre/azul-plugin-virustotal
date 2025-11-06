package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatAuthentihash = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("authentihash", bh.VtTypeString, "pe_authentihash", bh.AzFTString, "Authentihash of the PE file"),
}

var Authentihash = bh.NewHandlerV3(vtToAzFeatAuthentihash, "")
