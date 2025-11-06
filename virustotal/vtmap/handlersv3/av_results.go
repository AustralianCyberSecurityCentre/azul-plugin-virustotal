package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatAvResults = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("result", bh.VtTypeString, "av_signature", bh.AzFTString, "Name of antivirus signature that was triggered, labelled by the product name", bh.AddDictOfDictHandling("")),
}

var AvResults = bh.NewHandlerV3(vtToAzFeatAvResults, "last_analysis_results")
