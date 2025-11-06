package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatKnownDistributors = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("data_sources", bh.VtTypeListOfStrings, "data_sources", bh.AzFTString, "knownDistributors - data sources where the information was ingested from."),
	bh.NewVtPathToAzFeat("distributors", bh.VtTypeListOfStrings, "distributors", bh.AzFTString, "knownDistributors - companies distributing the file."),
	bh.NewVtPathToAzFeat("filenames", bh.VtTypeListOfStrings, "filenames", bh.AzFTString, "knownDistributors - names the file is distributed as."),
	bh.NewVtPathToAzFeat("links", bh.VtTypeListOfStrings, "links", bh.AzFTString, "knownDistributors - URLs to get more information about the file."),
	bh.NewVtPathToAzFeat("products", bh.VtTypeListOfStrings, "products", bh.AzFTString, "knownDistributors - products this file belongs to."),
}

var KnownDistributors = bh.NewHandlerV3(vtToAzFeatKnownDistributors, "known_distributors")
