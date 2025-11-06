package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatCrowdsourcedIdsStats = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("high", bh.VtTypeInteger, "rule_match_crowd_sourced", bh.AzFTString, "crowdsourcedIdsStats - : number of IDS matched rules having a certain severity.", bh.AddStaticValueHandler("high")),
	bh.NewVtPathToAzFeat("info", bh.VtTypeInteger, "rule_match_crowd_sourced", bh.AzFTString, "crowdsourcedIdsStats - : number of IDS matched rules having a certain severity.", bh.AddStaticValueHandler("info")),
	bh.NewVtPathToAzFeat("low", bh.VtTypeInteger, "rule_match_crowd_sourced", bh.AzFTString, "crowdsourcedIdsStats - : number of IDS matched rules having a certain severity.", bh.AddStaticValueHandler("low")),
	bh.NewVtPathToAzFeat("medium", bh.VtTypeInteger, "rule_match_crowd_sourced", bh.AzFTString, "crowdsourcedIdsStats - : number of IDS matched rules having a certain severity.", bh.AddStaticValueHandler("medium")),
}

var CrowdsourcedIdsStats = bh.NewHandlerV3(vtToAzFeatCrowdsourcedIdsStats, "crowdsourced_ids_stats")
