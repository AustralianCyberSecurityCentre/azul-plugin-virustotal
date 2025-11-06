package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSigmaAnalysisStats = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("critical", bh.VtTypeInteger, "sigma_severity", bh.AzFTString, "sigmaAnalysisStats - number of matched rules for a given severity (check the label for severity).", bh.AddStaticValueHandler("critical")),
	bh.NewVtPathToAzFeat("high", bh.VtTypeInteger, "sigma_severity", bh.AzFTString, "sigmaAnalysisStats - number of matched rules for a given severity (check the label for severity).", bh.AddStaticValueHandler("high")),
	bh.NewVtPathToAzFeat("low", bh.VtTypeInteger, "sigma_severity", bh.AzFTString, "sigmaAnalysisStats - number of matched rules for a given severity (check the label for severity).", bh.AddStaticValueHandler("low")),
	bh.NewVtPathToAzFeat("medium", bh.VtTypeInteger, "sigma_severity", bh.AzFTString, "sigmaAnalysisStats - number of matched rules for a given severity (check the label for severity).", bh.AddStaticValueHandler("medium")),
}

var SigmaAnalysisStats = bh.NewHandlerV3(vtToAzFeatSigmaAnalysisStats, "sigma_analysis_stats")
