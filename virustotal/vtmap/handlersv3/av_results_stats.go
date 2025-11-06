package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatAvResultsStats = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("confirmed-timeout", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("confirmed-timeout")),
	bh.NewVtPathToAzFeat("failure", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("failure")),
	bh.NewVtPathToAzFeat("harmless", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("harmless")),
	bh.NewVtPathToAzFeat("malicious", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("malicious")),
	bh.NewVtPathToAzFeat("suspicious", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("suspicious")),
	bh.NewVtPathToAzFeat("timeout", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("timeout")),
	bh.NewVtPathToAzFeat("type-unsupported", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("type-unsupported")),
	bh.NewVtPathToAzFeat("undetected", bh.VtTypeInteger, "av_verdict", bh.AzFTString, "Verdict of AV scanners with the label being the number of AV scanners to have that verdict.", bh.AddStaticValueHandler("undetected")),
}

var AvResultsStats = bh.NewHandlerV3(vtToAzFeatAvResultsStats, "last_analysis_stats")
