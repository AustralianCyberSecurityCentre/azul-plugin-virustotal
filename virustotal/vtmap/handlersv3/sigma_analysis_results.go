package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSigmaAnalysisResults = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("rule_title", bh.VtTypeString, "rule_title", bh.AzFTString, "sigmaAnalysisResults - matched sigma rule title.", bh.AddListOfDictHandling("", "rule_id")),
	bh.NewVtPathToAzFeat("rule_source", bh.VtTypeString, "rule_source", bh.AzFTString, "sigmaAnalysisResults - sigma ruleset where this rule belongs to.", bh.AddListOfDictHandling("", "rule_id")),
	// Not mapping this because there is already way too much content. - Note: would need special mapping to map this as it's a nested list of dict.
	//bh.NewVtPathToAzFeat("match_context", bh.VtTypeDict, "match_context", bh.dont-map, "sigmaAnalysisResults - specific matched events. This dictionary contains the following key:"),
	//bh.NewVtPathToAzFeat("match_context.values", bh.VtTypeDict, "match_context_values", bh.AzFTString, "sigmaAnalysisResults - > all matched events represented as key-value."),
	bh.NewVtPathToAzFeat("rule_level", bh.VtTypeString, "rule_level", bh.AzFTString, "sigmaAnalysisResults - rule level, can be either of 'critical', 'high', 'medium', 'low'.", bh.AddListOfDictHandling("", "rule_id")),
	bh.NewVtPathToAzFeat("rule_description", bh.VtTypeString, "rule_description", bh.AzFTString, "sigmaAnalysisResults - rule description", bh.AddListOfDictHandling("", "rule_id")),
	bh.NewVtPathToAzFeat("rule_author", bh.VtTypeString, "rule_author", bh.AzFTString, "sigmaAnalysisResults - rule author", bh.AddListOfDictHandling("", "rule_id")),
	bh.NewVtPathToAzFeat("rule_id", bh.VtTypeString, "rule_id", bh.AzFTString, "sigmaAnalysisResults - rule ID in VirusTotal. You can use this to find other files matching this same rule.", bh.AddListOfDictHandling("", "rule_id")),
}

var SigmaAnalysisResults = bh.NewHandlerV3(vtToAzFeatSigmaAnalysisResults, "sigma_analysis_results")
