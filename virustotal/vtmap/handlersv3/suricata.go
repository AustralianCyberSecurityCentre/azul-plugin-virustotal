package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSuricata = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("alert", bh.VtTypeString, "alert", bh.AzFTString, "suricata - brief summary about what the alert is detecting.", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("classification", bh.VtTypeString, "classification", bh.AzFTString, "suricata - traffic classification (i.e. 'Potentially Bad Traffic').", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("destinations", bh.VtTypeListOfStrings, "destinations", bh.AzFTString, "suricata - strings in the network captured that matched the rule. Strings start with a date in %Y-%m-%d %H:%M:%S.%f format.", bh.AddDictOfDictHandling("")),
}

var Suricata = bh.NewHandlerV3(vtToAzFeatSuricata, "suricata")
