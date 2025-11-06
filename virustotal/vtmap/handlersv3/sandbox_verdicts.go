package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSandboxVerdicts = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("category", bh.VtTypeString, "category", bh.AzFTString, "sandboxVerdicts - normalized verdict category. It can be one of suspicious, malicious, harmless or undetected.", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("confidence", bh.VtTypeInteger, "confidence", bh.AzFTInteger, "sandboxVerdicts - verdict confidence from 0 to 100.", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("malware_classification", bh.VtTypeListOfStrings, "malware_classification", bh.AzFTString, "sandboxVerdicts - raw sandbox verdicts.", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("malware_names", bh.VtTypeListOfStrings, "malware_names", bh.AzFTString, "sandboxVerdicts - malware family names.", bh.AddDictOfDictHandling("")),
	bh.NewVtPathToAzFeat("sandbox_name", bh.VtTypeString, "sandbox_name", bh.AzFTString, "sandboxVerdicts - sandbox that provided the verdict.", bh.AddDictOfDictHandling("")),
}

var SandboxVerdicts = bh.NewHandlerV3(vtToAzFeatSandboxVerdicts, "sandbox_verdicts")
