package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatPowershellInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("cmdlets", bh.VtTypeListOfStrings, "cmdlets", bh.AzFTString, "powershellInfo - cmdlets used in the script."),
	bh.NewVtPathToAzFeat("cmdlets_alias", bh.VtTypeListOfStrings, "cmdlets_alias", bh.AzFTString, "powershellInfo - cmdlets alias used in the script."),
	bh.NewVtPathToAzFeat("dotnet_calls", bh.VtTypeListOfStrings, "dotnet_calls", bh.AzFTString, "powershellInfo - .Net calls used in the script."),
	bh.NewVtPathToAzFeat("functions", bh.VtTypeListOfStrings, "functions", bh.AzFTString, "powershellInfo - function names defined in the script."),
	bh.NewVtPathToAzFeat("ps_variables", bh.VtTypeListOfStrings, "ps_variables", bh.AzFTString, "powershellInfo - variables used by the script."),
}

var PowershellInfo = bh.NewHandlerV3(vtToAzFeatPowershellInfo, "powershell_info")
