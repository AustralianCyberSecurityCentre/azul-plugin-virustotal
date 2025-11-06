package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatDetectiteasy = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("filetype", bh.VtTypeString, "filetype", bh.AzFTString, "detectiteasy - 'PE32', 'PE64', 'ELF32', 'ELF64', 'Mach-O64'."),
	bh.NewVtPathToAzFeat("values.info", bh.VtTypeString, "values_info", bh.AzFTString, "detectiteasy - context of the artifact (i.e. 'Native', 'GUI32', 'NRV', etc).", bh.AddListOfDictHandling("values", "name")),
	bh.NewVtPathToAzFeat("values.version", bh.VtTypeString, "values_version", bh.AzFTString, "detectiteasy - version of program.", bh.AddListOfDictHandling("values", "name")),
	bh.NewVtPathToAzFeat("values.type", bh.VtTypeString, "values_type", bh.AzFTString, "detectiteasy - general type of detection ('Linker', 'Compiler', 'Packer', etc).", bh.AddListOfDictHandling("values", "name")),
	bh.NewVtPathToAzFeat("values.name", bh.VtTypeString, "values_name", bh.AzFTString, "detectiteasy - item specific name ('UPX', 'Microsoft Linker', 'gcc(GNU)', etc).", bh.AddListOfDictHandling("values", "name")),
}

var Detectiteasy = bh.NewHandlerV3(vtToAzFeatDetectiteasy, "detectiteasy")
