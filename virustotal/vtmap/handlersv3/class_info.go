package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatClassInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("constants", bh.VtTypeListOfStrings, "constants", bh.AzFTString, "classInfo - used constants in this class."),
	bh.NewVtPathToAzFeat("extends", bh.VtTypeString, "extends", bh.AzFTString, "classInfo - class that this one inherits."),
	bh.NewVtPathToAzFeat("implements", bh.VtTypeListOfStrings, "implements", bh.AzFTString, "classInfo - implemented interfaces."),
	bh.NewVtPathToAzFeat("methods", bh.VtTypeListOfStrings, "class_methods", bh.AzFTString, "classInfo - methods belonging to the class."),
	bh.NewVtPathToAzFeat("name", bh.VtTypeString, "name", bh.AzFTString, "classInfo - class name."),
	bh.NewVtPathToAzFeat("platform", bh.VtTypeString, "platform", bh.AzFTString, "classInfo - platform as a string, derived from major and minor version number."),
	bh.NewVtPathToAzFeat("provides", bh.VtTypeListOfStrings, "provides", bh.AzFTString, "classInfo - provided classes, fields and methods."),
	bh.NewVtPathToAzFeat("requires", bh.VtTypeListOfStrings, "requires", bh.AzFTString, "classInfo - required classes, fields and methods."),
}

var ClassInfo = bh.NewHandlerV3(vtToAzFeatClassInfo, "class_info")
