package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatJarInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("filenames", bh.VtTypeListOfStrings, "filenames", bh.AzFTString, "jarInfo - names of contained files."), // too much data
	bh.NewVtPathToAzFeat("files_by_type", bh.VtTypeDict, "files_by_type", bh.AzFTString, "jarInfo - types and amount of each contained file type. Keys are file types and values are how many of each file type there is."),
	// bh.NewVtPathToAzFeat("manifest", bh.VtTypeString, "manifest", bh.AzFTString, "jarInfo - Jar manifest file content."), // This is too long
	bh.NewVtPathToAzFeat("max_date", bh.VtTypeString, "max_date", bh.AzFTString, "jarInfo - oldest contained file date in %Y-%m-%d %H:%M:%S format."),
	bh.NewVtPathToAzFeat("max_depth", bh.VtTypeInteger, "max_depth", bh.AzFTInteger, "jarInfo - package's maximum directory depth."),
	bh.NewVtPathToAzFeat("min_date", bh.VtTypeString, "min_date", bh.AzFTString, "jarInfo - most recent contained file date in %Y-%m-%d %H:%M:%S format."),
	bh.NewVtPathToAzFeat("packages", bh.VtTypeListOfStrings, "packages", bh.AzFTString, "jarInfo - guess of packages used in the package .class files."),
	bh.NewVtPathToAzFeat("strings", bh.VtTypeListOfStrings, "strings", bh.AzFTString, "jarInfo - interesting strings found in the package .class files."),
	bh.NewVtPathToAzFeat("total_dirs", bh.VtTypeInteger, "total_dirs", bh.AzFTInteger, "jarInfo - number of directories in the package."),
	bh.NewVtPathToAzFeat("total_files", bh.VtTypeInteger, "total_files", bh.AzFTInteger, "jarInfo - number of files in the package."),
}

var JarInfo = bh.NewHandlerV3(vtToAzFeatJarInfo, "jar_info")
