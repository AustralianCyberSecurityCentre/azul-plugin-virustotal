package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatDebInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("changelog", bh.VtTypeDict, "changelog", bh.dont-map, "debInfo - information about changes in the packaged version of a project. More info."),
	bh.NewVtPathToAzFeat("changelog.Author", bh.VtTypeString, "changelog_author", bh.AzFTString, "debInfo - author name."),
	bh.NewVtPathToAzFeat("changelog.Date", bh.VtTypeString, "changelog_date", bh.AzFTDatetime, "debInfo - build/last edited date in %a, %d %b %Y %H:%M:%S %z format.", bh.AddDateFormat("%a, %d %b %Y %H:%M:%S %z")),
	bh.NewVtPathToAzFeat("changelog.Debian revision", bh.VtTypeString, "changelog_debian_revision", bh.AzFTString, "debInfo - system revision."),
	bh.NewVtPathToAzFeat("changelog.Debian version", bh.VtTypeString, "changelog_debian_version", bh.AzFTString, "debInfo - system version."),
	bh.NewVtPathToAzFeat("changelog.Distributions", bh.VtTypeString, "changelog_distributions", bh.AzFTString, "debInfo - contains the (space-separated) name(s) of the distribuition(s) where this version of the package should be installed. More info."),
	bh.NewVtPathToAzFeat("changelog.Full version", bh.VtTypeString, "changelog_full_version", bh.AzFTString, "debInfo - full system version."),
	bh.NewVtPathToAzFeat("changelog.Package", bh.VtTypeString, "changelog_package", bh.AzFTString, "debInfo - package type."),
	bh.NewVtPathToAzFeat("changelog.Urgency", bh.VtTypeString, "changelog_urgency", bh.AzFTString, "debInfo - description of how important it is to upgrade to this version from previous ones. Possible values are 'low', 'medium', 'high', 'emergency' or 'critical'. More info."),
	bh.NewVtPathToAzFeat("changelog.Version history", bh.VtTypeString, "changelog_version_history", bh.AzFTString, "debInfo - system version history."),
	// bh.NewVtPathToAzFeat("control_metadata", bh.VtTypeDict, "control_metadata", bh.dont-map, "debInfo - package metadata information. Fields may change from package to package, all values are strings, but some common fields are (more fields listed in the debian docs):"),
	bh.NewVtPathToAzFeat("control_metadata.Maintainer", bh.VtTypeString, "control_metadata_maintainer", bh.AzFTString, "debInfo - maintainer identifier."),
	bh.NewVtPathToAzFeat("control_metadata.Description", bh.VtTypeString, "control_metadata_description", bh.AzFTString, "debInfo - package description."),
	bh.NewVtPathToAzFeat("control_metadata.Package", bh.VtTypeString, "control_metadata_package", bh.AzFTString, "debInfo - package name."),
	bh.NewVtPathToAzFeat("control_metadata.Depends", bh.VtTypeString, "control_metadata_depends", bh.AzFTString, "debInfo - package dependencies."),
	bh.NewVtPathToAzFeat("control_metadata.Version", bh.VtTypeString, "control_metadata_version", bh.AzFTString, "debInfo - package version."),
	bh.NewVtPathToAzFeat("control_metadata.Architecture", bh.VtTypeString, "control_metadata_architecture", bh.AzFTString, "debInfo - architecture for running this software (ie. 'i386')."),
	// bh.NewVtPathToAzFeat("control_scripts", bh.VtTypeDict, "control_scripts", bh.dont-map, "debInfo - scripts to run in package management operations."),
	bh.NewVtPathToAzFeat("control_scripts.postinst", bh.VtTypeString, "control_scripts_postinst", bh.AzFTString, "debInfo - script to run after installation."),
	bh.NewVtPathToAzFeat("control_scripts.postrm", bh.VtTypeString, "control_scripts_postrm", bh.AzFTString, "debInfo - script to run after removal."),
	bh.NewVtPathToAzFeat("control_scripts.preinst", bh.VtTypeString, "control_scripts_preinst", bh.AzFTString, "debInfo - script to run before installation."),
	bh.NewVtPathToAzFeat("control_scripts.prerm", bh.VtTypeString, "control_scripts_prerm", bh.AzFTString, "debInfo - script to run before removal."),
	// bh.NewVtPathToAzFeat("structural_metadata", bh.VtTypeDict, "structural_metadata", bh.dont-map, "debInfo - package structure information:"),
	bh.NewVtPathToAzFeat("structural_metadata.contained_files", bh.VtTypeInteger, "structural_metadata_contained_files", bh.AzFTInteger, "debInfo - number of files inside the package."),
	bh.NewVtPathToAzFeat("structural_metadata.contained_items", bh.VtTypeInteger, "structural_metadata_contained_items", bh.AzFTInteger, "debInfo - number of files and directories inside the package."),
	bh.NewVtPathToAzFeat("structural_metadata.max_date", bh.VtTypeString, "structural_metadata_max_date", bh.AzFTDatetime, "debInfo - oldest child file modification date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("structural_metadata.min_date", bh.VtTypeString, "structural_metadata_min_date", bh.AzFTDatetime, "debInfo - most recent child file modification date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
}

var DebInfo = bh.NewHandlerV3(vtToAzFeatDebInfo, "deb_info")
