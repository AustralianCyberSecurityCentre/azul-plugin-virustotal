package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatIsoimageInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("abstract_file_id", bh.VtTypeString, "abstract_file_id", bh.AzFTString, "isoimageInfo - filename of a file in the root directory that contains abstract information for this volume set."),
	bh.NewVtPathToAzFeat("application_id", bh.VtTypeString, "application_id", bh.AzFTString, "isoimageInfo - application used to create the file."),
	bh.NewVtPathToAzFeat("bibliographic_file_id", bh.VtTypeString, "bibliographic_file_id", bh.AzFTString, "isoimageInfo - filename of a file in the root directory that contains bibliographic information for this volume set."),
	bh.NewVtPathToAzFeat("copyright_file_id", bh.VtTypeString, "copyright_file_id", bh.AzFTString, "isoimageInfo - filename of a file in the root directory that contains copyright information for this volume set."),
	bh.NewVtPathToAzFeat("created", bh.VtTypeString, "created", bh.AzFTDatetime, "isoimageInfo - file creation time in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("data_preparer_id", bh.VtTypeString, "data_preparer_id", bh.AzFTString, "isoimageInfo - the identifier of the person(s) who prepared the data for this volume."),
	bh.NewVtPathToAzFeat("effective", bh.VtTypeString, "effective", bh.AzFTDatetime, "isoimageInfo - volume effective date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("expires", bh.VtTypeString, "expires", bh.AzFTDatetime, "isoimageInfo - volume expiration date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("file_structure_version", bh.VtTypeInteger, "file_structure_version", bh.AzFTInteger, "isoimageInfo - file structure version."),
	bh.NewVtPathToAzFeat("max_date", bh.VtTypeString, "max_date", bh.AzFTDatetime, "isoimageInfo - most recent contained file date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("min_date", bh.VtTypeString, "min_date", bh.AzFTDatetime, "isoimageInfo - oldest contained file date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("modified", bh.VtTypeString, "modified", bh.AzFTDatetime, "isoimageInfo - last modification date in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("num_files", bh.VtTypeInteger, "num_files", bh.AzFTInteger, "isoimageInfo - number of files contained."),
	bh.NewVtPathToAzFeat("publisher_id", bh.VtTypeString, "publisher_id", bh.AzFTString, "isoimageInfo - volume publisher."),
	bh.NewVtPathToAzFeat("system_id", bh.VtTypeString, "system_id", bh.AzFTString, "isoimageInfo - name of the system that can act on initial sectors (i.e. 'Win32')."),
	bh.NewVtPathToAzFeat("total_size", bh.VtTypeInteger, "total_size", bh.AzFTInteger, "isoimageInfo - the size of the set in this logical volume."),
	bh.NewVtPathToAzFeat("type_code", bh.VtTypeString, "type_code", bh.AzFTString, "isoimageInfo - format type code (i.e. 'CD001')."),
	bh.NewVtPathToAzFeat("volume_id", bh.VtTypeString, "volume_id", bh.AzFTString, "isoimageInfo - volume identifier."),
	bh.NewVtPathToAzFeat("volume_set_id", bh.VtTypeString, "volume_set_id", bh.AzFTString, "isoimageInfo - volume set identifier."),
}

var IsoimageInfo = bh.NewHandlerV3(vtToAzFeatIsoimageInfo, "isoimage_info")
