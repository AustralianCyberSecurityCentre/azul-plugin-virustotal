package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatBundleInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("beginning", bh.VtTypeString, "beginning", bh.AzFTString, "bundleInfo - decompressed head of the file for some file formats: ZLIB and GZIP."),
	bh.NewVtPathToAzFeat("error", bh.VtTypeString, "error", bh.AzFTString, "bundleInfo - error message when attempting to decompress the bundle."),
	bh.NewVtPathToAzFeat("extensions", bh.VtTypeDict, "extensions", bh.AzFTString, "bundleInfo - contains file extensions as key and how many of each one there is inside the bundle as value."),
	bh.NewVtPathToAzFeat("file_types", bh.VtTypeDict, "file_type_counts", bh.AzFTString, "bundleInfo - contains file types as key and how many of each one there is inside the bundle as value."),
	bh.NewVtPathToAzFeat("highest_datetime", bh.VtTypeString, "highest_datetime", bh.AzFTDatetime, "bundleInfo - most recent date in contained files, in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S"), bh.EnableOnlyLogOnError()),
	bh.NewVtPathToAzFeat("lowest_datetime", bh.VtTypeString, "lowest_datetime", bh.AzFTDatetime, "bundleInfo - oldest date in contained files, in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S"), bh.EnableOnlyLogOnError()),
	bh.NewVtPathToAzFeat("num_children", bh.VtTypeInteger, "num_children", bh.AzFTInteger, "bundleInfo - how many files and directories there are inside the bundle."),
	bh.NewVtPathToAzFeat("password", bh.VtTypeString, "password", bh.AzFTString, "bundleInfo - password to decrypt the bundle, if found."),
	bh.NewVtPathToAzFeat("type", bh.VtTypeString, "type", bh.AzFTString, "bundleInfo - bundle type: 'ZIP', 'RAR', 'ZLIB', 'TAR', 'BZIP' and 'GZIP'"),
	bh.NewVtPathToAzFeat("uncompressed_size", bh.VtTypeInteger, "uncompressed_size", bh.AzFTInteger, "bundleInfo - uncompressed size of content inside the compressed file."),
}

var BundleInfo = bh.NewHandlerV3(vtToAzFeatBundleInfo, "bundle_info")
