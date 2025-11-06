package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSwfInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("compression", bh.VtTypeString, "compression", bh.AzFTString, "swfInfo - used compression type (i.e. 'zlib')."),
	bh.NewVtPathToAzFeat("duration", bh.VtTypeFloat, "duration", bh.AzFTFloat, "swfInfo - length of the media in seconds."),
	bh.NewVtPathToAzFeat("file_attributes", bh.VtTypeListOfStrings, "file_attributes", bh.AzFTString, "swfInfo - specific attributes (i.e. 'ActionScript3', 'UseGPU')."),
	bh.NewVtPathToAzFeat("flash_packages", bh.VtTypeListOfStrings, "flash_packages", bh.AzFTString, "swfInfo - list of used Flash packages."),
	bh.NewVtPathToAzFeat("frame_count", bh.VtTypeInteger, "frame_count", bh.AzFTInteger, "swfInfo - number of frames."),
	bh.NewVtPathToAzFeat("frame_size", bh.VtTypeString, "frame_size", bh.AzFTString, "swfInfo - size of frames in pixels."),
	bh.NewVtPathToAzFeat("metadata", bh.VtTypeString, "metadata", bh.AzFTString, "swfInfo - content of file XML metadata file."),
	bh.NewVtPathToAzFeat("num_swf_tags", bh.VtTypeString, "num_swf_tags", bh.AzFTString, "swfInfo - number of SWF tags."),
	bh.NewVtPathToAzFeat("num_unrecognized_tags", bh.VtTypeInteger, "num_unrecognized_tags", bh.AzFTInteger, "swfInfo - number of unrecognized tags."),
	bh.NewVtPathToAzFeat("suspicious_strings", bh.VtTypeListOfStrings, "suspicious_strings", bh.AzFTString, "swfInfo - list of found suspicious strings."),
	bh.NewVtPathToAzFeat("suspicious_urls", bh.VtTypeListOfStrings, "suspicious_urls", bh.AzFTString, "swfInfo - list of found suspicious URLs."),
	bh.NewVtPathToAzFeat("version", bh.VtTypeInteger, "version", bh.AzFTInteger, "swfInfo - SWF version."),
}

var SwfInfo = bh.NewHandlerV3(vtToAzFeatSwfInfo, "swf_info")
