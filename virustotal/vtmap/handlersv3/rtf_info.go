package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatRtfInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("document_properties", bh.VtTypeDict, "document_properties", bh.dont-map, "rtfInfo - structural metadata about the document."),
	bh.NewVtPathToAzFeat("document_properties.custom_xml_data_properties", bh.VtTypeInteger, "document_properties_custom_xml_data_properties", bh.AzFTInteger, "rtfInfo - number of custom XML data objects."),
	bh.NewVtPathToAzFeat("document_properties.default_ansi_codepage", bh.VtTypeString, "document_properties_default_ansi_codepage", bh.AzFTString, "rtfInfo - used codepage (i.e. 'Western European')."),
	bh.NewVtPathToAzFeat("document_properties.default_character_set", bh.VtTypeString, "document_properties_default_character_set", bh.AzFTString, "rtfInfo - character set used (i.e. 'ANSI')."),
	bh.NewVtPathToAzFeat("document_properties.default_languages", bh.VtTypeListOfStrings, "document_properties_default_languages", bh.AzFTString, "rtfInfo - languages detected in the document."),
	bh.NewVtPathToAzFeat("document_properties.dos_stubs", bh.VtTypeInteger, "document_properties_dos_stubs", bh.AzFTInteger, "rtfInfo - number of found DOS stubs."),
	bh.NewVtPathToAzFeat("document_properties.embedded_drawings", bh.VtTypeInteger, "document_properties_embedded_drawings", bh.AzFTInteger, "rtfInfo - number of contained drawings."),
	bh.NewVtPathToAzFeat("document_properties.embedded_pictures", bh.VtTypeInteger, "document_properties_embedded_pictures", bh.AzFTInteger, "rtfInfo - number of embedded pictures."),
	bh.NewVtPathToAzFeat("document_properties.longest_hex_string", bh.VtTypeInteger, "document_properties_longest_hex_string", bh.AzFTInteger, "rtfInfo - longest hexadecimal string found in the document."),
	bh.NewVtPathToAzFeat("document_properties.non_ascii_characters", bh.VtTypeInteger, "document_properties_non_ascii_characters", bh.AzFTInteger, "rtfInfo - number of non-ASCII characters in the document."),
	// bh.NewVtPathToAzFeat("document_properties.objects", bh.VtTypeListOfDict, "document_properties_objects", bh.dont-map, "rtfInfo - list of objects contained. Every item on the list contains the following fields:"),
	bh.NewVtPathToAzFeat("document_properties.objects.class", bh.VtTypeString, "document_properties_objects_class", bh.AzFTString, "rtfInfo - object class.", bh.AddListOfDictHandling("document_properties.objects", "class")),
	bh.NewVtPathToAzFeat("document_properties.objects.type", bh.VtTypeString, "document_properties_objects_type", bh.AzFTString, "rtfInfo - object type.", bh.AddListOfDictHandling("document_properties.objects", "class")),
	bh.NewVtPathToAzFeat("document_properties.read_only_protection", bh.VtTypeBool, "document_properties_read_only_protection", bh.AzFTString, "rtfInfo - noting if file is for read only."),
	bh.NewVtPathToAzFeat("document_properties.rtf_header", bh.VtTypeString, "document_properties_rtf_header", bh.AzFTString, "rtfInfo - RTF header (i.e. 'rtf1')."),
	bh.NewVtPathToAzFeat("document_properties.user_protection", bh.VtTypeBool, "document_properties_user_protection", bh.AzFTString, "rtfInfo - user protection."),
	// bh.NewVtPathToAzFeat("summary_info", bh.VtTypeDict, "summary_info", bh.dont-map, "rtfInfo - other document properties. Additional subfields may be returned, but the most common ones are:"),
	bh.NewVtPathToAzFeat("summary_info.author", bh.VtTypeString, "summary_info_author", bh.AzFTString, "rtfInfo - document author."),
	bh.NewVtPathToAzFeat("summary_info.company", bh.VtTypeString, "summary_info_company", bh.AzFTString, "rtfInfo - document's author's company name."),
	bh.NewVtPathToAzFeat("summary_info.creation_time", bh.VtTypeString, "summary_info_creation_time", bh.AzFTString, "rtfInfo - date of creation in in %Y-%m-%d %H:%M:%S format."),
	bh.NewVtPathToAzFeat("summary_info.editing_time", bh.VtTypeInteger, "summary_info_editing_time", bh.AzFTInteger, "rtfInfo - total editing time in minutes."),
	bh.NewVtPathToAzFeat("summary_info.number_of_characters", bh.VtTypeInteger, "summary_info_number_of_characters", bh.AzFTInteger, "rtfInfo - number of characters in the document."),
	bh.NewVtPathToAzFeat("summary_info.number_of_non_whitespace_characters", bh.VtTypeInteger, "summary_info_number_of_non_whitespace_characters", bh.AzFTInteger, "rtfInfo - non-whitespace characters found."),
	bh.NewVtPathToAzFeat("summary_info.number_of_pages", bh.VtTypeInteger, "summary_info_number_of_pages", bh.AzFTInteger, "rtfInfo - number of pages in the document."),
	bh.NewVtPathToAzFeat("summary_info.number_of_words", bh.VtTypeInteger, "summary_info_number_of_words", bh.AzFTInteger, "rtfInfo - number of words in the document."),
	bh.NewVtPathToAzFeat("summary_info.operator", bh.VtTypeString, "summary_info_operator", bh.AzFTString, "rtfInfo - document creator username."),
	bh.NewVtPathToAzFeat("summary_info.print_time", bh.VtTypeString, "summary_info_print_time", bh.AzFTString, "rtfInfo - date of last printing in %Y-%m-%d %H:%M:%S format."),
	bh.NewVtPathToAzFeat("summary_info.revision_time", bh.VtTypeString, "summary_info_revision_time", bh.AzFTString, "rtfInfo - date of last revision in %Y-%m-%d %H:%M:%S format."),
	bh.NewVtPathToAzFeat("summary_info.title", bh.VtTypeString, "summary_info_title", bh.AzFTString, "rtfInfo - document title."),
	bh.NewVtPathToAzFeat("summary_info.version", bh.VtTypeInteger, "summary_info_version", bh.AzFTInteger, "rtfInfo - RTF version stated in the document."),
	bh.NewVtPathToAzFeat("summary_info.version_number", bh.VtTypeInteger, "summary_info_version_number", bh.AzFTInteger, "rtfInfo - document version number."),
}

var RtfInfo = bh.NewHandlerV3(vtToAzFeatRtfInfo, "rtf_info")
