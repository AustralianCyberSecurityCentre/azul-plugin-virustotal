package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatOfficeInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("documment_summary_info", bh.VtTypeDict, "documment_summary_info", bh.dont-map, "officeInfo - some of the metadata about the office file is here."),
	bh.NewVtPathToAzFeat("documment_summary_info.characters_with_spaces", bh.VtTypeInteger, "documment_summary_info_characters_with_spaces", bh.AzFTInteger, "officeInfo - number of characters including spaces."),
	bh.NewVtPathToAzFeat("documment_summary_info.code_page", bh.VtTypeString, "documment_summary_info_code_page", bh.AzFTString, "officeInfo - character set used for this document."),
	bh.NewVtPathToAzFeat("documment_summary_info.company", bh.VtTypeString, "documment_summary_info_company", bh.AzFTString, "officeInfo - company name."),
	bh.NewVtPathToAzFeat("documment_summary_info.hyperlinks_changed", bh.VtTypeBool, "documment_summary_info_hyperlinks_changed", bh.AzFTString, "officeInfo - one or more hyperlinks in this part were updated exclusively in this part by a producer."),
	bh.NewVtPathToAzFeat("documment_summary_info.line_count", bh.VtTypeInteger, "documment_summary_info_line_count", bh.AzFTInteger, "officeInfo - number of lines."),
	bh.NewVtPathToAzFeat("documment_summary_info.links_dirty", bh.VtTypeBool, "documment_summary_info_links_dirty", bh.AzFTString, "officeInfo - whether the custom links are hampered by excessive noise, for all applications."),
	bh.NewVtPathToAzFeat("documment_summary_info.paragraph_count", bh.VtTypeInteger, "documment_summary_info_paragraph_count", bh.AzFTInteger, "officeInfo - number of paragraphs."),
	bh.NewVtPathToAzFeat("documment_summary_info.scale", bh.VtTypeBool, "documment_summary_info_scale", bh.AzFTString, "officeInfo - true if scaling of thumbnail is required, False to use cropping."),
	bh.NewVtPathToAzFeat("documment_summary_info.shared_document", bh.VtTypeBool, "documment_summary_info_shared_document", bh.AzFTString, "officeInfo - note if is a shared document."),
	bh.NewVtPathToAzFeat("documment_summary_info.version", bh.VtTypeInteger, "documment_summary_info_version", bh.AzFTInteger, "officeInfo - identifier of Microsoft Office application."),
	// bh.NewVtPathToAzFeat("entries", bh.VtTypeListOfDict, "entries", bh.dont-map, "officeInfo - contains OLE objects in the document. Every item in the list contains the following fields:"),
	bh.NewVtPathToAzFeat("entries.clsid", bh.VtTypeString, "entries_clsid", bh.AzFTString, "officeInfo - application unique identifier.", bh.AddListOfDictHandling("entries", "name")),
	bh.NewVtPathToAzFeat("entries.clsid_literal", bh.VtTypeString, "entries_clsid_literal", bh.AzFTString, "officeInfo - readable version of clsid.", bh.AddListOfDictHandling("entries", "name")),
	bh.NewVtPathToAzFeat("entries.name", bh.VtTypeString, "entries_name", bh.AzFTString, "officeInfo - object name.", bh.AddListOfDictHandling("entries", "name")),
	bh.NewVtPathToAzFeat("entries.sid", bh.VtTypeInteger, "entries_sid", bh.AzFTInteger, "officeInfo - index of the entry in the OLE directory.", bh.AddListOfDictHandling("entries", "name")),
	bh.NewVtPathToAzFeat("entries.size", bh.VtTypeInteger, "entries_size", bh.AzFTInteger, "officeInfo - object size in bytes.", bh.AddListOfDictHandling("entries", "name")),
	bh.NewVtPathToAzFeat("entries.type_literal", bh.VtTypeString, "entries_type_literal", bh.AzFTString, "officeInfo - object type.", bh.AddListOfDictHandling("entries", "name")),
	// bh.NewVtPathToAzFeat("ole", bh.VtTypeDict, "ole", bh.dont-map, "officeInfo - like macros found in the OLE directory."),
	// bh.NewVtPathToAzFeat("ole.macros", bh.VtTypeListOfDict, "ole_macros", bh.dont-map, "officeInfo - details of macros found."),
	bh.NewVtPathToAzFeat("ole.macros.length", bh.VtTypeInteger, "ole_macros_length", bh.AzFTInteger, "officeInfo - macro length.", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.macros.patterns", bh.VtTypeListOfStrings, "ole_macros_patterns", bh.AzFTString, "officeInfo - interesting patterns found ('exe-pattern', 'url-pattern', etc.).", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.macros.properties", bh.VtTypeListOfStrings, "ole_macros_properties", bh.AzFTString, "officeInfo - interesting properties ('obfuscated', 'run-file', etc.).", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.macros.stream_path", bh.VtTypeString, "ole_macros_stream_path", bh.AzFTString, "officeInfo - path in the OLE strorage tree.", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.macros.vba_code", bh.VtTypeString, "ole_macros_vba_code", bh.AzFTString, "officeInfo - macro code.", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.macros.vba_filename", bh.VtTypeString, "ole_macros_vba_filename", bh.AzFTString, "officeInfo - name of the macro.", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	bh.NewVtPathToAzFeat("ole.num_macros", bh.VtTypeInteger, "ole_num_macros", bh.AzFTInteger, "officeInfo - number of found macros.", bh.AddListOfDictHandling("ole.macros", "vba_filename")),
	// bh.NewVtPathToAzFeat("summary_info", bh.VtTypeDict, "summary_info", bh.dont-map, "officeInfo - other set of metadata about the office file is here. Depending on the type of Office file, some fields may appear or not."),
	bh.NewVtPathToAzFeat("summary_info.application_name", bh.VtTypeString, "summary_info_application_name", bh.AzFTString, "officeInfo - specific Office application (i.e. 'Microsoft PowerPoint')."),
	bh.NewVtPathToAzFeat("summary_info.author", bh.VtTypeString, "summary_info_author", bh.AzFTString, "officeInfo - original user who created the file."),
	bh.NewVtPathToAzFeat("summary_info.character_count", bh.VtTypeInteger, "summary_info_character_count", bh.AzFTInteger, "officeInfo - number of characters in the document."),
	bh.NewVtPathToAzFeat("summary_info.code_page", bh.VtTypeString, "summary_info_code_page", bh.AzFTString, "officeInfo - character set used for this document (i.e. 'Latin I')."),
	bh.NewVtPathToAzFeat("summary_info.creation_datetime", bh.VtTypeString, "summary_info_creation_datetime", bh.AzFTDatetime, "officeInfo - date of creation in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("summary_info.edit_time", bh.VtTypeInteger, "summary_info_edit_time", bh.AzFTInteger, "officeInfo - time spent editing the document, in seconds."),
	bh.NewVtPathToAzFeat("summary_info.last_author", bh.VtTypeString, "summary_info_last_author", bh.AzFTString, "officeInfo - last user who edited the file."),
	bh.NewVtPathToAzFeat("summary_info.last_printed", bh.VtTypeString, "summary_info_last_printed", bh.AzFTDatetime, "officeInfo - date of last printing in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("summary_info.last_saved", bh.VtTypeString, "summary_info_last_saved", bh.AzFTDatetime, "officeInfo - date of last saving, in %Y-%m-%d %H:%M:%S format.", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("summary_info.page_count", bh.VtTypeInteger, "summary_info_page_count", bh.AzFTInteger, "officeInfo - number of pages of the document."),
	bh.NewVtPathToAzFeat("summary_info.revision_number", bh.VtTypeInteger, "summary_info_revision_number", bh.AzFTInteger, "officeInfo - document revision number."),
	bh.NewVtPathToAzFeat("summary_info.security", bh.VtTypeInteger, "summary_info_security", bh.AzFTInteger, "officeInfo - 0 if no password.", bh.AddAllowIntegerToBeZero()),
	bh.NewVtPathToAzFeat("summary_info.template", bh.VtTypeString, "summary_info_template", bh.AzFTString, "officeInfo - template use to create this file."),
	bh.NewVtPathToAzFeat("summary_info.title", bh.VtTypeString, "summary_info_title", bh.AzFTString, "officeInfo - document title."),
	bh.NewVtPathToAzFeat("summary_info.word_count", bh.VtTypeInteger, "summary_info_word_count", bh.AzFTInteger, "officeInfo - number of words in the document."),
}

var OfficeInfo = bh.NewHandlerV3(vtToAzFeatOfficeInfo, "office_info")
