package handlersv3

import (
	"log"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/tidwall/gjson"
)

var vtToAzFeatPeInfo = []bh.VtPathToAzFeature{
	//bh.NewVtPathToAzFeat("debug", bh.VtTypeListOfDict, "debug", bh.dont-map, "peInfo - debug information if present. Every item contains the following fields:"),
	//bh.NewVtPathToAzFeat("debug.codeview", bh.VtTypeDict, "debug_codeview", bh.dont-map, "peInfo - CodeView debug info if present."),
	// bh.NewVtPathToAzFeat("debug.codeview.age", bh.VtTypeInteger, "debug_codeview_age", bh.AzFTInteger, "peInfo - always-incrementing value."),
	// bh.NewVtPathToAzFeat("debug.codeview.guid", bh.VtTypeString, "debug_codeview_guid", bh.AzFTString, "peInfo - unique identifier. Only returned if signature is 'RSDS'."),
	// bh.NewVtPathToAzFeat("debug.codeview.name", bh.VtTypeString, "debug_codeview_name", bh.AzFTString, "peInfo - path of the PDB file."),
	// bh.NewVtPathToAzFeat("debug.codeview.offset", bh.VtTypeInteger, "debug_codeview_offset", bh.AzFTInteger, "peInfo - set to 0. Only returned if signature is 'NB10'."),
	// bh.NewVtPathToAzFeat("debug.codeview.signature", bh.VtTypeString, "debug_codeview_signature", bh.AzFTString, "peInfo - can be 'RSDS' or 'NB10'."),
	// bh.NewVtPathToAzFeat("debug.codeview.timestamp", bh.VtTypeString, "debug_codeview_timestamp", bh.AzFTString, "peInfo - DBG file timestamp. Only returned in signature is 'NB10'."),
	// //bh.NewVtPathToAzFeat("debug.fpo", bh.VtTypeDict, "debug_fpo", bh.dont-map, "peInfo - present when the type is IMAGE_DEBUG_TYPE_FPO."),
	// bh.NewVtPathToAzFeat("debug.fpo.functions", bh.VtTypeInteger, "debug_fpo_functions", bh.AzFTInteger, "peInfo - contains the number of FP0 data records."),
	// //bh.NewVtPathToAzFeat("debug.misc", bh.VtTypeDict, "debug_misc", bh.dont-map, "peInfo - Present when the type is IMAGE_DEBUG_TYPE_MISC."),
	// bh.NewVtPathToAzFeat("debug.misc.datatype", bh.VtTypeInteger, "debug_misc_datatype", bh.AzFTInteger, "peInfo - always set to 1 (`IMAGE_DEBUG_MISC_EXENAME)."),
	// bh.NewVtPathToAzFeat("debug.misc.length", bh.VtTypeInteger, "debug_misc_length", bh.AzFTInteger, "peInfo - total length of the record, rounded to four byte multiple."),
	// bh.NewVtPathToAzFeat("debug.misc.unicode", bh.VtTypeInteger, "debug_misc_unicode", bh.AzFTInteger, "peInfo - 1 if data is a unicode string."),
	// bh.NewVtPathToAzFeat("debug.misc.data", bh.VtTypeString, "debug_misc_data", bh.AzFTString, "peInfo - actual data."),
	// bh.NewVtPathToAzFeat("debug.misc.reserved", bh.VtTypeString, "debug_misc_reserved", bh.AzFTString, "peInfo - reserved bytes."),
	// bh.NewVtPathToAzFeat("debug.offset", bh.VtTypeInteger, "debug_offset", bh.AzFTInteger, "peInfo - location of this debug information."),
	// bh.NewVtPathToAzFeat("debug.reserved10", bh.VtTypeDict, "debug_reserved10", bh.AzFTString, "peInfo - present when the type is IMAGE_DEBUG_TYPE_RESERVED10."),
	// bh.NewVtPathToAzFeat("debug.reserved10.value", bh.VtTypeString, "debug_reserved10_value", bh.AzFTString, "peInfo - it only contains 4 bytes, which value is stored in hex format."),
	// bh.NewVtPathToAzFeat("debug.size", bh.VtTypeInteger, "debug_size", bh.AzFTInteger, "peInfo - size of this debug information chunk."),
	// bh.NewVtPathToAzFeat("debug.timestamp", bh.VtTypeString, "debug_timestamp", bh.AzFTString, "peInfo - date in %a %b %d %H:%M:%S %Y format."),
	// bh.NewVtPathToAzFeat("debug.type", bh.VtTypeInteger, "debug_type", bh.AzFTInteger, "peInfo - debug type information."),
	// bh.NewVtPathToAzFeat("debug.type_str", bh.VtTypeString, "debug_type_str", bh.AzFTString, "peInfo - human-readable version of debug type information."),
	bh.NewVtPathToAzFeat("entry_point", bh.VtTypeInteger, "entry_point", bh.AzFTInteger, "peInfo - executable entry point."),
	bh.NewVtPathToAzFeat("exports", bh.VtTypeListOfStrings, "exports", bh.AzFTString, "peInfo - exported functions. It usually appears in DLLs but not in PEs."),
	bh.NewVtPathToAzFeat("imphash", bh.VtTypeString, "imphash", bh.AzFTString, "peInfo - hash based on imports."),
	//bh.NewVtPathToAzFeat("import_list", bh.VtTypeListOfDict, "import_list", bh.dont-map, "peInfo - contains all imported functions. Every item is a dictionary containing the following fields:"),
	bh.NewVtPathToAzFeat("import_list.imported_functions", bh.VtTypeListOfStrings, "import_list_imported_functions", bh.AzFTString, "peInfo - imported function names.", bh.AddListOfDictHandling("import_list", "library_name")),
	bh.NewVtPathToAzFeat("import_list.library_name", bh.VtTypeString, "import_list_library_name", bh.AzFTString, "peInfo - DLL name.", bh.AddListOfDictHandling("import_list", "library_name")),
	bh.NewVtPathToAzFeat("machine_type", bh.VtTypeInteger, "machine_type", bh.AzFTInteger, "peInfo - platform for this executable."),
	//bh.NewVtPathToAzFeat("overlay", bh.VtTypeDict, "overlay", bh.dont-map, "peInfo - if the PE file contains info appended to the end, some info about that content."),
	bh.NewVtPathToAzFeat("overlay.chi2", bh.VtTypeFloat, "overlay_chi2", bh.AzFTFloat, "peInfo - chi-squared test value of bytes from overlay content."),
	bh.NewVtPathToAzFeat("overlay.entropy", bh.VtTypeFloat, "overlay_entropy", bh.AzFTFloat, "peInfo - entropy value of bytes from overlay content."),
	bh.NewVtPathToAzFeat("overlay.filetype", bh.VtTypeString, "overlay_filetype", bh.AzFTString, "peInfo - if we're able to identify a specific file format, it is mentioned here."),
	bh.NewVtPathToAzFeat("overlay.md5", bh.VtTypeString, "overlay_md5", bh.AzFTString, "peInfo - hash of the overlay content."),
	bh.NewVtPathToAzFeat("overlay.offset", bh.VtTypeInteger, "overlay_offset", bh.AzFTInteger, "peInfo - location of the overlay start."),
	bh.NewVtPathToAzFeat("overlay.size", bh.VtTypeInteger, "overlay_size", bh.AzFTInteger, "peInfo - in number of bytes."),
	//bh.NewVtPathToAzFeat("resource_details", bh.VtTypeListOfDict, "resource_details", bh.dont-map, "peInfo - if the PE contains resources, some info about them."),
	bh.NewVtPathToAzFeat("resource_details.chi2", bh.VtTypeFloat, "resource_details_chi2", bh.AzFTFloat, "peInfo - chi-squared test of resource content.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_details.entropy", bh.VtTypeFloat, "resource_details_entropy", bh.AzFTFloat, "peInfo - entropy value of resource content.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_details.filetype", bh.VtTypeString, "resource_details_filetype", bh.AzFTString, "peInfo - noted if we're able to identify a specific file format.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_details.lang", bh.VtTypeString, "resource_details_lang", bh.AzFTString, "peInfo - language of the resource.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_details.sha256", bh.VtTypeString, "resource_details_sha256", bh.AzFTString, "peInfo - hash of the resource content.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_details.type", bh.VtTypeString, "resource_details_type", bh.AzFTString, "peInfo - type or resource.", bh.AddListOfDictHandling("resource_details", "sha256")),
	bh.NewVtPathToAzFeat("resource_langs", bh.VtTypeDict, "resource_langs", bh.AzFTString, "peInfo - digest of languages found in resources. Key is language (as string) and value is how many resources there are having that language (as integer)."),
	bh.NewVtPathToAzFeat("resource_types", bh.VtTypeDict, "resource_types", bh.AzFTString, "peInfo - digest of resource types. Key is resource type (as string) and value is how many resources there are of that specific type (as integer)."),
	//bh.NewVtPathToAzFeat("sections", bh.VtTypeListOfDict, "sections", bh.dont-map, "peInfo - information about PE sections:"),
	bh.NewVtPathToAzFeat("sections.entropy", bh.VtTypeFloat, "sections_entropy", bh.AzFTFloat, "peInfo - entropy value of section content.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("sections.md5", bh.VtTypeString, "sections_md5", bh.AzFTString, "peInfo - hash of the section.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("sections.name", bh.VtTypeString, "sections_name", bh.AzFTString, "peInfo - section name.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("sections.raw_size", bh.VtTypeInteger, "sections_raw_size", bh.AzFTInteger, "peInfo - size of the initialized data on disk, in bytes.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("sections.virtual_address", bh.VtTypeInteger, "sections_virtual_address", bh.AzFTInteger, "peInfo - address of the first byte of the section when loaded into memory, relative to the image base.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("sections.virtual_size", bh.VtTypeString, "sections_virtual_size", bh.AzFTString, "peInfo - total size of the section when loaded into memory, in bytes.", bh.AddListOfDictHandling("sections", "name")),
	bh.NewVtPathToAzFeat("timestamp", bh.VtTypeString, "timestamp", bh.AzFTDatetime, "peInfo - compilation time in Unix Epoch format.", bh.AddSpecialFeatureHandlerFn(unixEpochTimeHandler)),
}

var PeInfo = bh.NewHandlerV3(vtToAzFeatPeInfo, "pe_info")

func unixEpochTimeHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	resultList := []events.BinaryEntityFeature{}
	newResult := result.Get(featMapping.VtPath)

	if newResult.Type == gjson.Null {
		// Nothing interesting found.
		return resultList, nil
	}
	if newResult.Type != gjson.Number {
		log.Printf("Warning - unixEpochTimeHandler got a non unix time object, timestamp will not be mapped in dot_net_assembly!")
	}

	timeValue := time.Unix(newResult.Int(), 0)

	resultList = append(resultList, events.BinaryEntityFeature{
		Name:  featMapping.AzName,
		Value: timeValue.Format(time.RFC3339),
		Type:  featMapping.AzType,
	})
	return resultList, nil
}
