package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatElfInfo = []bh.VtPathToAzFeature{
	// bh.NewVtPathToAzFeat("export_list", bh.VtTypeListOfDict, "export_list", bh.dont-map, "elfInfo - contains exported elements. Each dictionary contains:"),
	bh.NewVtPathToAzFeat("export_list.name", bh.VtTypeString, "export_list_name", bh.AzFTString, "elfInfo - The exported item's name.", bh.AddListOfDictHandling("export_list", "name")),
	bh.NewVtPathToAzFeat("export_list.type", bh.VtTypeString, "export_list_type", bh.AzFTString, "elfInfo - The exported item's type.", bh.AddListOfDictHandling("export_list", "name")),
	// bh.NewVtPathToAzFeat("header", bh.VtTypeDict, "header", bh.dont-map, "elfInfo - some descriptive metadata about the file."),
	bh.NewVtPathToAzFeat("header.type", bh.VtTypeString, "header_type", bh.AzFTString, "elfInfo - human readable type of file (i.e. 'EXEC (Executable file)')."),
	bh.NewVtPathToAzFeat("header.hdr_version", bh.VtTypeString, "header_hdr_version", bh.AzFTString, "elfInfo - header version."),
	bh.NewVtPathToAzFeat("header.num_prog_headers", bh.VtTypeInteger, "header_num_prog_headers", bh.AzFTInteger, "elfInfo - number of entries in the program header."),
	bh.NewVtPathToAzFeat("header.os_abi", bh.VtTypeString, "header_os_abi", bh.AzFTString, "elfInfo - human readable application binary interface type (i.e. 'UNIX - Linux')."),
	bh.NewVtPathToAzFeat("header.obj_version", bh.VtTypeString, "header_obj_version", bh.AzFTString, "elfInfo - '0x1' for original ELF files."),
	bh.NewVtPathToAzFeat("header.machine", bh.VtTypeString, "header_machine", bh.AzFTString, "elfInfo - platform (ie. 'Advanced Micro Devices X86-64')."),
	bh.NewVtPathToAzFeat("header.entrypoint", bh.VtTypeInteger, "header_entrypoint", bh.AzFTInteger, "elfInfo - executable entry point."),
	bh.NewVtPathToAzFeat("header.num_section_headers", bh.VtTypeString, "header_num_section_headers", bh.AzFTString, "elfInfo - number of section headers."),
	bh.NewVtPathToAzFeat("header.abi_version", bh.VtTypeInteger, "header_abi_version", bh.AzFTInteger, "elfInfo - application binary interface version."),
	bh.NewVtPathToAzFeat("header.data", bh.VtTypeString, "header_data", bh.AzFTString, "elfInfo - data alignment in memory (i.e. 'little endian'.)"),
	bh.NewVtPathToAzFeat("header.class", bh.VtTypeString, "header_class", bh.AzFTString, "elfInfo - file class (i.e. 'ELF32')."),
	// bh.NewVtPathToAzFeat("import_list", bh.VtTypeListOfDict, "import_list", bh.dont-map, "elfInfo - contains imported elements. Each dictionary contains:"),
	bh.NewVtPathToAzFeat("import_list.name", bh.VtTypeString, "import_list_name", bh.AzFTString, "elfInfo - The imported item's name.", bh.AddListOfDictHandling("import_list", "name")),
	bh.NewVtPathToAzFeat("import_list.type", bh.VtTypeString, "import_list_type", bh.AzFTString, "elfInfo - The imported item's type.", bh.AddListOfDictHandling("import_list", "name")),
	bh.NewVtPathToAzFeat("packers", bh.VtTypeListOfStrings, "packers", bh.AzFTString, "elfInfo - contains the executable's packers, if any."),
	// bh.NewVtPathToAzFeat("section_list", bh.VtTypeListOfDict, "section_list", bh.dont-map, "elfInfo - sections of the ELF file. Every item contains the following fields:"),
	bh.NewVtPathToAzFeat("section_list.name", bh.VtTypeString, "section_list_name", bh.AzFTString, "elfInfo - section name.", bh.AddListOfDictHandling("section_list", "name")),
	bh.NewVtPathToAzFeat("section_list.virtual_address", bh.VtTypeInteger, "section_list_virtual_address", bh.AzFTInteger, "elfInfo - section virtual address.", bh.AddListOfDictHandling("section_list", "name")),
	bh.NewVtPathToAzFeat("section_list.flags", bh.VtTypeString, "section_list_flags", bh.AzFTString, "elfInfo - section flags.", bh.AddListOfDictHandling("section_list", "name")),
	bh.NewVtPathToAzFeat("section_list.physical_offset", bh.VtTypeInteger, "section_list_physical_offset", bh.AzFTInteger, "elfInfo - section physical offset.", bh.AddListOfDictHandling("section_list", "name")),
	bh.NewVtPathToAzFeat("section_list.section_type", bh.VtTypeString, "section_list_section_type", bh.AzFTString, "elfInfo - type of section.", bh.AddListOfDictHandling("section_list", "name")),
	bh.NewVtPathToAzFeat("section_list.size", bh.VtTypeInteger, "section_list_size", bh.AzFTInteger, "elfInfo - size of section in bytes.", bh.AddListOfDictHandling("section_list", "name")),
	// bh.NewVtPathToAzFeat("segment_list", bh.VtTypeListOfDict, "segment_list", bh.dont-map, "elfInfo - aka Program Headers. each dictionary contains:"),
	bh.NewVtPathToAzFeat("segment_list.segment_type", bh.VtTypeString, "segment_list_segment_type", bh.AzFTString, "elfInfo - The segment type.", bh.AddListOfDictHandling("segment_list", "segment_type")),
	bh.NewVtPathToAzFeat("segment_list.resources", bh.VtTypeListOfStrings, "segment_list_resources", bh.AzFTString, "elfInfo - A list of resources involved in that segment.", bh.AddListOfDictHandling("segment_list", "segment_type")),
	bh.NewVtPathToAzFeat("shared_libraries", bh.VtTypeListOfStrings, "shared_libraries", bh.AzFTString, "elfInfo - contains shared libraries used by this executable."),
}

var ElfInfo = bh.NewHandlerV3(vtToAzFeatElfInfo, "elf_info")
