package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatExiftool = []bh.VtPathToAzFeature{
	// PE
	bh.NewVtPathToAzFeat("CodeSize", bh.VtTypeString, "code_size", bh.AzFTInteger, "Number of bytes in the PE."),
	bh.NewVtPathToAzFeat("EntryPoint", bh.VtTypeString, "entry_point", bh.AzFTString, "Entrypoint to the PE."),
	bh.NewVtPathToAzFeat("FileOS", bh.VtTypeString, "file_os", bh.AzFTString, "Operating system the PE was compiled on."),
	bh.NewVtPathToAzFeat("FileVersionNumber", bh.VtTypeString, "version_number", bh.AzFTString, "Version number of the PE."),
	bh.NewVtPathToAzFeat("ImageFileCharacteristics", bh.VtTypeString, "image_file_characteristics", bh.AzFTString, "Characteristics as defined in the PE file header"),
	bh.NewVtPathToAzFeat("OSVersion", bh.VtTypeString, "os_version", bh.AzFTString, "Operating system version as defined in PE optional header."),
	bh.NewVtPathToAzFeat("PEType", bh.VtTypeString, "pe_type", bh.AzFTString, "File type of the PE."),
	// Image
	// PDF
	bh.NewVtPathToAzFeat("DocumentID", bh.VtTypeString, "document_id", bh.AzFTString, "Document ID of the PDF."),
	bh.NewVtPathToAzFeat("FileType", bh.VtTypeString, "file_type", bh.AzFTString, "File type of the PE."),
	bh.NewVtPathToAzFeat("FileTypeExtension", bh.VtTypeString, "extension", bh.AzFTString, "Extension of the file."),
	bh.NewVtPathToAzFeat("Format", bh.VtTypeString, "format", bh.AzFTString, "Additional file type information."),
	bh.NewVtPathToAzFeat("HasXFA", bh.VtTypeString, "has_XFA", bh.AzFTString, "Does the PDF have XFA."),
	bh.NewVtPathToAzFeat("MIMEType", bh.VtTypeString, "mime", bh.AzFTString, "Mime type of the file."),
	bh.NewVtPathToAzFeat("ModifyDate", bh.VtTypeString, "modify_date", bh.AzFTString, "Last date the PDF was modified."),
	bh.NewVtPathToAzFeat("PDFVersion", bh.VtTypeString, "PDF_version", bh.AzFTString, "Version number of the PDF."),
	bh.NewVtPathToAzFeat("PageCount", bh.VtTypeInteger, "page_count", bh.AzFTInteger, "Number of pages in the PDF."),
}

var ExifTool = bh.NewHandlerV3(vtToAzFeatExiftool, "exiftool")
