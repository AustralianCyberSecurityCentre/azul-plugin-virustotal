package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatPdfInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("acroform", bh.VtTypeInteger, "acroform", bh.AzFTInteger, "pdfInfo - count of /AcroForm tags found in the document. An AcroForm is an interactive form."),
	bh.NewVtPathToAzFeat("autoaction", bh.VtTypeInteger, "autoaction", bh.AzFTInteger, "pdfInfo - number of /AA tags found in the document. An AutoAction defines an action to be taken in response to various trigger events affecting the document as a whole."),
	bh.NewVtPathToAzFeat("embedded_file", bh.VtTypeInteger, "embedded_file", bh.AzFTInteger, "pdfInfo - number of /EmbeddedFile tags found in the document. An embedded file makes the PDF file self-contained, since it allows to work with the PDF and the files it references as a single entity."),
	bh.NewVtPathToAzFeat("encrypted", bh.VtTypeInteger, "encrypted", bh.AzFTInteger, "pdfInfo - whether the document is encrypted or not, this is defined by the /Encrypt tag."),
	bh.NewVtPathToAzFeat("flash", bh.VtTypeInteger, "flash", bh.AzFTInteger, "pdfInfo - number of /RichMedia tags found in the PDF. This tag allows to attach Flash applications, audio, video and other multimedia in the PDF file."),
	bh.NewVtPathToAzFeat("header", bh.VtTypeString, "header", bh.AzFTString, "pdfInfo - PDF version (i.e. '%PDF-1.7')."),
	bh.NewVtPathToAzFeat("javascript", bh.VtTypeInteger, "javascript", bh.AzFTInteger, "pdfInfo - number of /JavaScript tags found in the PDF. This tag is used to define Javascript actions. It must be used with the /S tag in order to specify the type of action."),
	bh.NewVtPathToAzFeat("jbig2_compression", bh.VtTypeInteger, "jbig2_compression", bh.AzFTInteger, "pdfInfo - number of /JBIG2Decode tags found in the PDF. This tag is used to decompress data encoded using the JBIG2 standard, reproducing the original monochrome (1 bit per pixel) image data."),
	bh.NewVtPathToAzFeat("js", bh.VtTypeInteger, "js", bh.AzFTInteger, "pdfInfo - number of /JS tags found in the PDF. This tag is used with the /JavaScript one to add in-line javascript code when defining the object. In normal situations, js and javascript values should be the same (as they are used in pairs)."),
	bh.NewVtPathToAzFeat("num_endobj", bh.VtTypeInteger, "num_endobj", bh.AzFTInteger, "pdfInfo - number of objects definitions (endobj keyword). This should have the same value as num_obj field."),
	bh.NewVtPathToAzFeat("num_endstream", bh.VtTypeInteger, "num_endstream", bh.AzFTInteger, "pdfInfo - number of defined stream objects (endstream keyword). This should have the same value as num_stream field."),
	bh.NewVtPathToAzFeat("num_launch_actions", bh.VtTypeInteger, "num_launch_actions", bh.AzFTInteger, "pdfInfo - number of /Launch tags found in the PDF. This tag defines a Launch Action which is used to launch an application, open or print a document."),
	bh.NewVtPathToAzFeat("num_obj", bh.VtTypeInteger, "num_obj", bh.AzFTInteger, "pdfInfo - number of objects definitions (obj keyword)."),
	bh.NewVtPathToAzFeat("num_object_streams", bh.VtTypeInteger, "num_object_streams", bh.AzFTInteger, "pdfInfo - number of object streams. An object stream is a stream that contains a sequence of PDF objects."),
	bh.NewVtPathToAzFeat("num_pages", bh.VtTypeInteger, "num_pages", bh.AzFTInteger, "pdfInfo - number of pages."),
	bh.NewVtPathToAzFeat("num_stream", bh.VtTypeInteger, "num_stream", bh.AzFTInteger, "pdfInfo - Number of defined stream objects (stream keyword)."),
	bh.NewVtPathToAzFeat("openaction", bh.VtTypeInteger, "openaction", bh.AzFTInteger, "pdfInfo - number of /OpenAction tags found in the PDF. An OpenAction is a value specifying a destination that shall be displayed or an action that shall be performed when the document is opened. If empty, the document will be opened at the top of the first page at the default magnification factor."),
	bh.NewVtPathToAzFeat("startxref", bh.VtTypeInteger, "startxref", bh.AzFTInteger, "pdfInfo - number of startxref keywords in the document. This keyword is used to indicate the offset of a cross reference table or stream."),
	bh.NewVtPathToAzFeat("suspicious_colors", bh.VtTypeInteger, "suspicious_colors", bh.AzFTInteger, "pdfInfo - number of colors expressed with more than 3 bytes (CVE-2009-3459)."),
	bh.NewVtPathToAzFeat("trailer", bh.VtTypeInteger, "trailer", bh.AzFTInteger, "pdfInfo - number of trailer keywords in the document. The trailer of a PDF enables a conforming reader to quickly find the cross-reference table and certain special objects."),
	bh.NewVtPathToAzFeat("xfa", bh.VtTypeInteger, "xfa", bh.AzFTInteger, "pdfInfo - number of \\XFA tags found in the PDF. XFA stands for Adobe XML Forms Architecture and gives support for interactive forms inside the document."),
	bh.NewVtPathToAzFeat("xref", bh.VtTypeInteger, "xref", bh.AzFTInteger, "pdfInfo - Number of xref keywords in the document. That keyword is used to define the cross-reference table, which contains information that permits random access to indirect objects within the file so that the entire file need not be read to locate any particular object."),
}

var PdfInfo = bh.NewHandlerV3(vtToAzFeatPdfInfo, "pdf_info")
