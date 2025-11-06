package handlersv3

import (
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
)

var vtToAzFeatSignatureInfo = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("comments", bh.VtTypeString, "comments", bh.AzFTString, "signatureInfo - from the file's version resource, if found."),
	bh.NewVtPathToAzFeat("copyright", bh.VtTypeString, "copyright", bh.AzFTString, "signatureInfo - from the file’s version resource, if found."),
	bh.NewVtPathToAzFeat("counter signers", bh.VtTypeString, "counter_signers", bh.AzFTString, "signatureInfo - string with counter signers Common Names. Names separated by ;  characters."),
	bh.NewVtPathToAzFeat("description", bh.VtTypeString, "description", bh.AzFTString, "signatureInfo - from the file's version resource, if found."),
	bh.NewVtPathToAzFeat("file version", bh.VtTypeString, "file_version", bh.AzFTString, "signatureInfo - from the file’s version resource, if found."),
	bh.NewVtPathToAzFeat("internal name", bh.VtTypeString, "internal_name", bh.AzFTString, "signatureInfo - from the file's version resource, if found."),
	bh.NewVtPathToAzFeat("original name", bh.VtTypeString, "original_name", bh.AzFTString, "signatureInfo - from the file’s version resource, if found."),
	bh.NewVtPathToAzFeat("product", bh.VtTypeString, "product", bh.AzFTString, "signatureInfo - from the file's version resource, if found."),
	bh.NewVtPathToAzFeat("signing date", bh.VtTypeString, "signing_date", bh.AzFTString, "signatureInfo - when the file was signed, in %H:%M %p %m/%d/%Y format."),
	// A lot of clutter not much value.
	// bh.NewVtPathToAzFeat("counter signers details", bh.VtTypeListOfDict, "counter_signers_details", bh.dont-map, "signatureInfo - details about each counter signer certificate."),
	// bh.NewVtPathToAzFeat("counter signers details.algorithm", bh.VtTypeString, "counter_signers_details_algorithm", bh.AzFTString, "signatureInfo - the ones used for creating the key pairs.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.cert issuer", bh.VtTypeString, "counter_signers_details_cert_issuer", bh.AzFTString, "signatureInfo - company that issued the certificate.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.name", bh.VtTypeString, "counter_signers_details_name", bh.AzFTString, "signatureInfo - certificate subject.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.serial number", bh.VtTypeString, "counter_signers_details_serial_number", bh.AzFTString, "signatureInfo - in hex, byte by byte separated by spaces.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.status", bh.VtTypeString, "counter_signers_details_status", bh.AzFTString, "signatureInfo - it can say 'Valid' or state the problem with the certificate if any (i.e. ''This certificate or one of the certificates in the certificate chain is not time valid.').", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.thumbprint", bh.VtTypeString, "counter_signers_details_thumbprint", bh.AzFTString, "signatureInfo - hex representation of the certificate hash.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.valid from", bh.VtTypeString, "counter_signers_details_valid_from", bh.AzFTString, "signatureInfo - validity start date, in %H:%M %p %m/%d/%Y format.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.valid to", bh.VtTypeString, "counter_signers_details_valid_to", bh.AzFTString, "signatureInfo - expiry date, in %H:%M %p %m/%d/%Y format.", bh.AddListOfDictHandling("counter signers details", "name")),
	// bh.NewVtPathToAzFeat("counter signers details.valid usage", bh.VtTypeString, "counter_signers_details_valid_usage", bh.AzFTString, "signatureInfo - indicates which situations the certificate is valid for (i.e. 'Code Signing').", bh.AddListOfDictHandling("counter signers details", "name")),
	// A lot of clutter not much value.
	// bh.NewVtPathToAzFeat("x509", bh.VtTypeListOfDict, "x509", bh.dont-map, "signatureInfo - list of certificates found in the file. Every item in the list is an SSL Certificate object, but returning just the following fields from the object:"),
	// bh.NewVtPathToAzFeat("x509.algorithm", bh.VtTypeString, "x509_algorithm", bh.AzFTString, "signatureInfo - the ones used for creating the key pairs.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.cert issuer", bh.VtTypeString, "x509_cert_issuer", bh.AzFTString, "signatureInfo - company that issued the certificate. Extracted from the certificate's issuer.CN field.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.name", bh.VtTypeString, "x509_name", bh.AzFTString, "signatureInfo - certificate subject.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.serial number", bh.VtTypeString, "x509_serial_number", bh.AzFTString, "signatureInfo - in hex, byte by byte separated by spaces.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.thumbprint", bh.VtTypeString, "x509_thumbprint", bh.AzFTString, "signatureInfo - hex representation of the certificate hash.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.valid from", bh.VtTypeString, "x509_valid_from", bh.AzFTString, "signatureInfo - validity start date, in %H:%M %p %m/%d/%Y format.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.valid to", bh.VtTypeString, "x509_valid_to", bh.AzFTString, "signatureInfo - expiry date, in %H:%M %p %m/%d/%Y format.", bh.AddListOfDictHandling("x509", "name")),
	// bh.NewVtPathToAzFeat("x509.valid usage", bh.VtTypeString, "x509_valid_usage", bh.AzFTString, "signatureInfo - indicates which situations the certificate is valid for (i.e. 'Code Signing'). Extracted from 'extended key usage' certificate extension.", bh.AddListOfDictHandling("x509", "name")),
}

var SignatureInfo = bh.NewHandlerV3(vtToAzFeatSignatureInfo, "signature_info")
