package handlersv3

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/tidwall/gjson"
)

var vtToAzFeatAndroguard = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("Activities", bh.VtTypeListOfStrings, "apk_activities", bh.AzFTString, "androguard - containing the app's activity names."),
	bh.NewVtPathToAzFeat("AndroguardVersion", bh.VtTypeString, "androguard_version", bh.AzFTString, "androguard - used Androguard version."),
	bh.NewVtPathToAzFeat("AndroidApplication", bh.VtTypeInteger, "android_application", bh.AzFTInteger, "androguard - Android file type in integer format."),
	bh.NewVtPathToAzFeat("AndroidApplicationError", bh.VtTypeBool, "android_application_error", bh.AzFTString, "androguard - whether there was an error processing the application or not."),
	bh.NewVtPathToAzFeat("AndroidApplicationInfo", bh.VtTypeString, "android_application_info", bh.AzFTString, "androguard - Android file type in readable form ('APK', 'DEX', 'AXML')."),
	bh.NewVtPathToAzFeat("AndroidVersionCode", bh.VtTypeString, "android_version_code", bh.AzFTString, "androguard - Android version code, read from the manifest."),
	bh.NewVtPathToAzFeat("AndroidVersionName", bh.VtTypeString, "android_version_name", bh.AzFTString, "androguard - Android version name, read from the manifest."),
	bh.NewVtPathToAzFeat("Libraries", bh.VtTypeListOfStrings, "apk_libraries", bh.AzFTString, "androguard - containing the app's used library names."),
	bh.NewVtPathToAzFeat("main_activity", bh.VtTypeString, "apk_main_activity", bh.AzFTString, "androguard - main activity name, read from the manifest."),
	bh.NewVtPathToAzFeat("MinSdkVersion", bh.VtTypeString, "apk_sdk_min", bh.AzFTString, "androguard - minimum supported SDK version."),
	bh.NewVtPathToAzFeat("Package", bh.VtTypeString, "apk_package_name", bh.AzFTString, "androguard - package name, read from the manifest."),
	bh.NewVtPathToAzFeat("Providers", bh.VtTypeListOfStrings, "apk_providers", bh.AzFTString, "androguard - contains the app's used providers."),
	bh.NewVtPathToAzFeat("Receivers", bh.VtTypeListOfStrings, "apk_receivers", bh.AzFTString, "androguard - contains the app's used receivers."),
	bh.NewVtPathToAzFeat("RiskIndicator.APK", bh.VtTypeDict, "apk_risk_indicator_apk", bh.AzFTString, "androguard - names used components and how many there are (i.e. 'EXECUTABLE': 3). Keys are strings and values are integers."),
	bh.NewVtPathToAzFeat("RiskIndicator.PERM", bh.VtTypeDict, "apk_risk_indicator_perm", bh.AzFTString, "androguard - names types of permissions and how many there are (i.e. 'DANGEROUS': 11). Keys are strings and values are integers."),
	bh.NewVtPathToAzFeat("Services", bh.VtTypeListOfStrings, "apk_services", bh.AzFTString, "androguard - contains the app's used services."),
	bh.NewVtPathToAzFeat("StringsInformation", bh.VtTypeListOfStrings, "apk_strings_information", bh.AzFTString, "androguard - contains interesting strings found in the app."),
	bh.NewVtPathToAzFeat("TargetSdkVersion", bh.VtTypeString, "apk_sdk_target", bh.AzFTString, "androguard - Android version the app has been tested for."),
	bh.NewVtPathToAzFeat("VTAndroidInfo", bh.VtTypeFloat, "apk_vt_android_info", bh.AzFTFloat, "androguard - internal version of the Androguard tool used by VT."),
	bh.NewVtPathToAzFeat("certificate.thumbprint", bh.VtTypeString, "apk_cert_fingerprint", bh.AzFTString, "androguard - The fingerprint of the certificate."),
	bh.NewVtPathToAzFeat("certificate", bh.VtTypeDict, "apk_cert_issuer", bh.AzFTString, "androguard - The issuer of the certificate in a dict.", bh.AddSpecialFeatureHandlerFn(androCertIssuerHandler)),
	bh.NewVtPathToAzFeat("certificate", bh.VtTypeDict, "apk_cert_subject", bh.AzFTString, "androguard - The subject of the certificate in a dict.", bh.AddSpecialFeatureHandlerFn(androSubjectHandler)),
	bh.NewVtPathToAzFeat("certificate.validfrom", bh.VtTypeString, "apk_cert_valid_from", bh.AzFTDatetime, "androguard - The certificate validity from the given date. (%Y-%m-%d %H:%M:%S)", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	bh.NewVtPathToAzFeat("certificate.validto", bh.VtTypeString, "apk_cert_valid_to", bh.AzFTDatetime, "androguard - The certificate validity to the given date format (%Y-%m-%d %H:%M:%S).", bh.AddDateFormat("%Y-%m-%d %H:%M:%S")),
	//bh.NewVtPathToAzFeat("intent_filters", bh.VtTypeDict, "intent_filters", bh.dont-map, "androguard - contains the app's intent filters. The dictionary contains three subfields:"),
	// bh.NewVtPathToAzFeat("intent_filters.Activities", bh.VtTypeDict, "intent_filters_activities", bh.dont-map, "androguard - : intent filters from activities."),
	bh.NewVtPathToAzFeat("intent_filters.Activities.action", bh.VtTypeListOfStrings, "apk_intent_filters", bh.AzFTString, "androguard - All of the intent filters in an application(not separated by type)."),
	// bh.NewVtPathToAzFeat("intent_filters.Activities.category", bh.VtTypeListOfStrings, "intent_filters_activities_category", bh.AzFTString, "androguard - defined categories."),
	// bh.NewVtPathToAzFeat("intent_filters.Receivers", bh.VtTypeDict, "intent_filters_receivers", bh.dont-map, "androguard - intent filters from receivers."),
	bh.NewVtPathToAzFeat("intent_filters.Receivers.action", bh.VtTypeListOfStrings, "apk_intent_filters", bh.AzFTString, "androguard - All of the intent filters in an application(not separated by type)."),
	// bh.NewVtPathToAzFeat("intent_filters.Receivers.category", bh.VtTypeListOfStrings, "intent_filters_receivers_category", bh.AzFTString, "androguard - defined categories."),
	// bh.NewVtPathToAzFeat("intent_filters.Services", bh.VtTypeDict, "intent_filters_services", bh.dont-map, "androguard - intent filters for services."),
	bh.NewVtPathToAzFeat("intent_filters.Services.action", bh.VtTypeListOfStrings, "apk_intent_filters", bh.AzFTString, "androguard - All of the intent filters in an application(not separated by type)."),
	// bh.NewVtPathToAzFeat("intent_filters.Services.category", bh.VtTypeListOfStrings, "intent_filters_services_category", bh.AzFTString, "androguard - defined categories."),
	bh.NewVtPathToAzFeat("permission_details", bh.VtTypeDict, "apk_permissions", bh.AzFTString, "androguard - The literal permissions as declared in the manifest, with the label as the description of the permission.", bh.AddSpecialFeatureHandlerFn(androApkPermHandler)),
	// bh.NewVtPathToAzFeat("permission_details.full_description", bh.VtTypeString, "permission_details_full_description", bh.AzFTString, "androguard - describes the permission with more detail."),
	// bh.NewVtPathToAzFeat("permission_details.permission_type", bh.VtTypeString, "permission_details_permission_type", bh.AzFTString, "androguard - describes the type of permission (i.e. normal, dangerous, etc)."),
	// bh.NewVtPathToAzFeat("permission_details.short_description", bh.VtTypeString, "permission_details_short_description", bh.AzFTString, "androguard - short summary describing the permission."),
}

var Androguard = bh.NewHandlerV3(vtToAzFeatAndroguard, "androguard")

/* Certifcate format:
All fields in the issuer and subject are comma sperated list key=val,key=val,key=val....
"certificate": {
    "Issuer": {
        "C": "CN",
        "CN": "MyName",
        "DN": "C:CN, CN:MyName, L:Beijing, O:Blabla, ST:Beijing, OU:Blablabla",
        "L": "Beijing",
        "O": "Blabla",
        "OU": "Blablabla",
        "ST": "Beijing"
    },
    "Subject": {
        "C": "CN",
        "CN": "MyName",
        "DN": "C:CN, CN:MyName, L:Beijing, O:Blablabla, ST:Beijing, OU:Blablabla",
        "L": "Beijing",
        "O": "Blablabla",
        "OU": "Blablabla",
        "ST": "Beijing"
    },
    "serialnumber": "b155424bb4743446",
    "thumbprint": "af54c24d4240644e64a0c4d742944a64964c4448",
    "validfrom": "2015-05-14 11:13:58",
    "validto": "2042-09-29 11:13:58"
},
*/

func androCertIssuerHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	return certIssuerAndSubjectHandler(result, featMapping, true)
}

func androSubjectHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	return certIssuerAndSubjectHandler(result, featMapping, false)
}

/*
Take a certificate issuer or subject and append all the dictionary items to one another.
e.g

	    "Issuer": {
	        "C": "CN",
	        "CN": "MyName",
	        "DN": "C:CN, CN:MyName, L:Beijing, O:Blabla, ST:Beijing, OU:Blablabla",
	        "L": "Beijing",
	        "O": "Blabla",
	        "OU": "Blablabla",
	        "ST": "Beijing"
	    },
		becomes
		C=CN,CN=MyName,DN=C:CN,CN:MyName,L:Beijing,O:Blabla,ST:Beijing,OU:Blablabla,L=Beijing,O=Blabla,OU=Blablabla,ST=Beijing
*/
func certIssuerAndSubjectHandler(result gjson.Result, featMapping bh.VtPathToAzFeature, isCertIssuer bool) ([]events.BinaryEntityFeature, error) {
	mappedFeats := []events.BinaryEntityFeature{}
	// Only one path
	if isCertIssuer {
		featMapping.VtPath = fmt.Sprintf("%s.Issuer", featMapping.VtPath)
	} else {
		featMapping.VtPath = fmt.Sprintf("%s.Subject", featMapping.VtPath)
	}
	newResult := result.Get(featMapping.VtPath)
	if newResult.Type == gjson.Null {
		// Nothing interesting found because the path doesn't exist.
		return mappedFeats, nil
	}
	if newResult.Type != gjson.JSON {
		return mappedFeats, fmt.Errorf("androguard special handler, the type of the path %s was expected to be a dictionary (JSON) and was %s", featMapping.VtPath, newResult.Type.String())
	}
	var sb strings.Builder
	// Sort by key to make result consistent
	certKeyMap := newResult.Map()
	keys := make([]string, 0, len(certKeyMap))
	for k := range certKeyMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("%s=%s,", k, certKeyMap[k].String()))
	}
	stringResult := sb.String()
	mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
		Name:  featMapping.AzName,
		Value: stringResult[:len(stringResult)-2],
		Type:  featMapping.AzType,
	})
	return mappedFeats, nil
}

/*
Handles this input:

	"permission_details": {
		"android.permission.ACCESS_COARSE_LOCATION": {
			"full_description": "Access coarse location sources, such as the mobile network database, to determine an approximate phone location, where available. Malicious applications can use this to determine approximately where you are.",
			"permission_type": "dangerous",
			"short_description": "coarse (network-based) location"
		},
		"android.permission.ACCESS_FINE_LOCATION": {
			"full_description": "Access fine location sources, such as the Global Positioning System on the phone, where available. Malicious applications can use this to determine where you are and may consume additional battery power.",
			"permission_type": "dangerous",
			"short_description": "fine (GPS) location"
		},
	}

Converts it into Azul features:

	value=android.permission.ACCESS_COARSE_LOCATION, label="dangerous"
	value=android.permission.ACCESS_FINE_LOCATION, label="dangerous"
*/
func androApkPermHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	mappedFeats := []events.BinaryEntityFeature{}
	// Only one path
	newResult := result.Get(featMapping.VtPath)
	if newResult.Type == gjson.Null {
		// Nothing interesting found because the path doesn't exist.
		return mappedFeats, nil
	}
	if newResult.Type != gjson.JSON {
		return mappedFeats, fmt.Errorf("androguard special handler permissions, the type of the path %s was expected to be a dictionary (JSON) and was %s", featMapping.VtPath, newResult.Type.String())
	}
	// Holds the key as the permission name and the resultDict is the value which itself is a dict of descriptions.
	for resultKey, resultDict := range newResult.Map() {
		permDescription := resultDict.Map()
		permTypeValue, success := permDescription["permission_type"]
		if success {
			mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
				Name:  featMapping.AzName,
				Value: resultKey,
				Label: permTypeValue.String(),
				Type:  featMapping.AzType,
			})
		} else { // Don't map the permission_type because it failed to map.
			log.Printf("Warning - failed to map permission_type in androguard permission handler.")
			mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
				Name:  featMapping.AzName,
				Value: resultKey,
				Type:  featMapping.AzType,
			})
		}
	}

	return mappedFeats, nil
}
