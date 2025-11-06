package basehandlerv3

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/tidwall/gjson"
)

const (
	featureHandlingStd        string = "standard"   // Standard default handler for parsing.
	featureHandlingListOfDict string = "listOfDict" // Member in a list of dict object.
	featureHandlingDictOfDict string = "dictOfDict" // Member of a dict within a dict
	featureHandlingSpecial    string = "special"    // Handled by a custom handling function.
)

// Maximum value a string can be and still be put into the database.
const MAX_VALUE_DB_STRING = 32766

type DictOfDictParameters struct {
	pathToDict string
}

type ListOfDictParameters struct {
	pathToList string
	labelKey   string
}

/*Feature value to be mapped to azul*/
type VtPathToAzFeature struct {
	VtPath       string // Path relative to root path
	VtType       string // Virustotal type, used to determine how to process data.
	VtDateFormat string // String for date format to be pulled out of Vt.

	AzName        string             // Azul name for the feature
	AzType        events.FeatureType // Azul type of the feature
	AzDescription string             // Description of the feature to be displayed in Azul

	isInfo                   bool // Is this feature mapped to info.
	isIntegerAllowedToBeZero bool // Is an integer value allowed to be zero defaults to false.
	// isChildren bool // Is this feature able to generate children. // FUTURE

	isLogErrorOnly bool // Only log errors

	handling       string // Handling that should be applied to the feature. (values can be featureHandlingStd, featureHandlingListOfDict, featureHandlingSpecial)
	handlingObject interface{}

	// Special handlers used to override the default behaviour when the feature needs different behaviour.
	specialFeatureHandler  func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error)
	specialChildrenHandler func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntity, error)
	specialInfoHandler     func(result gjson.Result, featMapping VtPathToAzFeature) (map[string]json.RawMessage, error)
}

/*Converts a datetime format from standard python format into a golang compatible one and adds it to the feature.*/
func AddDateFormat(dateFmt string) func(*VtPathToAzFeature) {
	originalFmt := dateFmt
	dateFmt = strings.ReplaceAll(dateFmt, "%a", "Mon")
	dateFmt = strings.ReplaceAll(dateFmt, "%A", "Monday")
	dateFmt = strings.ReplaceAll(dateFmt, "%w", "2")
	dateFmt = strings.ReplaceAll(dateFmt, "%d", "02")
	dateFmt = strings.ReplaceAll(dateFmt, "%b", "Jan")
	dateFmt = strings.ReplaceAll(dateFmt, "%B", "January")
	dateFmt = strings.ReplaceAll(dateFmt, "%m", "01")
	dateFmt = strings.ReplaceAll(dateFmt, "%y", "06")
	dateFmt = strings.ReplaceAll(dateFmt, "%Y", "2006")
	dateFmt = strings.ReplaceAll(dateFmt, "%H", "15")
	dateFmt = strings.ReplaceAll(dateFmt, "%I", "03")
	dateFmt = strings.ReplaceAll(dateFmt, "%p", "PM")
	dateFmt = strings.ReplaceAll(dateFmt, "%M", "04")
	dateFmt = strings.ReplaceAll(dateFmt, "%S", "05")
	dateFmt = strings.ReplaceAll(dateFmt, "%f", ".000000")
	dateFmt = strings.ReplaceAll(dateFmt, "%z", "-0700")
	dateFmt = strings.ReplaceAll(dateFmt, "%Z", "MST")
	dateFmt = strings.ReplaceAll(dateFmt, "%j", "002")
	if strings.Contains(dateFmt, "%") {
		message := fmt.Sprintf("The date time format provided was '%s' could not be converted to golang format, this is how much was converted '%s'", originalFmt, dateFmt)
		log.Println(message)
		panic(message)
	}

	return func(af *VtPathToAzFeature) {
		af.VtDateFormat = dateFmt
	}
}

/*Allow an integer value to be zero, otherwise it isn't included in the features.*/
func AddAllowIntegerToBeZero() func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.isIntegerAllowedToBeZero = true
	}
}

/*Only log errors not warnings (as they can be quite loud).*/
func EnableOnlyLogOnError() func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.isLogErrorOnly = true
	}
}

/*Wrapped function to add a static value to a feature and has the label be the value.*/
func addStaticValueHandler(value string) func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	return func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
		standardFeat, err := StandardFeatureHandler(result, featMapping)
		if err != nil {
			return standardFeat, err
		}
		for idx := range standardFeat {
			standardFeat[idx].Label = fmt.Sprintf("%v", standardFeat[idx].Value)
			standardFeat[idx].Value = value
		}
		return standardFeat, err
	}
}

/*
Adds a static value to a feature and has the label be the value
Note - this handler only works with a string type because it sets the value as the provided value.
*/
func AddStaticValueHandler(value string) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.specialFeatureHandler = addStaticValueHandler(value)
		af.handling = featureHandlingSpecial
	}
}

/*
Handle the case where you have a list of dictionary values by:
taking all the values in the list pathToList and adding the key 'labelKey' to the label of all values.
e.g:

	{
	 "path": {
	 	"to": {
			"list": [
				{
					"name": "a",
					"val": "carrot",
					"other_val": "banana"
				}
			]
		}
	}

you would call AddListOfDictHandling("path.to.list", "name")
and the values you get are:
events.BinaryEntityFeature{Name: "a", Value: "banana", Type: bh.AzFTString, Label: "a"}
events.BinaryEntityFeature{Name: "val", Value: "carrot", Type: bh.AzFTString, Label: "a"}
events.BinaryEntityFeature{Name: "other_val", Value: "banana", Type: bh.AzFTString, Label: "a"}
*/
func AddListOfDictHandling(pathToList string, labelKey string) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.handling = featureHandlingListOfDict
		af.handlingObject = ListOfDictParameters{pathToList: pathToList, labelKey: labelKey}
	}
}

/*
Handle the case where you have a nested dict with known keys and want to use the first level dict key as the label
e.g:

	{
		"outer_label_1":{
			"inner_val_a_1": "randomValue123125413241"
			"inner_val_b_1": "randomValue999999"
			"inner_val_c_1": "randomValue892348"
		}
		"outer_label_2":{
			"inner_val_a_2": "randomValue888888"
			"inner_val_b_2": "randomValue96666"
			"inner_val_c_2": "randomValue855555"
		}
	}

maps to:
events.BinaryEntityFeature{Name: "inner_val_a_1", Value: "randomValue123125413241", Type: bh.AzFTString, Label: "outer_label_1"}
events.BinaryEntityFeature{Name: "inner_val_b_1", Value: "randomValue999999", Type: bh.AzFTString, Label: "outer_label_1"}
events.BinaryEntityFeature{Name: "inner_val_c_1", Value: "randomValue892348", Type: bh.AzFTString, Label: "outer_label_1"}
*/
func AddDictOfDictHandling(pathToOuterDict string) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.handling = featureHandlingDictOfDict
		af.handlingObject = DictOfDictParameters{pathToDict: pathToOuterDict}
	}
}

/*Add a custom handler for the feature you want to process.*/
func AddSpecialFeatureHandlerFn(fn func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error)) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.specialFeatureHandler = fn
		af.handling = featureHandlingSpecial
	}
}

/*Add a special handler for processing child contents.*/
func AddSpecialChildrenHandlerFn(fn func(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntity, error)) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.specialChildrenHandler = fn
	}
}

/*Adds a special handler for info related content.*/
func AddSpecialInfoHandlerFn(fn func(result gjson.Result, featMapping VtPathToAzFeature) (map[string]json.RawMessage, error)) func(*VtPathToAzFeature) {
	return func(af *VtPathToAzFeature) {
		af.specialInfoHandler = fn
	}
}

/*Convenience function for creating the basic vtPathToAzFeat object.*/
func NewVtPathToAzFeat(vtPath string, vtType string, azName string, azType events.FeatureType, azDescription string, additionalOptions ...func(*VtPathToAzFeature)) VtPathToAzFeature {
	vtPathToAzFeat := VtPathToAzFeature{
		VtPath:        vtPath,
		VtType:        vtType,
		AzName:        azName,
		AzType:        azType,
		AzDescription: azDescription,
		handling:      featureHandlingStd,
	}
	for _, op := range additionalOptions {
		op(&vtPathToAzFeat)
	}

	return vtPathToAzFeat
}

/*Coerce a string like feature into the appropriate type.*/
func CoerceStringLikeFeature(value string, featMapping VtPathToAzFeature) (string, error) {
	if len(featMapping.VtDateFormat) > 0 {
		dateVal, err := time.Parse(featMapping.VtDateFormat, value)
		if err == nil {
			return dateVal.Format(time.RFC3339), nil
		} else {
			errorMessage := fmt.Sprintf("Warning - failed to parse date %s in path %s, with expected format: %s", value, featMapping.VtPath, featMapping.VtDateFormat)
			// Don't log known bad date format, and don't log the warning if it's disabled.
			if value != "0000-00-00 00:00:00" && !featMapping.isLogErrorOnly {
				log.Println(errorMessage)
			}

			return "", errors.New(errorMessage)
		}
	}
	return value, nil
}

func StandardFeatureHandler(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	return standardFeatureHandlerInternal(result, featMapping, false)
}

/*Allows to override path to facilitate listOfDict and dictOfDict where the result is simply set to the currentValue.*/
func standardFeatureHandlerInternal(result gjson.Result, featMapping VtPathToAzFeature, valueIsResult bool) ([]events.BinaryEntityFeature, error) {
	mappedFeats := []events.BinaryEntityFeature{}
	var err error
	// We know there is only one path for standardHandling.
	var newResult gjson.Result
	if valueIsResult {
		newResult = result
	} else {
		newResult = result.Get(featMapping.VtPath)
	}

	if newResult.Type == gjson.Null {
		// Nothing interesting found because the path doesn't exist.
		return mappedFeats, nil
	}
	switch featMapping.VtType {
	case VtTypeInteger:
		// Drop any integer values that are zero unless they are explicitly allowed.
		if !featMapping.isIntegerAllowedToBeZero && newResult.String() == "0" {
			return mappedFeats, nil
		}
		// Attempt to convert to an integer and if it can't be drop it.
		if _, err = strconv.Atoi(newResult.String()); err != nil {
			return mappedFeats, nil
		}
		fallthrough
	case VtTypeFloat:
		if featMapping.VtType == VtTypeFloat {
			// Drop invalid floats.
			if _, err = strconv.ParseFloat(newResult.String(), 64); err != nil {
				return mappedFeats, nil
			}
		}
		fallthrough
	case VtTypeBool:
		fallthrough
	case VtTypeString:
		// get the value and cast to string.
		if newResult.Type == gjson.JSON {
			return mappedFeats, fmt.Errorf("the type of the path %s was JSON and was meant to be string like", featMapping.VtPath)
		}
		value := newResult.String()
		if len(value) >= MAX_VALUE_DB_STRING {
			// Drop value that has a string that is too long for the db to handle
			log.Printf("WARNING - Dropped a feature for mapping with path %s because the string value was too long max length is %d.", featMapping.VtPath, MAX_VALUE_DB_STRING)
			return mappedFeats, nil
		}
		// Value must be string like so proceed.
		standardisedVal, err := CoerceStringLikeFeature(value, featMapping)
		if err == nil {
			mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
				Name:  featMapping.AzName,
				Value: standardisedVal,
				Type:  featMapping.AzType,
			})
		}
		return mappedFeats, nil
	case VtTypeListOfStrings:
		if newResult.Type != gjson.JSON || !newResult.IsArray() {
			return mappedFeats, fmt.Errorf("the type of the path %s was expected to be a list of strings (JSON) and was %s and was an array %v", featMapping.VtPath, newResult.Type.String(), newResult.IsArray())
		}

		for _, stringValue := range newResult.Array() {

			if stringValue.Type == gjson.JSON {
				return mappedFeats, fmt.Errorf("the type of the path %s was JSON and was meant to be string like", featMapping.VtPath)
			}
			stringValueRaw := stringValue.String()
			// Filter out large strings
			if len(stringValueRaw) >= MAX_VALUE_DB_STRING {
				// Drop value that has a string that is too long for the db to handle
				log.Printf("WARNING - Dropped a feature for mapping with path %s because the string value was too long max length is %d.", featMapping.VtPath, MAX_VALUE_DB_STRING)
				continue
			}

			standardisedVal, err := CoerceStringLikeFeature(stringValueRaw, featMapping)
			if err == nil {
				mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
					Name:  featMapping.AzName,
					Value: standardisedVal,
					Type:  featMapping.AzType,
				})
			}
		}
		return mappedFeats, nil

	case VtTypeDict:
		if newResult.Type != gjson.JSON {
			return mappedFeats, fmt.Errorf("the type of the path %s was expected to be a dictionary (JSON) and was %s", featMapping.VtPath, newResult.Type.String())
		}
		for resultKey, resultVal := range newResult.Map() {
			resultValString := resultVal.String()
			// Filter out large strings
			if len(resultValString) >= MAX_VALUE_DB_STRING {
				// Drop value that has a string that is too long for the db to handle
				log.Printf("WARNING - Dropped a feature for mapping with path %s because the string value was too long max length is %d.", featMapping.VtPath, MAX_VALUE_DB_STRING)
				continue
			}

			mappedFeats = append(mappedFeats, events.BinaryEntityFeature{
				Name:  featMapping.AzName,
				Value: resultKey,
				Label: resultValString,
				Type:  featMapping.AzType,
			})
		}
	default:
		return []events.BinaryEntityFeature{}, fmt.Errorf("invalid vt type provided couldn't map the features to azul for path %v", featMapping.VtPath)
	}
	return mappedFeats, nil
}

/*Default handler for lists of dicts, refer to AddListOfDictHandling for more info.*/
func listOfDictFeatureHandler(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	// FUTURE - this can be optimised by taking the curListOfMaps and caching it for the next run.
	// (By storing it in the baseHandler loop) Still need to check it's valid by looking at the path to the list.
	mappedFeats := []events.BinaryEntityFeature{}
	// We know there is only one path for standardHandling.
	listOfDictParams, ok := featMapping.handlingObject.(ListOfDictParameters)
	if !ok {
		log.Printf("ERROR - misconfigured list of dict handler is taking the wrong parameters for path '%s' the feature will not be mapped.", featMapping.VtPath)
		return mappedFeats, nil
	}
	// Account for case where list is at the root of the object.
	var listRef gjson.Result
	if listOfDictParams.pathToList == "" {
		listRef = result
	} else {
		listRef = result.Get(listOfDictParams.pathToList)
	}

	if listRef.Type == gjson.Null {
		// Nothing interesting found because the path doesn't exist.
		return mappedFeats, nil
	} else if !listRef.IsArray() {
		return mappedFeats, fmt.Errorf("warning - the listOfDict with list path '%s' has an invalid list path and the value is not a list, feature path is %s", listOfDictParams.pathToList, featMapping.VtPath)
	}

	tmpListArray := listRef.Array()
	var curListOfMaps []map[string]gjson.Result
	for _, listVal := range tmpListArray {
		curListOfMaps = append(curListOfMaps, listVal.Map())
	}
	pathToFeatInDict := strings.ReplaceAll(featMapping.VtPath, listOfDictParams.pathToList, "")
	// Remove leading fullstop if present.
	if pathToFeatInDict[0] == '.' {
		pathToFeatInDict = pathToFeatInDict[1:]
	}
	for _, dictVal := range curListOfMaps {
		label := dictVal[listOfDictParams.labelKey]
		labelAsString := ""
		if label.Type != gjson.Null {
			labelAsString = label.String()
		}
		val := dictVal[pathToFeatInDict]
		newFeatureValues, err := standardFeatureHandlerInternal(val, featMapping, true)
		if err != nil {
			log.Printf("Warning - could not process feature with path %s in listOfDict handler.", featMapping.VtPath)
			continue
		}
		for idx := range newFeatureValues {
			newFeatureValues[idx].Label = labelAsString
		}
		mappedFeats = append(mappedFeats, newFeatureValues...)

	}
	return mappedFeats, nil
}

/*Default handler for dictOfDict objects, refer to AddDictOfDictHandling for more detail.*/
func dictOfDictFeatureHandler(result gjson.Result, featMapping VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	mappedFeats := []events.BinaryEntityFeature{}

	dictOfDictParams, ok := featMapping.handlingObject.(DictOfDictParameters)
	if !ok {
		log.Printf("ERROR - misconfigured dict of dict handler is taking the wrong parameters for path '%s' the feature will not be mapped.\n", featMapping.VtPath)
		return mappedFeats, nil
	}
	// Account for case where the dictionary is the object.
	var mapRef gjson.Result
	if dictOfDictParams.pathToDict == "" {
		mapRef = result
	} else {
		mapRef = result.Get(dictOfDictParams.pathToDict)
	}

	// Map isn't present ignore.
	if mapRef.Type == gjson.Null {
		return mappedFeats, nil
	}
	outerMap := mapRef.Map()

	// Pre-cast all of the gjson result to make everything simpler.
	fullMap := map[string]map[string]gjson.Result{}
	for key, val := range outerMap {
		if val.Type == gjson.Null {
			continue
		} else if val.Type != gjson.JSON {
			log.Printf("Warning - could not map dict of dict as the provided object was not a dict of dict. Path %s Object: %v", featMapping.VtPath, val)
			continue
		}
		fullMap[key] = val.Map()
	}

	pathToFeatInDict := strings.ReplaceAll(featMapping.VtPath, dictOfDictParams.pathToDict, "")
	// Remove leading fullstop if present.
	if pathToFeatInDict[0] == '.' {
		pathToFeatInDict = pathToFeatInDict[1:]
	}

	// Look through all the parent keys for our mapping
	for key, innerMap := range fullMap {
		for innerKey, innerVal := range innerMap {
			// Only run on our current feature.
			if innerKey != pathToFeatInDict {
				continue
			}
			// Standard feature value handling for all features within the dictionary
			additionalFeats, err := standardFeatureHandlerInternal(innerVal, featMapping, true)
			if err != nil {
				log.Printf("Warning could not map dictOfDict with path %s", featMapping.VtPath)
				continue
			}
			// Add the parent dictionary key as a label.
			for idx := range additionalFeats {
				additionalFeats[idx].Label = key
			}
			// Append the features.
			mappedFeats = append(mappedFeats, additionalFeats...)
		}
	}

	return mappedFeats, nil
}
