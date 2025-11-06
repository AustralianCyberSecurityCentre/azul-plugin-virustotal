package basehandlerv3

import (
	"fmt"
	"log"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/tidwall/gjson"
)

const BasePathV3 = "attributes"
const MaxFeaturesPerFeature = 1000
const MaxTotalFeatures = 10 * MaxFeaturesPerFeature

const (
	AzFTInteger  events.FeatureType = events.FeatureInteger  // Int, Int64, Int32
	AzFTFloat    events.FeatureType = events.FeatureFloat    // Float32, Float64
	AzFTString   events.FeatureType = events.FeatureString   // string
	AzFTDatetime events.FeatureType = events.FeatureDatetime // time.Time
)

// Vt types.
const (
	VtTypeString        string = "string"
	VtTypeListOfStrings string = "list of strings"
	VtTypeInteger       string = "integer"
	VtTypeFloat         string = "float"
	VtTypeDict          string = "dictionary"
	VtTypeBool          string = "bool"
	// Type used to indicate nested objects in a list that isn't used directly.
	// It does appear in generated map handlers though which is why it's retained:
	// VtTypeListOfDict    string = "list of dictionaries"
	// Special handling, enables a completely custom handler function to be provided for handling edge cases.
	VtTypeSpecial string = "special"
)

type HandlerV3 struct {
	AdditionalRootPath string // Root path after data.attributes for a given handler
	VtToAzFeature      []VtPathToAzFeature
	Description        []events.PluginEntityFeature

	// At setup
	CanCreateFeatures bool
	CanCreateInfo     bool
	CanCreateChildren bool

	// Children func(result gjson.Result) ([]events.BinaryEntity, error)
	// Info     func(result gjson.Result) (map[string]json.RawMessage, error)
}

func NewHandlerV3(vtToAzFeature []VtPathToAzFeature, additionalRootPath string) HandlerV3 {
	h3 := HandlerV3{
		AdditionalRootPath: additionalRootPath,
		VtToAzFeature:      vtToAzFeature,
	}
	h3.initDescription()
	return h3
}

/*Create the description from the existing vtToAz info.*/
func (h3 *HandlerV3) initDescription() {
	description := []events.PluginEntityFeature{}
	for _, vtToAzFeat := range h3.VtToAzFeature {
		description = append(description, events.PluginEntityFeature{
			Name:        vtToAzFeat.AzName,
			Description: vtToAzFeat.AzDescription,
			Type:        vtToAzFeat.AzType,
		})
	}
	h3.Description = description
}

func (h3 *HandlerV3) GetDescription() []events.PluginEntityFeature {
	return h3.Description
}

/*Get features from a given V3 handler (Assumes that gjson.Result is at the data level for the file reports).*/
func (h3 *HandlerV3) GetFeatures(result gjson.Result) ([]events.BinaryEntityFeature, error) {
	var err error
	var lastResult []events.BinaryEntityFeature
	finalResult := []events.BinaryEntityFeature{}
	basePath := BasePathV3
	if len(h3.AdditionalRootPath) > 0 {
		basePath = fmt.Sprintf("%s.%s", basePath, h3.AdditionalRootPath)
	}
	// Don't look at the handler if there are no features.
	result = result.Get(basePath)
	if result.Type == gjson.Null {
		return finalResult, nil
	}

	for _, vtToAzFeat := range h3.VtToAzFeature {
		if vtToAzFeat.isInfo {
			// Ignore info mappers handlers.
			continue
		}
		if vtToAzFeat.VtType == VtTypeSpecial && vtToAzFeat.handling == featureHandlingStd {
			return finalResult, fmt.Errorf("special type requires special handling for feature %v", vtToAzFeat.VtPath)
		}
		switch vtToAzFeat.handling {
		case featureHandlingStd:
			lastResult, err = StandardFeatureHandler(result, vtToAzFeat)
		case featureHandlingListOfDict:
			lastResult, err = listOfDictFeatureHandler(result, vtToAzFeat)
		case featureHandlingDictOfDict:
			lastResult, err = dictOfDictFeatureHandler(result, vtToAzFeat)
		case featureHandlingSpecial:
			lastResult, err = vtToAzFeat.specialFeatureHandler(result, vtToAzFeat)
		default:
			log.Panicf("Can't use the provided handler %s, it is not a recognized handler.", vtToAzFeat.handling)
		}
		if err != nil {
			return finalResult, err
		} else {
			// Drop excess features if over 1000 are trying to be added.
			if len(lastResult) > MaxFeaturesPerFeature {
				lastResult = lastResult[:MaxFeaturesPerFeature]
			}
			// If the total number of features is going to be pushed above max allowable, push in these features and
			// post the result to Dispatcher.
			if len(finalResult)+len(lastResult) > MaxTotalFeatures {
				featureSlotsAvailable := MaxTotalFeatures - len(finalResult)
				finalResult = append(finalResult, lastResult[:featureSlotsAvailable]...)
				break
			}
			finalResult = append(finalResult, lastResult...)
		}
	}
	return finalResult, nil
}

/*Currently unused*/
func (h3 *HandlerV3) GetChildren(result gjson.Result) ([]events.BinaryEntity, error) {
	return []events.BinaryEntity{}, nil
}

/*Only runs on feature mappings that have isInfo set to true.*/
func (h3 *HandlerV3) GetInfo(result gjson.Result) (map[string]any, error) {
	return map[string]any{}, nil
}
