package handlersv3

import (
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v10/gosrc/events"
	bh "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/tidwall/gjson"
)

// Minimum length according to doco https://github.com/trendmicro/tlsh
const MIN_LENGTH_OF_TLSH = 70

var vtToAzFeatCommon = []bh.VtPathToAzFeature{
	bh.NewVtPathToAzFeat("tlsh", bh.VtTypeString, "tlsh", bh.AzFTString, "The TLSH hash of the file.", bh.AddSpecialFeatureHandlerFn(commonTlshHandler)),
	bh.NewVtPathToAzFeat("magic", bh.VtTypeString, "magic", bh.AzFTString, "The magic of the file"),
	bh.NewVtPathToAzFeat("ssdeep", bh.VtTypeString, "ssdeep", bh.AzFTString, "The SSDEEP hash of the file."),
	bh.NewVtPathToAzFeat("type_tag", bh.VtTypeString, "file_type_vt", bh.AzFTString, "The filetype from virustotal."),
	bh.NewVtPathToAzFeat("tags", bh.VtTypeListOfStrings, "tags", bh.AzFTString, "Virustotal tags for the files characteristics."),
}

var Common = bh.NewHandlerV3(vtToAzFeatCommon, "")

func commonTlshHandler(result gjson.Result, featMapping bh.VtPathToAzFeature) ([]events.BinaryEntityFeature, error) {
	mappedFeats, err := bh.StandardFeatureHandler(result, featMapping)
	if err != nil {
		return mappedFeats, err
	}
	// Drop values that are too short to be TLSH values such as TNULL which can happen
	for _, val := range mappedFeats {
		if len(val.Value) < MIN_LENGTH_OF_TLSH {
			return []events.BinaryEntityFeature{}, nil
		}
	}

	return mappedFeats, nil
}
