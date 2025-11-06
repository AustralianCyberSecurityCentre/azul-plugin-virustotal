package vtmap

import (
	"encoding/json"
	"fmt"

	"log"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	basehandlerv3 "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/basehandlerv3"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal/vtmap/handlersv3"
	"github.com/tidwall/gjson"
)

// SupressChildren defines the list of parent file types not to raise child records for.
var SupressChildren = [...]string{
	"Android",
	"APK",
	"DEX",
}

const MaxFeaturesPerFeature = 1000
const MaxTotalFeatures = 10 * MaxFeaturesPerFeature

var V3Handlers = []basehandlerv3.HandlerV3{
	handlersv3.Common, // ssdeep, tlsh, magic, tags, type_tags
	handlersv3.SandboxVerdicts,
	handlersv3.AvResults,
	handlersv3.AvResultsStats,
	// Low feature count - Specific types (these types are all fixed quantity of features (no).)
	handlersv3.Authentihash,
	handlersv3.BundleInfo,
	handlersv3.CrowdsourcedIdsStats,
	handlersv3.PasswordInfo,
	handlersv3.SignatureInfo,
	handlersv3.SigmaAnalysisStats,
	handlersv3.IsoimageInfo,
	handlersv3.DebInfo,
	// High feature count - Specific types
	handlersv3.ExifTool,
	handlersv3.Androguard,
	handlersv3.ElfInfo,
	handlersv3.PeInfo,
	// High feature count - Most likely to drop
	handlersv3.KnownDistributors,
}

func FeatureDescriptionsV3(handlers []basehandlerv3.HandlerV3) []events.PluginEntityFeature {
	desc := make([]events.PluginEntityFeature, 0)
	for _, d := range handlers {
		desc = append(desc, d.Description...)
	}

	return desc
}

func TotalFeatureDescriptions() []events.PluginEntityFeature {
	return FeatureDescriptionsV3(V3Handlers)
}

func AllowsChildren(ftype string) bool {
	// children need to be submitted back to dispatcher for file analysis
	// FUTURE re-enable mapping of child binaries.
	return false
	// for i := 0; i < len(SupressChildren); i++ {
	// 	if ftype == SupressChildren[i] {
	// 		return false
	// 	}
	// }
	// return true
}

/*Get string data from a map or an empty string if it can't be found.*/
func getStrValOrDefault(coreMap map[string]gjson.Result, key string) string {
	val, ok := coreMap[key]
	if !ok {
		return ""
	}
	if val.Type != gjson.String {
		return ""
	}
	return val.String()

}

func MapV3(handlers []basehandlerv3.HandlerV3, filescan gjson.Result) ([]events.BinaryEntity, error) {
	var b events.BinaryEntity
	b.Features = []events.BinaryEntityFeature{}
	b.Info = nil
	b.Datastreams = []events.BinaryEntityDatastream{}

	// Standard submission parameters.
	getData := filescan.Get("data") // "data" appears on file reports but not on feed results so optionally use it.
	if getData.Type != gjson.Null {
		filescan = getData
	}
	coreData := filescan.Get(basehandlerv3.BasePathV3)
	coreMap := coreData.Map()
	b.Sha256 = getStrValOrDefault(coreMap, "sha256")
	b.Sha1 = getStrValOrDefault(coreMap, "sha1")
	b.Md5 = getStrValOrDefault(coreMap, "md5")
	b.Ssdeep = getStrValOrDefault(coreMap, "ssdeep")
	b.Tlsh = getStrValOrDefault(coreMap, "tlsh")
	b.Magic = getStrValOrDefault(coreMap, "magic")
	b.FileFormatLegacy = getStrValOrDefault(coreMap, "magika")
	// Take the second closest type.
	if b.FileFormatLegacy == "" {
		b.FileFormatLegacy = getStrValOrDefault(coreMap, "type_tag")
	}
	b.FileExtension = getStrValOrDefault(coreMap, "type_extension")
	b.FileFormat = settings.IdentifyMapper.FindFileType("", b.FileFormatLegacy)

	size, ok := coreMap["size"]
	if ok && size.Type == gjson.Number {
		b.Size = size.Uint()
	}

	// Mimetype is special and only exists on exiftool
	mimePath := fmt.Sprintf("%s.exiftool.MIMEType", basehandlerv3.BasePathV3)
	mimeType := filescan.Get(mimePath)
	if mimeType.Type != gjson.String {
		b.Mime = ""
	} else {
		b.Mime = mimeType.String()
	}

	var additionalFeats []events.BinaryEntityFeature
	allInfo := map[string]any{}
	var additionalInfo map[string]any
	var err error
	for _, h := range handlers {
		// Get features
		additionalFeats, err = h.GetFeatures(filescan)
		if err == nil {
			b.Features = append(b.Features, additionalFeats...)
		} else {
			log.Printf("Warning - unable to get features from the handler with root path '%s' due to error %s", h.AdditionalRootPath, err)
		}
		// FUTURE - handle children.
		// Get Info
		if h.CanCreateInfo {
			additionalInfo, err = h.GetInfo(filescan)
			if err == nil {
				for key, val := range additionalInfo {
					allInfo[key] = val
				}
			} else {
				log.Printf("Warning - unable to get info from the handler with root path '%s' due to error %s", h.AdditionalRootPath, err)
			}
		}
	}
	encodedInfo, err := json.Marshal(&allInfo)
	if err != nil {
		log.Printf("Warning - unable to encode info due to error %s", err)
	} else if len(encodedInfo) > 0 {
		b.Info = encodedInfo
	}
	return []events.BinaryEntity{b}, nil
}
