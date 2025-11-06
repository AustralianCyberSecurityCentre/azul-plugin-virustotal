package vtmap

import (
	"fmt"

	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/virustotal"
	"github.com/tidwall/gjson"
)

const EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Filename returns a basename of filename if defined in the list of supplied features, otherwise the empty string.
func filename(feats []events.BinaryEntityFeature) string {
	for _, f := range feats {
		if f.Name == "filename" {
			val := f.Value
			// strip any dir information (platform independently)
			elem := strings.Split(val, "/")
			val = elem[len(elem)-1]
			elem = strings.Split(val, `\`)
			return elem[len(elem)-1]
		}
	}
	return ""
}

func TransformFileReportSingleV3(raw []byte, author *events.EventAuthor, source *events.EventSource) ([]events.BinaryEvent, error) {
	var err error
	sha256 := gjson.GetBytes(raw, "data.attributes.sha256").String()
	if len(sha256) != 64 {
		return nil, fmt.Errorf("no sha256")
	}

	binaries, err := MapV3(V3Handlers, gjson.ParseBytes(raw))
	if err != nil {
		return nil, fmt.Errorf("mapv3: %v", err)
	}

	msgs := []events.BinaryEvent{}
	// wrap in output events
	for idx := range binaries {
		// skip any empty files..
		if binaries[idx].Sha256 == EmptyHash {
			continue
		}

		ob := events.BinaryEvent{
			ModelVersion: 3,
			Author:       *author,
			Timestamp:    st.Now(),
			Action:       events.ActionMapped,
			Source:       *source,
		}
		// add step for this plugin (has to be a previous step)
		nodeMapped := ob.Source.Path[len(ob.Source.Path)-1]
		nodeMapped.Author = *author
		nodeMapped.Action = ob.Action
		nodeMapped.Sha256 = binaries[idx].Sha256
		nodeMapped.Timestamp = source.Timestamp
		ob.Source.Path = append(ob.Source.Path, nodeMapped)

		// was child of mapped events.. eg. had compressed contents
		if idx > 0 {
			nodeMappedChild := events.EventSourcePathNode{
				Author:    *author,
				Action:    ob.Action,
				Sha256:    binaries[idx].Sha256,
				Timestamp: source.Timestamp,
			}
			// override the last path to be the 'parent' entity
			// and then add another one for the 'child'
			ob.Source.Path[len(ob.Source.Path)-1].Sha256 = binaries[0].Sha256
			// sum := events.EventSourcePathNodeSummary{}
			if binaries[idx].Size > 0 {
				nodeMappedChild.Size = binaries[idx].Size
			}
			if len(binaries[idx].FileFormatLegacy) > 0 {
				nodeMappedChild.FileFormatLegacy = binaries[idx].FileFormatLegacy
			}
			binaries[idx].FileFormat = st.IdentifyMapper.FindFileType(binaries[idx].FileFormat, binaries[idx].FileFormatLegacy)
			name := filename(binaries[idx].Features)
			if len(name) > 0 {
				nodeMappedChild.Filename = name
			}
			ob.Source.Path = append(ob.Source.Path, nodeMappedChild)
		}
		ob.Entity = binaries[idx]
		msgs = append(msgs, ob)
	}
	return msgs, nil
}

func TransformFileFeedSingleV3(raw []byte, author *events.EventAuthor) ([]*events.BinaryEvent, error) {
	msgs := []*events.BinaryEvent{}
	var err error

	// Parse info
	vtmsg, err := virustotal.ParseVTInfoV3(raw)
	if err != nil {
		return nil, fmt.Errorf("parseVTInfo %v", err)
	}
	if vtmsg == nil {
		// record was corrupt
		return nil, nil
	}
	// build source information
	source, err := virustotal.BuildSourceV3(vtmsg, author)
	if err != nil {
		return nil, fmt.Errorf("BuildSourceV3 %v", err)
	}
	if source == nil {
		// record was too old
		return nil, nil
	}
	binaries, err := MapV3(V3Handlers, gjson.ParseBytes(raw))

	if err != nil {
		return nil, fmt.Errorf("map %v", err)
	}

	// wrap in output events
	for idx := range binaries {
		// skip any empty files..
		if binaries[idx].Sha256 == EmptyHash {
			continue
		}

		ob := events.BinaryEvent{
			ModelVersion: 3,
			Author:       *author,
			Timestamp:    st.Now(),
			Action:       events.ActionMapped,
			Source:       *source,
		}

		// was child of mapped events.. eg. had compressed contents
		if idx > 0 {
			nodeMappedChild := events.EventSourcePathNode{
				Author:    *author,
				Action:    ob.Action,
				Sha256:    binaries[idx].Sha256,
				Timestamp: source.Path[0].Timestamp,
			}
			// override the last path to be the 'parent' entity
			// and then add another one for the 'child'
			ob.Source.Path[len(ob.Source.Path)-1].Sha256 = binaries[0].Sha256
			if binaries[idx].Size > 0 {
				nodeMappedChild.Size = binaries[idx].Size
			}
			if len(binaries[idx].FileFormatLegacy) > 0 {
				nodeMappedChild.FileFormatLegacy = binaries[idx].FileFormatLegacy
			}
			binaries[idx].FileFormat = st.IdentifyMapper.FindFileType(binaries[idx].FileFormat, binaries[idx].FileFormatLegacy)
			name := filename(binaries[idx].Features)
			if len(name) > 0 {
				nodeMappedChild.Filename = name
			}
			ob.Source.Path = append(ob.Source.Path, nodeMappedChild)
		}
		ob.Entity = binaries[idx]
		msgs = append(msgs, &ob)
	}
	return msgs, nil
}
