package virustotal

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
)

func BuildSourceV3(vtmsg *VtMessageCommon, author *events.EventAuthor) (*events.EventSource, error) {
	// get date of virustotal record
	if vtmsg == nil {
		errMsg := "attempted to build a source from a bad message that could not be parsed"
		log.Println(errMsg)
		return nil, errors.New(errMsg)
	}
	if vtmsg.LastScanDate.IsZero() {
		return nil, errors.New("vtmsg has no ScanDate")
	}

	if st.MaxAgeHours > 0 {
		oldest := st.Now().UTC().Add(time.Hour * -time.Duration(st.MaxAgeHours))
		if vtmsg.LastScanDate.Before(oldest) {
			return nil, nil
		}
	}
	source := events.EventSource{
		Name:       "virustotal",
		References: make(map[string]string),
		Path: []events.EventSourcePathNode{
			{
				Action:           events.ActionMapped,
				Author:           *author,
				Timestamp:        vtmsg.LastScanDate,
				Sha256:           vtmsg.Sha256,
				FileFormatLegacy: vtmsg.FileFormatLegacy,
				FileFormat:       st.IdentifyMapper.FindFileType("", vtmsg.FileFormatLegacy),
				Size:             uint64(vtmsg.Size),
			},
		},
		Timestamp: vtmsg.LastScanDate,
	}

	// add filename to entity summary, if available on this submission
	filename := vtmsg.Submission.Filename
	if len(filename) > 0 {
		// summaries should just include basename
		// remember platform independent
		elem := strings.Split(filename, "/")
		filename = elem[len(elem)-1]
		elem = strings.Split(filename, `\`)
		filename = elem[len(elem)-1]
		source.Path[0].Filename = filename
	}

	ref := vtmsg.Submission.Id
	if len(ref) > 0 {
		source.References["submitter_id"] = ref
	}
	ref = vtmsg.Submission.Region
	if len(ref) > 0 && ref != "?" {
		source.References["submitter_region"] = ref
	}
	ref = vtmsg.Submission.City
	if len(ref) > 0 && ref != "?" {
		source.References["submitter_city"] = ref
	}
	ref = vtmsg.Submission.Country
	if len(ref) > 0 && ref != "XX" {
		source.References["submitter_country"] = ref
	}
	ref = vtmsg.Submission.Interface
	if len(ref) > 0 {
		source.References["interface"] = ref
	}
	return &source, nil
}
