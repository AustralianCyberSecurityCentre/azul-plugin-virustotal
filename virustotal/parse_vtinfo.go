package virustotal

import (
	"time"

	"github.com/goccy/go-json"
)

type VTSubmissionCommon struct {
	Id        string
	Region    string
	City      string
	Country   string
	Interface string
	Filename  string
}

type VtMessageCommon struct {
	Sha256           string
	LastScanDate     time.Time
	Submission       VTSubmissionCommon
	FileFormatLegacy string
	Size             int
	DownloadUrl      string
}

func convertVTMessageV3ToCommon(msg *vtMessageV3) *VtMessageCommon {
	lastScanDate := time.Unix(msg.Attributes.LastAnalysisDate, 0)
	// Take magika file type because it's best
	fileType := msg.Attributes.Type
	if len(fileType) == 0 {
		// Fall back to the type tag.
		fileType = msg.Attributes.TypeAlternate
	}
	return &VtMessageCommon{
		Sha256:       msg.Attributes.Sha256,
		LastScanDate: lastScanDate,
		Submission: VTSubmissionCommon{
			Id:        msg.ContextAttributes.Submitter.Id,
			Region:    msg.ContextAttributes.Submitter.Region,
			City:      msg.ContextAttributes.Submitter.City,
			Country:   msg.ContextAttributes.Submitter.Country,
			Interface: msg.ContextAttributes.Submitter.Interface,
			Filename:  "", // Doesn't map filename because submissions don't include them.
		},
		FileFormatLegacy: fileType,
		Size:             msg.Attributes.Size,
		DownloadUrl:      msg.ContextAttributes.DownloadUrl,
	}
}

type vtSubmissionV3 struct {
	Id        string `json:"id"`
	Region    string `json:"region"`
	City      string `json:"city"`
	Country   string `json:"country"`
	Interface string `json:"interface"`
	// Filename  string `json:"filename"`
}

type vtContextAttributesV3 struct {
	Submitter   vtSubmissionV3 `json:"submitter"`
	DownloadUrl string         `json:"download_url"`
}

type vtMessageV3Attributes struct {
	Sha256           string `json:"sha256"`
	LastAnalysisDate int64  `json:"last_analysis_date"`
	Type             string `json:"type_tag"`
	TypeAlternate    string `json:"magika"` // Secondary type if first one isn't found
	Size             int    `json:"size"`
}

type vtMessageV3 struct {
	Attributes        vtMessageV3Attributes `json:"attributes"`
	ContextAttributes vtContextAttributesV3 `json:"context_attributes"`
}

func ParseVTInfoV3(line []byte) (*VtMessageCommon, error) {
	var vtmsg vtMessageV3
	err := json.Unmarshal([]byte(line), &vtmsg)
	if err != nil {
		return nil, err
	}
	// some virustotal records are missing sha256, which means we can't map them to azul
	if len(vtmsg.Attributes.Sha256) == 0 {
		return nil, nil
	}

	return convertVTMessageV3ToCommon(&vtmsg), nil
}
