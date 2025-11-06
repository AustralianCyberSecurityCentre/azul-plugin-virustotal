package settings

import (
	"log"
	"os"
	"strconv"
	"time"

	identify "github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/legacy_identify"
)

var DispatcherEventsUrl string = "https://dispatcher.internal"
var DispatcherDataUrl string = "https://dispatcher.internal"
var VirustotalApiKey string
var VirustotalApiServer = "https://www.virustotal.com"
var StateDir string = "/tmp/vtloadstate"
var PkgLimit int = -1 // default download all remaining
var MaxAgeHours int = 72
var SelectRulesPath string = "./select_rules"
var DownloadSizeLimit int
var LookupSources string = ""
var DeploymentKey string = "plugin-virustotal"
var IdentifyMapper *identify.VirusTotalAndLegacyMapper

// Metric related settings.
var PushGateway string = ""

// During testing we often need to make 'now' constant
var Now = time.Now

func SetNowToISO(isotime string) {
	startAt, err := time.Parse("2006-01-02T15:04:05Z", isotime)
	if err != nil {
		panic(err)
	}
	Now = func() time.Time { return startAt }
}

func ResetNow() {
	Now = time.Now
}

func Setup() {
	var tmp string
	var err error
	tmp = os.Getenv("PACKAGE_LIMIT")
	if len(tmp) > 0 {
		PkgLimit, err = strconv.Atoi(tmp)
		if err != nil {
			panic(err)
		}
	}
	tmp = os.Getenv("PLUGIN_EVENTS_URL")
	if len(tmp) > 0 {
		DispatcherEventsUrl = tmp
	}
	tmp = os.Getenv("PLUGIN_DATA_URL")
	if len(tmp) > 0 {
		DispatcherDataUrl = tmp
	}
	tmp = os.Getenv("VIRUSTOTAL_APISERVER")
	if len(tmp) > 0 {
		VirustotalApiServer = tmp
	}
	tmp = os.Getenv("VIRUSTOTAL_APIKEY")
	if len(tmp) > 0 {
		VirustotalApiKey = tmp
	}

	tmp = os.Getenv("STATEDIR")
	if len(tmp) > 0 {
		StateDir = tmp
	}
	if len(VirustotalApiKey) > 0 {
		err = os.MkdirAll(StateDir, 0755)
		if err != nil {
			panic(err)
		}
	}
	tmp = os.Getenv("DISPATCHER_MAX_AGE_HOURS")
	if len(tmp) > 0 {
		var ageErr error
		MaxAgeHours, ageErr = strconv.Atoi(tmp)
		if ageErr != nil {
			panic(ageErr)
		}
	}

	log.Printf("Running with server %s", VirustotalApiServer)

	tmp = os.Getenv("RULES_ROOT")
	if len(tmp) > 0 {
		SelectRulesPath = tmp
	}
	tmp = os.Getenv("MAX_DOWNLOAD_SIZE_MB")
	maxSize := 20 // default 20mb
	if len(tmp) > 0 {
		var err error
		maxSize, err = strconv.Atoi(tmp)
		if err != nil {
			panic(err)
		}
	}
	DownloadSizeLimit = maxSize * 1048576

	// list of sources, separated by comma
	tmp = os.Getenv("LOOKUP_SOURCES")
	if len(tmp) > 0 {
		LookupSources = tmp
	}

	tmp = os.Getenv("PLUGIN_DEPLOYMENT_KEY")
	if len(tmp) > 0 {
		DeploymentKey = tmp
	}

	// metric related settings
	tmp = os.Getenv("PLUGIN_PROMETHEUS_PUSH_GATEWAY")
	if len(tmp) > 0 {
		PushGateway = tmp
	}

	IdentifyMapper, err = identify.NewLegacyMapper()
	if err != nil {
		panic(err)
	}
}

func init() {
	Setup()
}
