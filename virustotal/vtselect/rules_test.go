package vtselect

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
)

func TestLoadRules(t *testing.T) {
	rules, err := loadRules(testdata.Dir + "/select_rules/example")
	require.Nil(t, err)
	require.Equal(t, len(rules), 3)
	require.Equal(t, rules, []Rule{
		{
			Syntax:      "gjson",
			Reference:   "",
			Rule:        "type|@eq:\"PDF\",positives|@gt:10",
			DailyQuota:  10,
			CollectPCAP: false,
			name:        "all_malicious_pdfs",
			path:        "pdf.yaml",
		},
		{
			Syntax:      "gjson",
			Reference:   "https://www.symantec.com/blogs/election-security/apt28-espionage-military-government",
			Rule:        "scans|@iany:sofacy,sednit,shunnael,apt28",
			DailyQuota:  10,
			CollectPCAP: false,
			name:        "any_av_sofacy",
			path:        "sofacy.yaml",
		},
		{
			Syntax:      "gjson",
			Reference:   "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf",
			Rule:        "scans|@iany:turla,wipbot,comrat",
			DailyQuota:  10,
			CollectPCAP: false,
			name:        "any_av_turla",
			path:        "turla.yaml",
		},
	},
	)
}
