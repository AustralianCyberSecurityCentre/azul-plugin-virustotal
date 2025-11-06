package vtselect

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"gopkg.in/yaml.v2"
)

var rules []Rule

type Rule struct {
	Syntax      string `yaml:"syntax"`
	Reference   string `yaml:"reference,omitempty"`
	Rule        string `yaml:"rule"`
	DailyQuota  uint32 `yaml:"daily_quota"`
	CollectPCAP bool   `yaml:"collect_pcap"`
	name        string
	path        string
}

func LoadRules() (int, error) {
	var err error
	rules, err = loadRules(st.SelectRulesPath)
	if err != nil {
		return 0, err
	}
	log.Printf("%d rules loaded from %s", len(rules), st.SelectRulesPath)
	if len(rules) == 0 {
		return 0, nil
	}
	for _, r := range rules {
		log.Printf("Rule Loaded with Name: '%s' Rule: '%s' Syntax: '%s'", r.name, r.Rule, r.Syntax)
	}
	log.Printf("Limiting hit downloads to %d bytes", st.DownloadSizeLimit)
	return len(rules), nil
}

func loadRules(root string) ([]Rule, error) {
	rules := make([]Rule, 0, 10)
	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if !strings.HasSuffix(info.Name(), ".yaml") {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				log.Printf("Unable to open rule file: %s\n", path)
				return nil
			}
			defer f.Close()
			content, err := io.ReadAll(f)
			if err != nil {
				log.Printf("Unable to read rule file: %s\n", path)
				return nil
			}
			var ruleFile []map[string]Rule
			err = yaml.Unmarshal(content, &ruleFile)
			if err != nil {
				log.Printf("Unable to parse rule file: %s\n", path)
			}
			for _, r := range ruleFile {
				for k, v := range r {
					v.name = k
					v.path = strings.Replace(path, root+"/", "", 1)
					rules = append(rules, v)
				}
			}
			return nil
		})
	return rules, err
}
