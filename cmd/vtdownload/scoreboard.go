package vtdownload

import (
	"time"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
)

const TotalGlobal = "Total"
const TotalQuota = "TotalQuota"
const PCAP = "PCAP"

type Scoreboard struct {
	date       time.Time
	categories map[string]int
}

func utcDate(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func NewScoreboard() *Scoreboard {
	s := Scoreboard{}
	s.reset(time.Now())
	return &s
}

func (s *Scoreboard) Feed(download *events.DownloadEntity, dt time.Time) {
	t := time.Now()
	if utcDate(t) != s.date {
		s.reset(t)
	}
	// event was for earlier period, skip
	if utcDate(dt).Before(s.date) {
		return
	}
	// not atomic / go routine safe for feeding
	categories := s.categories
	count := categories[download.Category]
	categories[download.Category] = count + 1
	total := categories[TotalGlobal]
	categories[TotalGlobal] = total + 1
	if len(download.DirectURL) == 0 {
		quota := categories[TotalQuota]
		categories[TotalQuota] = quota + 1
	}
	if download.PCAP {
		quota := categories[TotalQuota]
		categories[TotalQuota] = quota + 1
		pcap := categories[PCAP]
		categories[PCAP] = pcap + 1
	}
}

func (s *Scoreboard) Count(category string) uint32 {
	t := time.Now()
	if utcDate(t) != s.date {
		s.reset(t)
	}
	return uint32(s.categories[category])
}

func (s *Scoreboard) reset(t time.Time) {
	s.date = utcDate(t)
	categories := make(map[string]int, 0)
	categories[TotalGlobal] = 0
	categories[TotalQuota] = 0
	categories[PCAP] = 0
	s.categories = categories
}
