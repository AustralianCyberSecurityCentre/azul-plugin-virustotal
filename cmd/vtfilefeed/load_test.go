package vtfilefeed

import (
	"strings"
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	st "github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/settings"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
)

func TestAuthorGetsFeatures(t *testing.T) {
	require.Greater(t, len(author.Features), 30)
}

func TestProcess1V3(t *testing.T) {
	st.MaxAgeHours = -1
	chFromVT := make(chan []byte, 10)
	chToDP := make(chan *events.BinaryEvent, 10)
	done := make(chan *processOutput)
	go func() {
		done <- process(nil, chFromVT, chToDP)
		close(done)
		close(chToDP)
	}()
	chFromVT <- []byte("{}")
	close(chFromVT)
	res := <-done

	require.Equal(t, res, &processOutput{
		recordsIn:       1,
		recordBytesIn:   2,
		binaryEventsOut: 0,
		filtered:        1,
		failed:          0,
	})
}
func TestProcess2V3(t *testing.T) {
	st.MaxAgeHours = -1
	st.SetNowToISO("2024-01-01T01:00:00Z")
	chFromVT := make(chan []byte, 10)
	chToDP := make(chan *events.BinaryEvent, 10)

	done := make(chan *processOutput)
	go func() {
		done <- process(nil, chFromVT, chToDP)
		close(done)
		close(chToDP)
	}()
	for _, line := range strings.Split(string(testdata.GetFileBytes("data/load/v3_feed_example.json")), "\n") {
		if len(line) > 0 {
			chFromVT <- []byte(line)
		}
	}
	close(chFromVT)
	res := <-done

	require.Equal(t, &processOutput{
		recordsIn:       10,
		recordBytesIn:   217528,
		binaryEventsOut: 10,
		filtered:        0,
		failed:          0,
	}, res)
}
