package vtmap

import (
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v9/gosrc/events"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestHandlerStripContentV3(t *testing.T) {
	eventIn := testdata.GetFileBytes("data/load/v3_feed_example.first.json")
	parsed := gjson.ParseBytes(eventIn)
	mapped, err := MapV3(V3Handlers, parsed)
	require.Nil(t, err)
	require.Equal(t, 1, len(mapped))
	require.Equal(t, []events.BinaryEntityDatastream{}, mapped[0].Datastreams)
	require.Equal(t, "bebdfd8216bce5c81ebfdcdf496e69d00e3a922faa70110fed80d2e4287a07f8", mapped[0].Sha256)
	require.GreaterOrEqual(t, len(mapped[0].Features), 10) // 37 at time of test but as long as there are some
}

func TestTotalFeatureDescriptions(t *testing.T) {
	require.Equal(t, len(TotalFeatureDescriptions()), 191)
}
