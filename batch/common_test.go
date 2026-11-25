package batch

import (
	"errors"
	"testing"

	bedclient "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/client"
	"github.com/stretchr/testify/require"
)

func TestIsAgedOffResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{
			name:   "specific dispatcher age-off response",
			status: 425,
			body:   `{"status":"425","title":"All events to be published have been filtered out","error_enum":"ErrorStringEnumAllEventsAgedOffImmediately"}`,
			want:   true,
		},
		{
			name:   "unrelated 425 error",
			status: 425,
			body:   `{"error_enum":"SomeOtherDispatcherError"}`,
		},
		{
			name:   "missing classification",
			status: 425,
			body:   `{"title":"All events to be published have been filtered out"}`,
		},
		{
			name:   "bad JSON",
			status: 425,
			body:   `{unparseable}`,
		},
		{
			name:   "matching enum but unexpected status",
			status: 500,
			body:   `{"error_enum":"ErrorStringEnumAllEventsAgedOffImmediately"}`,
		},
		{
			name:   "temporary failure",
			status: 503,
			body:   `{"error_enum":"ServiceUnavailable"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isAgedOffResponse(tc.status, []byte(tc.body)))
		})
	}

	require.True(t, IsAgedOffRejection(&bedclient.HttpError{
		StatusCode: 425,
		Body:       `{"error_enum":"ErrorStringEnumAllEventsAgedOffImmediately"}`,
	}))
	require.False(t, IsAgedOffRejection(&bedclient.HttpError{
		StatusCode: 425,
		Body:       `{"error_enum":"OtherError"}`,
	}))
	require.False(t, IsAgedOffRejection(errors.Join(errors.New("wrapped"), &bedclient.HttpError{
		StatusCode: 503,
		Body:       `{"error_enum":"ErrorStringEnumAllEventsAgedOffImmediately"}`,
	})))
	require.False(t, IsAgedOffRejection(errors.New("network failure")))
	require.False(t, IsAgedOffRejection(nil))
}
