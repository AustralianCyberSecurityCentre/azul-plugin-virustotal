package receiver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-plugin-virustotal.git/testdata"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	// channel needs to be sufficiently large to contain all published records since we read after write
	read := make(chan []byte, 20)
	plugin_header_env_key := "PLUGIN_HEADERS"
	os.Setenv(plugin_header_env_key, "{\"Content-Security-Policy\":\"upgrade-insecure-requests; base-uri 'self';\",\"X-XSS-Protection\":\"0\"}")
	defer os.Unsetenv(plugin_header_env_key)
	router := makeServer(read)
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}
	var toSend []byte
	var err error
	var req *http.Request
	var resp *http.Response
	var body []byte

	// basic endpoint
	toSend = []byte{}
	req, err = http.NewRequest("GET", server.URL+"/", bytes.NewReader(toSend))
	require.Nil(t, err)
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, string(body), "hi this is the vtload server, please leave\n")
	// Verify header is being set
	require.Equal(t, "upgrade-insecure-requests; base-uri 'self';", resp.Header.Get("Content-Security-Policy"), "Failed to find header in headers %v", resp.Header)

	// not post
	toSend = []byte{}
	req, err = http.NewRequest("GET", server.URL+"/virustotal", bytes.NewReader(toSend))
	require.Nil(t, err)
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, resp.StatusCode, 405)
	require.Equal(t, string(body), "Method Not Allowed\n")

	// bad content type
	toSend = []byte{}
	req, err = http.NewRequest("POST", server.URL+"/virustotal", bytes.NewReader(toSend))
	require.Nil(t, err)
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, resp.StatusCode, 400)
	require.Equal(t, string(body), "'Content-Type: application/jsonlines' only")

	// good data but empty
	toSend = []byte{}
	req, err = http.NewRequest("POST", server.URL+"/virustotal", bytes.NewReader(toSend))
	require.Nil(t, err)
	req.Header.Add("Content-Type", "application/jsonlines")
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, resp.StatusCode, 200)
	require.Equal(t, string(body), "read 0 records\n")
	// Verify header is being set
	require.Equal(t, "upgrade-insecure-requests; base-uri 'self';", resp.Header.Get("Content-Security-Policy"), "Failed to find header in headers %v", resp.Header)

	// good data
	toSend = testdata.GetFileBytes("data/load/v3_feed_example.json")
	req, err = http.NewRequest("POST", server.URL+"/virustotal", bytes.NewReader(toSend))
	require.Nil(t, err)
	req.Header.Add("Content-Type", "application/jsonlines")
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, resp.StatusCode, 200)
	require.Equal(t, string(body), "read 10 records\n")

	// read data from channel
	close(read)
	seenRecords := 0
	seenBytes := 0
	for s := range read {
		seenRecords++
		seenBytes += len([]byte(s))
	}
	require.Equal(t, seenRecords, 10)
	require.Equal(t, seenBytes, 217528)
}

func TestServerTooBig(t *testing.T) {
	// channel needs to be sufficiently large to contain all published records since we read after write
	read := make(chan []byte, 20)
	router := makeServer(read)
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}
	var toSend []byte
	var err error
	var req *http.Request
	var resp *http.Response
	var body []byte

	// too big data (only 1 valid record for the length)
	maxLineBytes = 10000
	toSend = testdata.GetFileBytes("data/load/v3_feed_example.long.json")
	req, err = http.NewRequest("POST", server.URL+"/virustotal", bytes.NewReader(toSend))
	require.Nil(t, err)
	req.Header.Add("Content-Type", "application/jsonlines")
	resp, err = client.Do(req)
	require.Nil(t, err)
	body, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, resp.StatusCode, 200)
	require.Equal(t, string(body), "read 1 records\n")

	// read data from channel
	close(read)
	seenRecords := 0
	seenBytes := 0
	for s := range read {
		seenRecords++
		seenBytes += len([]byte(s))
	}
	require.Equal(t, seenRecords, 1)
	require.Equal(t, seenBytes, 9489)
}
